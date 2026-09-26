from __future__ import annotations

from datetime import UTC, datetime

from app.compute.service import ComputeOperationsService
from app.core.clock import FrozenClock
from app.database import close_connection, get_connection
from app.radiation.service import RadiationService

TEMPLATE = {
    "code": "diag-scan",
    "name": "星载诊断扫描",
    "algorithm": "diag-scan",
    "parameter_schema": {
        "iterations": {"type": "integer", "required": True, "minimum": 1, "maximum": 100000},
        "mode": {"type": "string", "required": True, "choices": ["fast", "accurate"]},
    },
    "default_parameters": {},
    "max_runtime_seconds": 300,
    "max_attempts": 2,
}

EVENT = {
    "event_code": "SPE-20260926-001",
    "source": "ground-station",
    "severity": "critical",
    "title": "南大西洋异常区高能粒子流",
    "description": "通量显著升高",
    "region": "SAA",
    "occurred_at": "2026-01-01T00:00:00+00:00",
    "ingested_by": "ground-operator",
}


def _task_payload(key: str, *, user: str = "sat-batch", project: str = "proj-batch",
                  priority: int = 50) -> dict:
    return {
        "template_code": "diag-scan",
        "project_code": project,
        "requested_by": user,
        "parameters": {"iterations": 100, "mode": "accurate"},
        "priority": priority,
        "idempotency_key": key,
    }


def _prepare(client) -> dict:
    created = client.post("/api/compute/templates?actor=admin", json=TEMPLATE)
    assert created.status_code == 201, created.text
    queued = client.post("/api/compute/tasks", json=_task_payload("rad-queue-0001", priority=10)).json()
    running = client.post("/api/compute/tasks",
                          json=_task_payload("rad-run-0002", priority=90)).json()
    claim = client.post("/api/compute/tasks/claim",
                        json={"worker_id": "sat-w1", "capabilities": ["diag-scan"], "lease_seconds": 120})
    assert claim.json()["task"]["id"] == running["id"]
    done = client.post("/api/compute/tasks",
                       json=_task_payload("rad-done-0003", priority=80)).json()
    claim2 = client.post("/api/compute/tasks/claim",
                         json={"worker_id": "sat-w2", "capabilities": ["diag-scan"], "lease_seconds": 120})
    assert claim2.json()["task"]["id"] == done["id"]
    complete = client.post(f"/api/compute/tasks/{done['id']}/complete",
                           json={"worker_id": "sat-w2", "result": {"scan": 0.99},
                                 "metrics": {"seconds": 3}})
    assert complete.status_code == 200
    return {"queued": queued, "running": running, "done": done}


def test_ingest_freezes_batch_keeps_critical_and_flags_results(client):
    tasks = _prepare(client)
    # 关键诊断任务（task 维度）风险等级 critical，策略默认保留
    profile = client.put("/api/radiation/profiles", json={
        "target_type": "task", "target_key": str(tasks["running"]["id"]),
        "risk_level": "critical", "reason": "在轨关键健康诊断", "actor": "safety-officer",
    })
    assert profile.status_code == 200

    event = client.post("/api/radiation/events", json=EVENT)
    assert event.status_code == 201, event.text
    body = event.json()
    assert body["isolation_counts"] == {"frozen": 1, "kept": 2}

    queued = client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()
    running = client.get(f"/api/compute/task-details/{tasks['running']['id']}").json()
    done = client.get(f"/api/compute/task-details/{tasks['done']['id']}").json()
    assert queued["status"] == "frozen"
    assert running["status"] == "running"  # 关键诊断保留
    assert done["status"] == "succeeded"  # 终态任务状态不变

    # 冻结任务不可被领取
    claim = client.post("/api/compute/tasks/claim",
                        json={"worker_id": "sat-w3", "capabilities": ["diag-scan"], "lease_seconds": 60})
    assert claim.json()["task"] is None

    # 已产生结果被标注为可疑
    annotations = client.get(f"/api/radiation/annotations?task_id={tasks['done']['id']}").json()["items"]
    assert len(annotations) == 1
    assert annotations[0]["confidence"] == "suspect"
    assert annotations[0]["state"] == "active"

    actions = [entry["action"] for entry in body["journal"]]
    assert actions == ["event_received", "freeze", "keep", "skip_terminal", "result_flagged"]


def test_duplicate_alert_does_not_create_duplicate_isolation(client):
    _prepare(client)
    first = client.post("/api/radiation/events", json=EVENT)
    assert first.status_code == 201
    duplicate = client.post("/api/radiation/events", json=EVENT)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    event_id = first.json()["event"]["id"]
    assert duplicate.json()["event"]["duplicate_count"] == 1
    isolations = client.get(f"/api/radiation/isolations?event_id={event_id}").json()["items"]
    assert len(isolations) == 3
    journal = duplicate.json()["journal"]
    assert journal[-1]["action"] == "duplicate_alert"


def test_policy_change_is_versioned_with_operator(client):
    current = client.get("/api/radiation/policies/current").json()
    assert current["version"] == 1 and current["created_by"] == "system"

    update = client.post("/api/radiation/policies", json={
        "name": "加强隔离策略",
        "rules": {
            "critical": {"action": "freeze", "annotate_results": True},
            "sensitive": {"action": "freeze", "annotate_results": True},
            "batch": {"action": "freeze", "annotate_results": True},
            "default": {"action": "freeze", "annotate_results": True},
        },
        "default_risk_level": "batch",
        "actor": "safety-officer",
        "change_reason": "汛期辐射增强，关键任务也冻结",
    })
    assert update.status_code == 201, update.text
    updated = update.json()
    assert updated["version"] == 2 and updated["created_by"] == "safety-officer"
    assert updated["change_reason"] == "汛期辐射增强，关键任务也冻结"

    old = client.get("/api/radiation/policies/versions/1").json()
    assert old["rules"]["critical"]["action"] == "keep"
    assert client.get("/api/radiation/policies").json()["items"][0]["version"] == 2

    # 与当前版本完全相同的策略不允许再生成新版本
    same = client.post("/api/radiation/policies", json={
        "name": "加强隔离策略",
        "rules": {
            "critical": {"action": "freeze", "annotate_results": True},
            "sensitive": {"action": "freeze", "annotate_results": True},
            "batch": {"action": "freeze", "annotate_results": True},
            "default": {"action": "freeze", "annotate_results": True},
        },
        "default_risk_level": "batch",
        "actor": "safety-officer",
        "change_reason": "重复提交",
    })
    assert same.status_code == 409

    bad = client.post("/api/radiation/policies", json={
        "name": "缺兜底",
        "rules": {"batch": {"action": "freeze", "annotate_results": True}},
        "default_risk_level": "batch",
        "actor": "safety-officer",
        "change_reason": "无 default",
    })
    assert bad.status_code == 422


def test_manual_batch_freeze_and_unfreeze(client):
    tasks = _prepare(client)
    freeze = client.post("/api/radiation/freeze", json={
        "actor": "flight-director",
        "reason": "临时轨道机动窗口，暂停批处理",
        "task_ids": [tasks["queued"]["id"]],
        "risk_level": "sensitive",
    })
    assert freeze.status_code == 200, freeze.text
    body = freeze.json()
    assert body["event_code"].startswith("MANUAL-")
    assert body["succeeded"][0] == {
        "task_id": tasks["queued"]["id"], "outcome": "frozen",
        "risk_level": "sensitive", "state": "frozen",
    }
    assert client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()["status"] == "frozen"

    # 重复手工冻结同一事件返回冲突，不产生重复隔离
    again = client.post("/api/radiation/freeze", json={
        "actor": "flight-director", "reason": "重复操作",
        "event_code": body["event_code"], "task_ids": [tasks["queued"]["id"]],
    })
    assert again.status_code == 200
    assert again.json()["failed"][0]["code"] == "conflict"

    unfreeze = client.post(f"/api/radiation/events/{body['event_id']}/unfreeze", json={
        "actor": "flight-director", "reason": "机动结束",
    })
    assert unfreeze.status_code == 200
    assert unfreeze.json()["released"] == [tasks["queued"]["id"]]
    assert client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()["status"] == "queued"


def test_exemption_with_reason_unfreezes_and_is_recorded(client):
    tasks = _prepare(client)
    event = client.post("/api/radiation/events", json=EVENT).json()
    event_id = event["event"]["id"]
    task_id = tasks["queued"]["id"]

    exempt = client.post(f"/api/radiation/events/{event_id}/tasks/{task_id}/exempt", json={
        "actor": "mission-commander",
        "reason": "该任务承担过境下行校准，经评估必须执行",
        "valid_until": "2026-12-31T00:00:00+00:00",
    })
    assert exempt.status_code == 201, exempt.text
    assert exempt.json()["isolation"]["state"] == "exempted"
    assert exempt.json()["exemption"]["reason"].startswith("该任务承担")
    assert client.get(f"/api/compute/task-details/{task_id}").json()["status"] == "queued"

    # 豁免后可以被领取
    claim = client.post("/api/compute/tasks/claim",
                        json={"worker_id": "sat-w4", "capabilities": ["diag-scan"], "lease_seconds": 60})
    assert claim.json()["task"]["id"] == task_id

    # 重复豁免被拒绝
    again = client.post(f"/api/radiation/events/{event_id}/tasks/{task_id}/exempt", json={
        "actor": "mission-commander", "reason": "再次豁免",
    })
    assert again.status_code == 409

    exemptions = client.get(f"/api/radiation/exemptions?event_id={event_id}").json()["items"]
    assert len(exemptions) == 1 and exemptions[0]["actor"] == "mission-commander"


def test_batch_exempt_without_task_ids_covers_all_frozen(client):
    _prepare(client)
    event = client.post("/api/radiation/events", json=EVENT).json()
    event_id = event["event"]["id"]
    result = client.post(f"/api/radiation/events/{event_id}/exemptions", json={
        "actor": "mission-commander", "reason": "整星过境校准窗口",
    })
    assert result.status_code == 201
    assert len(result.json()["succeeded"]) == 2


def test_result_annotation_clear_and_event_replay(client):
    tasks = _prepare(client)
    event1 = client.post("/api/radiation/events", json=EVENT).json()
    event1_id = event1["event"]["id"]
    annotation = client.get(f"/api/radiation/annotations?task_id={tasks['done']['id']}").json()["items"][0]
    assert annotation["event_id"] == event1_id

    cleared = client.post(f"/api/radiation/annotations/{annotation['id']}/clear", json={
        "actor": "data-steward", "reason": "复核原始遥测，结果未受影响",
    })
    assert cleared.status_code == 200
    assert cleared.json()["state"] == "cleared"
    assert cleared.json()["confidence"] == "verified"

    # 再次解除冲突
    assert client.post(f"/api/radiation/annotations/{annotation['id']}/clear", json={
        "actor": "data-steward", "reason": "重复解除",
    }).status_code == 409

    # 新事件产生新的可疑标注后回放该事件
    second_event = dict(EVENT, event_code="SPE-20260926-002")
    ingest2 = client.post("/api/radiation/events", json=second_event).json()
    event2_id = ingest2["event"]["id"]
    active = client.get(
        f"/api/radiation/annotations?task_id={tasks['done']['id']}&state=active"
    ).json()["items"]
    assert len(active) == 1 and active[0]["event_id"] == event2_id
    annotation2 = active[0]

    replay = client.post(f"/api/radiation/events/{event2_id}/replay", json={
        "actor": "data-steward", "reason": "使用加固通道重新计算",
    })
    assert replay.status_code == 200, replay.text
    replayed = replay.json()["replayed"]
    # 事件 2 下只有终态任务 done 带有可疑标注；queued 的冻结归属于仍活跃的事件 1，不能被事件 2 解冻
    assert [item["task_id"] for item in replayed] == [tasks["done"]["id"]]
    assert replayed[0]["action"] == "requeued"
    assert replayed[0]["result_versions"] == [annotation2["result_version"]]
    detail = client.get(f"/api/compute/task-details/{tasks['done']['id']}").json()
    assert detail["status"] == "queued"
    # 事件 2 的标注已回放；事件 1 解除过的标注保持 cleared
    event2_annotations = client.get(
        f"/api/radiation/annotations?event_id={event2_id}"
    ).json()["items"]
    assert event2_annotations[0]["state"] == "replayed"
    event1_annotations = client.get(
        f"/api/radiation/annotations?event_id={event1_id}"
    ).json()["items"]
    assert event1_annotations[0]["state"] == "cleared"
    # 事件 1 仍活跃，queued 任务保持冻结
    assert client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()["status"] == "frozen"


def test_resolve_event_releases_frozen_tasks(client):
    tasks = _prepare(client)
    event_id = client.post("/api/radiation/events", json=EVENT).json()["event"]["id"]
    assert client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()["status"] == "frozen"

    resolved = client.post(f"/api/radiation/events/{event_id}/resolve", json={
        "actor": "ground-operator", "reason": "粒子通量恢复正常",
    })
    assert resolved.status_code == 200
    assert resolved.json()["event"]["status"] == "resolved"
    assert client.get(f"/api/compute/task-details/{tasks['queued']['id']}").json()["status"] == "queued"

    assert client.post(f"/api/radiation/events/{event_id}/resolve", json={
        "actor": "ground-operator", "reason": "重复结束",
    }).status_code == 409


def test_state_survives_restart_and_reconcile_repairs_drift(client):
    tasks = _prepare(client)
    event_id = client.post("/api/radiation/events", json=EVENT).json()["event"]["id"]
    task_id = tasks["queued"]["id"]

    # 模拟服务重启：关闭线程连接后用全新服务实例读取，隔离与冻结状态仍准确还原
    close_connection()
    service = RadiationService(get_connection())
    assert service.reconcile() == {"refrozen": [], "restored": []}
    isolations = service.list_isolations(event_id=event_id, state="frozen")
    assert {item["task_id"] for item in isolations} == {task_id, tasks["running"]["id"]}
    assert service.get_event(event_id)["event"]["status"] == "active"

    # 模拟状态漂移：冻结记录仍在但任务被错误改回排队 -> 重新冻结
    connection = get_connection()
    connection.execute("UPDATE compute_tasks SET status='queued' WHERE id=?", (task_id,))
    result = RadiationService(connection).reconcile()
    assert result["refrozen"] == [task_id]

    # 事件解除后若任务卡在 frozen -> 还原为排队
    RadiationService(connection).resolve_event(event_id, {
        "actor": "ground-operator", "reason": "事件结束", "release_isolations": True,
    })
    connection.execute("UPDATE compute_tasks SET status='frozen' WHERE id=?", (task_id,))
    repaired = RadiationService(connection).reconcile()
    assert repaired["restored"] == [task_id]


def test_new_submission_during_active_event_is_screened(client):
    _prepare(client)
    client.post("/api/radiation/events", json=EVENT)
    new_task = client.post("/api/compute/tasks", json=_task_payload("rad-after-event-01"))
    assert new_task.status_code == 202
    assert new_task.json()["status"] == "frozen"

    # 豁免后人工重试不会被同事件再次冻结
    event_id = client.get("/api/radiation/events").json()["items"][0]["id"]
    task_id = new_task.json()["id"]
    client.post(f"/api/radiation/events/{event_id}/tasks/{task_id}/exempt", json={
        "actor": "mission-commander", "reason": "需要立即执行",
    })
    # 模拟失败后人工重试
    connection = get_connection()
    connection.execute("UPDATE compute_tasks SET status='failed' WHERE id=?", (task_id,))
    retried = client.post(f"/api/compute/tasks/{task_id}/retry", json={
        "actor": "ops", "reason": "豁免后重试",
    })
    assert retried.status_code == 200
    assert retried.json()["status"] == "queued"


def test_results_before_event_occurrence_are_not_flagged(client):
    tasks = _prepare(client)
    # 事件发生时间晚于结果产生时间 -> 不标注
    clock = FrozenClock(datetime(2026, 9, 26, 12, 0, tzinfo=UTC))
    service = RadiationService(get_connection(), clock)
    service.ingest_event({
        "event_code": "SPE-LATE-001", "source": "ground-station", "severity": "alert",
        "title": "迟到的告警", "description": "", "region": "",
        "occurred_at": "2026-09-27T00:00:00+00:00", "ingested_by": "ground-operator",
    })
    items = service.list_annotations(task_id=tasks["done"]["id"])
    assert items == []
