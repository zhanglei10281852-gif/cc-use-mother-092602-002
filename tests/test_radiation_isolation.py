from __future__ import annotations

from app.database import close_connection
from app.radiation.service import RadiationIsolationService

TEMPLATE = {
    "code": "solver-rad",
    "name": "辐射隔离用求解模板",
    "algorithm": "solver-rad",
    "parameter_schema": {"iterations": {"type": "integer", "required": True, "minimum": 1, "maximum": 10000}},
    "default_parameters": {},
    "max_runtime_seconds": 300,
    "max_attempts": 2,
}


def submit(client, key, *, priority: int = 50) -> int:
    response = client.post(
        "/api/compute/tasks",
        json={
            "template_code": "solver-rad",
            "project_code": "sat-orbit",
            "requested_by": "ground-ops",
            "parameters": {"iterations": 10},
            "priority": priority,
            "idempotency_key": key,
        },
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def setup_template(client) -> None:
    response = client.post("/api/compute/templates?actor=administrator", json=TEMPLATE)
    assert response.status_code == 201, response.text


def alert(external_id: str = "SPE-2026-0001", **overrides) -> dict:
    payload = {
        "external_id": external_id,
        "event_type": "solar_particle",
        "severity": "severe",
        "started_at": "2000-01-01T00:00:00+00:00",
        "source": "ground-station",
        "description": "地面站高能粒子告警",
    }
    payload.update(overrides)
    return payload


def complete_one_task(client, key: str) -> int:
    task_id = submit(client, key)
    claimed = client.post("/api/compute/tasks/claim", json={"worker_id": "w1", "capabilities": ["solver-rad"], "lease_seconds": 60})
    assert claimed.status_code == 200
    assert claimed.json()["task"]["id"] == task_id
    done = client.post(f"/api/compute/tasks/{task_id}/complete", json={"worker_id": "w1", "result": {"answer": 42}, "metrics": {"ms": 12}})
    assert done.status_code == 200, done.text
    return task_id


def test_alert_freezes_batch_tasks_keeps_critical_and_flags_results(client):
    setup_template(client)
    # 已完成任务：其结果落在辐射作用窗口内
    finished = complete_one_task(client, "rad-key-0001")
    # 一个运行中、一个排队的普通批处理
    running = submit(client, "rad-key-0002")
    claim = client.post("/api/compute/tasks/claim", json={"worker_id": "w2", "capabilities": ["solver-rad"], "lease_seconds": 60})
    assert claim.json()["task"]["id"] == running
    queued = submit(client, "rad-key-0003")
    # 关键诊断任务
    critical = submit(client, "rad-key-0004")
    classified = client.put(f"/api/radiation/tasks/{critical}/risk?actor=ops-lead", json={"risk_level": "critical", "note": "星上健康诊断"})
    assert classified.status_code == 200, classified.text

    event = client.post("/api/radiation/events", json=alert())
    assert event.status_code == 201, event.text
    body = event.json()
    event_id = body["id"]
    assert body["deduplicated"] is False
    assert body["quarantine"]["frozen"] == 2
    assert body["quarantine"]["suspect_results"] == 1

    # 普通批处理被冻结，运行中任务租约被释放
    for task_id in (running, queued):
        state = client.get(f"/api/radiation/tasks/{task_id}/isolation").json()
        assert state["is_frozen"] is True
        assert state["task_status"] == "frozen"
    # 关键诊断保留运行
    diag_state = client.get(f"/api/radiation/tasks/{critical}/isolation").json()
    assert diag_state["is_frozen"] is False
    assert diag_state["risk_level"] == "critical"

    # 调度器只能领到关键诊断任务，冻结任务不可被领取
    next_claim = client.post("/api/compute/tasks/claim", json={"worker_id": "w3", "capabilities": ["solver-rad"], "lease_seconds": 60}).json()
    assert next_claim["task"]["id"] == critical
    empty = client.post("/api/compute/tasks/claim", json={"worker_id": "w3", "capabilities": ["solver-rad"], "lease_seconds": 60}).json()
    assert empty["task"] is None

    # 已完成结果被标记为可疑
    flags = client.get(f"/api/radiation/result-flags?task_id={finished}").json()["items"]
    assert len(flags) == 1
    assert flags[0]["confidence"] == "suspect"
    assert flags[0]["event_id"] == event_id


def test_duplicate_alert_does_not_create_duplicate_quarantine(client):
    setup_template(client)
    first_task = submit(client, "dup-key-0001")
    second_task = submit(client, "dup-key-0002")

    first = client.post("/api/radiation/events", json=alert("DUP-1"))
    assert first.status_code == 201
    event_id = first.json()["id"]
    assert first.json()["quarantine"]["frozen"] == 2

    repeat = client.post("/api/radiation/events", json=alert("DUP-1", description="重复告警"))
    assert repeat.status_code == 201
    assert repeat.json()["id"] == event_id
    assert repeat.json()["deduplicated"] is True
    assert repeat.json()["deduplicated_count"] == 1
    assert repeat.json()["quarantine"]["frozen"] == 2

    # 底层隔离记录每个事件-任务对只有一条
    from app.database import get_connection

    rows = get_connection().execute(
        "SELECT task_id FROM radiation_quarantines WHERE event_id=? ORDER BY task_id", (event_id,)
    ).fetchall()
    assert [row["task_id"] for row in rows] == [first_task, second_task]

    third = client.post("/api/radiation/events", json=alert("DUP-1"))
    assert third.json()["deduplicated_count"] == 2


def test_restart_restores_isolation_state(client):
    setup_template(client)
    frozen_task = submit(client, "restart-key-001")
    event = client.post("/api/radiation/events", json=alert("RESTART-1")).json()

    # 模拟进程重启：关闭线程连接后用全新服务实例读取同一数据库
    close_connection()
    service = RadiationIsolationService()
    assert service.is_task_blocked(frozen_task) is True
    state = service.isolation_state(frozen_task)
    assert state["holding_event_ids"] == [event["id"]]
    assert state["task_status"] == "frozen"
    snapshot = service.snapshot()
    assert snapshot["events"]["active"] == 1
    assert snapshot["tasks"]["frozen"] == 1
    assert snapshot["quarantines"]["frozen"] == 1

    # 重启后调度守卫依然生效
    from app.compute.repository import ComputeRepository
    from app.database import get_connection

    candidate = ComputeRepository(get_connection()).queued_candidate(["solver-rad"], "2999-01-01T00:00:00+00:00")
    assert candidate is None


def test_manual_exemption_with_reason_resumes_task(client):
    setup_template(client)
    task_id = submit(client, "exempt-key-001")
    event = client.post("/api/radiation/events", json=alert("EXEMPT-1")).json()

    exempt = client.post(
        f"/api/radiation/events/{event['id']}/exempt?actor=duty-captain",
        json={"task_ids": [task_id], "reason": "地面光纤链路复核，星上计算未受影响"},
    )
    assert exempt.status_code == 200, exempt.text
    result = exempt.json()
    assert result["succeeded"][0]["status"] == "exempt"
    assert result["succeeded"][0]["resumed"] is True

    state = client.get(f"/api/radiation/tasks/{task_id}/isolation").json()
    assert state["is_frozen"] is False
    assert state["task_status"] == "queued"
    assert state["quarantines"][0]["exempt_reason"]

    # 豁免任务可以被调度
    claimed = client.post("/api/compute/tasks/claim", json={"worker_id": "w", "capabilities": ["solver-rad"], "lease_seconds": 60}).json()
    assert claimed["task"]["id"] == task_id


def test_overlapping_events_keep_task_frozen_until_all_holds_released(client):
    setup_template(client)
    task_id = submit(client, "overlap-key-001")
    event_one = client.post("/api/radiation/events", json=alert("OVERLAP-1")).json()
    # 第二起事件到来时任务已冻结：登记关联但不重复改状态
    event_two = client.post("/api/radiation/events", json=alert("OVERLAP-2"))
    assert event_two.json()["quarantine"]["frozen_task_ids"] == []
    assert event_two.json()["quarantine"]["already_held_task_ids"] == [task_id]
    # 两个事件各持有一条隔离记录，没有重复
    from app.database import get_connection

    holds = get_connection().execute(
        "SELECT event_id,status FROM radiation_quarantines WHERE task_id=? ORDER BY event_id", (task_id,)
    ).fetchall()
    assert [(row["event_id"], row["status"]) for row in holds] == [
        (event_one["id"], "frozen"),
        (event_two.json()["id"], "frozen"),
    ]

    # 在事件二下豁免/解冻都不能让任务恢复，因为事件一仍在冻结
    exempt_two = client.post(
        f"/api/radiation/events/{event_two.json()['id']}/exempt?actor=captain",
        json={"task_ids": [task_id], "reason": "事件二豁免"},
    ).json()
    assert exempt_two["succeeded"][0]["resumed"] is False
    assert exempt_two["succeeded"][0]["still_held_by_event_ids"] == [event_one["id"]]
    assert client.get(f"/api/radiation/tasks/{task_id}/isolation").json()["task_status"] == "frozen"

    # 事件一解冻后才真正恢复排队
    unfreeze = client.post(
        f"/api/radiation/events/{event_one['id']}/unfreeze?actor=captain",
        json={"task_ids": [task_id], "reason": "辐射云已通过"},
    ).json()
    assert unfreeze["succeeded"][0]["resumed"] is True
    assert client.get(f"/api/radiation/tasks/{task_id}/isolation").json()["task_status"] == "queued"


def test_batch_freeze_unfreeze_and_partial_failure(client):
    setup_template(client)
    task_id = submit(client, "manual-key-001")
    event = client.post("/api/radiation/events", json=alert("MANUAL-1")).json()
    # 事件未隔离过的任务不能直接解冻
    invalid = client.post(
        f"/api/radiation/events/{event['id']}/unfreeze?actor=captain",
        json={"task_ids": [999999], "reason": "不存在的任务"},
    )
    assert invalid.status_code == 200
    assert invalid.json()["failed"][0]["code"] == "not_found"

    # 先解冻再手工批量冻结
    unfreeze = client.post(
        f"/api/radiation/events/{event['id']}/unfreeze?actor=captain",
        json={"task_ids": [task_id], "reason": "先恢复"},
    ).json()
    assert unfreeze["succeeded"][0]["status"] == "unfrozen"
    refreeze = client.post(
        f"/api/radiation/events/{event['id']}/freeze?actor=captain",
        json={"task_ids": [task_id], "reason": "二次确认仍需冻结"},
    ).json()
    assert refreeze["succeeded"][0]["status"] == "frozen"
    assert refreeze["succeeded"][0]["froze_task"] is True
    # 重复冻结返回冲突而不是再造一条记录
    again = client.post(
        f"/api/radiation/events/{event['id']}/freeze?actor=captain",
        json={"task_ids": [task_id], "reason": "再冻一次"},
    ).json()
    assert again["succeeded"][0]["status"] == "frozen"


def test_result_annotation_and_event_replay(client):
    setup_template(client)
    task_id = complete_one_task(client, "replay-key-001")
    event = client.post("/api/radiation/events", json=alert("REPLAY-1")).json()

    annotation = client.post(
        f"/api/radiation/events/{event['id']}/tasks/{task_id}/results/1/annotation?actor=scientist",
        json={"confidence": "confirmed_clean", "reason": "与地面基准结果比对一致"},
    )
    assert annotation.status_code == 200, annotation.text
    assert annotation.json()["confidence"] == "confirmed_clean"

    replay = client.get(f"/api/radiation/events/{event['id']}/replay")
    assert replay.status_code == 200
    body = replay.json()
    assert task_id in body["affected_task_ids"]
    assert body["result_flags"][0]["confidence"] == "confirmed_clean"
    actions = {item["action"] for item in body["timeline"]}
    assert "event.ingest" in actions
    assert "result.flag" in actions
    assert "result.annotate" in actions


def test_policy_versions_record_operator_and_history(client):
    setup_template(client)
    policy = client.get("/api/radiation/policy")
    assert policy.status_code == 200
    assert policy.json()["version"] == 1
    assert policy.json()["created_by"] == "system"

    bad = client.post(
        "/api/radiation/policy?actor=ops-lead",
        json={"rules": {"freeze_risk_levels": ["normal"], "keep_risk_levels": ["normal"]}, "change_reason": "冲突策略"},
    )
    assert bad.status_code == 422

    new_policy = client.post(
        "/api/radiation/policy?actor=ops-lead",
        json={
            "rules": {"freeze_risk_levels": ["normal", "maintenance"], "keep_risk_levels": ["critical"], "freeze_task_statuses": ["queued"], "freeze_running": False},
            "change_reason": "运行中任务改为星上自主收尾，不再强冻",
        },
    )
    assert new_policy.status_code == 201, new_policy.text
    assert new_policy.json()["version"] == 2

    versions = client.get("/api/radiation/policy/versions").json()["items"]
    assert [item["version"] for item in versions] == [2, 1]
    assert versions[0]["created_by"] == "ops-lead"
    assert versions[0]["change_reason"]

    # 新策略只冻结排队任务，运行中任务保留
    running = submit(client, "policy-key-001")
    client.post("/api/compute/tasks/claim", json={"worker_id": "w", "capabilities": ["solver-rad"], "lease_seconds": 60})
    event = client.post("/api/radiation/events", json=alert("POLICY-1")).json()
    assert event["policy_version"] == 2
    state = client.get(f"/api/radiation/tasks/{running}/isolation").json()
    assert state["task_status"] == "running"
    assert state["is_frozen"] is False


def test_resolve_event_and_late_result_flagging(client):
    setup_template(client)
    critical = submit(client, "resolve-key-001")
    client.put(f"/api/radiation/tasks/{critical}/risk?actor=lead", json={"risk_level": "critical"})
    event = client.post("/api/radiation/events", json=alert("RESOLVE-1")).json()

    # 关键诊断在事件期间产出结果
    claimed = client.post("/api/compute/tasks/claim", json={"worker_id": "w", "capabilities": ["solver-rad"], "lease_seconds": 60}).json()
    assert claimed["task"]["id"] == critical
    client.post(f"/api/compute/tasks/{critical}/complete", json={"worker_id": "w", "result": {"ok": 1}, "metrics": {}})

    resolved = client.post(
        f"/api/radiation/events/{event['id']}/resolve?actor=ops-lead",
        json={"reason": "辐射事件结束"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "resolved"
    # 事件末期关键任务产出的结果在结束时补标
    flags = client.get(f"/api/radiation/result-flags?task_id={critical}").json()["items"]
    assert any(flag["confidence"] == "suspect" for flag in flags)

    repeat = client.post(
        f"/api/radiation/events/{event['id']}/resolve?actor=ops-lead",
        json={"reason": "再次结束"},
    )
    assert repeat.status_code == 409
