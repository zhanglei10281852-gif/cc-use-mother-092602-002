from __future__ import annotations

import argparse
import json

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db
from app.main import app


def command_init() -> int:
    init_db()
    print(json.dumps({"database": str(database_path()), "status": "initialized"}, ensure_ascii=False))
    return 0


def command_check() -> int:
    init_db()
    connection = get_connection()
    result = {
        "database": str(database_path()),
        "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
        "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
        "tables": connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["integrity"] == "ok" and result["foreign_keys"] == 1 else 1


def command_smoke() -> int:
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
    result = {"root": root.json(), "health": health.json(), "status_codes": [root.status_code, health.status_code]}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status_codes"] == [200, 200] else 1


def command_compute_demo() -> int:
    template = {
        "code": "monte-carlo-demo",
        "name": "蒙特卡洛演示",
        "algorithm": "monte-carlo",
        "parameter_schema": {
            "samples": {"type": "integer", "required": True, "minimum": 10, "maximum": 1000000},
            "seed": {"type": "integer", "required": True},
        },
        "default_parameters": {},
        "max_runtime_seconds": 60,
        "max_attempts": 3,
    }
    with TestClient(app) as client:
        created = client.post("/api/compute/templates?actor=cli-demo", json=template)
        if created.status_code not in {201, 409}:
            print(created.text)
            return 1
        task = client.post(
            "/api/compute/tasks",
            json={
                "template_code": "monte-carlo-demo",
                "project_code": "demo",
                "requested_by": "cli-user",
                "parameters": {"samples": 1000, "seed": 42},
                "priority": 80,
                "idempotency_key": "compute-demo-000001",
            },
        )
        claimed = client.post(
            "/api/compute/tasks/claim",
            json={"worker_id": "cli-worker", "capabilities": ["monte-carlo"], "lease_seconds": 60},
        )
    result = {"task": task.status_code, "claimed": claimed.status_code, "task_id": task.json().get("id")}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if task.status_code == 202 and claimed.status_code == 200 and claimed.json().get("task") else 1


def command_radiation_demo() -> int:
    import uuid

    suffix = uuid.uuid4().hex[:8]
    template_code = f"rad-demo-{suffix}"
    event_code = f"SPE-DEMO-{suffix}"

    def check(response, *allowed: int) -> None:
        if response.status_code not in allowed:
            print(response.text)
            raise SystemExit(1)

    with TestClient(app) as client:
        check(client.post(
            f"/api/compute/templates?actor=cli-demo",
            json={
                "code": template_code, "name": "辐射演示任务", "algorithm": template_code,
                "parameter_schema": {"samples": {"type": "integer", "required": True, "minimum": 1}},
                "default_parameters": {}, "max_runtime_seconds": 60, "max_attempts": 3,
            },
        ), 201)
        batch_task = client.post("/api/compute/tasks", json={
            "template_code": template_code, "project_code": "batch", "requested_by": "cli-user",
            "parameters": {"samples": 10}, "priority": 50,
            "idempotency_key": f"rad-batch-{suffix}",
        }).json()
        critical_task = client.post("/api/compute/tasks", json={
            "template_code": template_code, "project_code": "diagnostics", "requested_by": "cli-user",
            "parameters": {"samples": 10}, "priority": 90,
            "idempotency_key": f"rad-critical-{suffix}",
        }).json()
        check(client.put("/api/radiation/profiles", json={
            "target_type": "task", "target_key": str(critical_task["id"]),
            "risk_level": "critical", "reason": "关键在轨诊断", "actor": "safety-officer",
        }), 200)
        event = client.post("/api/radiation/events", json={
            "event_code": event_code, "source": "ground-station", "severity": "alert",
            "title": "高能粒子告警演示", "description": "南大西洋异常区通量升高",
            "region": "SAA", "ingested_by": "ground-operator",
        })
        check(event, 201)
        event_id = event.json()["event"]["id"]
        duplicate = client.post("/api/radiation/events", json={
            "event_code": event_code, "source": "ground-station", "severity": "alert",
            "title": "高能粒子告警演示", "ingested_by": "ground-operator",
        })
        check(duplicate, 200)
        assert duplicate.json()["duplicate"] is True
        # 批处理冻结，关键诊断保留
        detail = client.get(f"/api/compute/task-details/{batch_task['id']}").json()
        assert detail["status"] == "frozen"
        kept = client.get(f"/api/compute/task-details/{critical_task['id']}").json()
        assert kept["status"] == "queued"
        # 带原因的人工豁免
        check(client.post(f"/api/radiation/events/{event_id}/tasks/{batch_task['id']}/exempt", json={
            "actor": "mission-commander", "reason": "过境下行校准必须执行",
        }), 201)
        assert client.get(f"/api/compute/task-details/{batch_task['id']}").json()["status"] == "queued"
        # 事件结束 -> 隔离释放
        check(client.post(f"/api/radiation/events/{event_id}/resolve", json={
            "actor": "ground-operator", "reason": "粒子通量恢复正常",
        }), 200)
        isolations = client.get(f"/api/radiation/isolations?event_id={event_id}").json()["items"]
        assert {item["state"] for item in isolations} == {"released", "kept"}
        journal = client.get(f"/api/radiation/events/{event_id}/journal").json()["items"]
    result = {
        "event_code": event_code,
        "frozen_then_exempted": batch_task["id"],
        "kept_critical": critical_task["id"],
        "duplicate_count": duplicate.json()["event"]["duplicate_count"],
        "journal_actions": [entry["action"] for entry in journal],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="compute-operations", description="科学计算任务运营服务维护入口")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化 SQLite 数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行本地 API 冒烟检查")
    subparsers.add_parser("compute-demo", help="执行计算任务提交与领取演示")
    subparsers.add_parser("radiation-demo", help="执行辐射告警隔离全链路演示")
    args = parser.parse_args()
    return {"init-db": command_init, "check-db": command_check, "smoke": command_smoke, "compute-demo": command_compute_demo, "radiation-demo": command_radiation_demo}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
