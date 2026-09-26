from __future__ import annotations

import json
import sqlite3
from typing import Any


class RadiationRepository:
    """封装辐射事件、策略、隔离与结果标注的 SQLite 读写。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    # ---------- 事件 ----------

    def event_by_code(self, event_code: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_events WHERE event_code=?", (event_code,)
        ).fetchone()

    def event_by_id(self, event_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_events WHERE id=?", (event_id,)
        ).fetchone()

    def create_event(self, *, event_code: str, source: str, severity: str, title: str,
                     description: str, region: str, occurred_at: str, ingested_by: str,
                     now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO radiation_events(event_code,source,severity,title,description,region,"
            "occurred_at,status,duplicate_count,ingested_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,'active',0,?,?,?)",
            (event_code, source, severity, title, description, region, occurred_at,
             ingested_by, now, now),
        )
        return dict(self.event_by_id(cursor.lastrowid))

    def mark_duplicate(self, event_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE radiation_events SET duplicate_count=duplicate_count+1,updated_at=? WHERE id=?",
            (now, event_id),
        )

    def resolve_event(self, event_id: int, actor: str, reason: str, now: str) -> None:
        self.connection.execute(
            "UPDATE radiation_events SET status='resolved',resolved_at=?,resolved_by=?,"
            "resolve_reason=?,updated_at=? WHERE id=?",
            (now, actor, reason, now, event_id),
        )

    def list_events(self, *, status: str | None, limit: int) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute(
                "SELECT * FROM radiation_events WHERE status=? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM radiation_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def active_events(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM radiation_events WHERE status='active' ORDER BY id"
        ).fetchall()

    # ---------- 策略 ----------

    def current_policy(self, code: str = "default") -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_policies WHERE code=? AND is_current=1", (code,)
        ).fetchone()

    def policy_by_version(self, code: str, version: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_policies WHERE code=? AND version=?", (code, version)
        ).fetchone()

    def list_policies(self, code: str = "default") -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM radiation_policies WHERE code=? ORDER BY version DESC", (code,)
        ).fetchall()
        return [dict(row) for row in rows]

    def create_policy_version(self, *, code: str, version: int, name: str,
                              rules: dict[str, Any], default_risk_level: str,
                              change_reason: str, actor: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE radiation_policies SET is_current=0 WHERE code=?", (code,)
        )
        cursor = self.connection.execute(
            "INSERT INTO radiation_policies(code,version,name,rules_json,default_risk_level,"
            "change_reason,created_by,created_at,is_current) VALUES(?,?,?,?,?,?,?,?,1)",
            (code, version, name, json.dumps(rules, ensure_ascii=False, sort_keys=True),
             default_risk_level, change_reason, actor, now),
        )
        return dict(self.connection.execute(
            "SELECT * FROM radiation_policies WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    # ---------- 任务风险档案 ----------

    def upsert_profile(self, *, target_type: str, target_key: str, risk_level: str,
                       reason: str, actor: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "INSERT INTO radiation_task_profiles(target_type,target_key,risk_level,reason,"
            "updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(target_type,target_key) DO UPDATE SET risk_level=excluded.risk_level,"
            "reason=excluded.reason,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
            (target_type, target_key, risk_level, reason, actor, now, now),
        )
        return dict(self.connection.execute(
            "SELECT * FROM radiation_task_profiles WHERE target_type=? AND target_key=?",
            (target_type, target_key),
        ).fetchone())

    def profile(self, target_type: str, target_key: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_task_profiles WHERE target_type=? AND target_key=?",
            (target_type, target_key),
        ).fetchone()

    def list_profiles(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM radiation_task_profiles ORDER BY target_type,target_key"
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 隔离 ----------

    def isolation(self, event_id: int, task_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_isolations WHERE event_id=? AND task_id=?",
            (event_id, task_id),
        ).fetchone()

    def isolation_by_id(self, isolation_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_isolations WHERE id=?", (isolation_id,)
        ).fetchone()

    def create_isolation(self, *, event_id: int, task_id: int, risk_level: str, action: str,
                         state: str, reason: str, previous_status: str,
                         previous: dict[str, Any], frozen_by: str, frozen_at: str | None,
                         now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO radiation_isolations(event_id,task_id,risk_level,action,state,reason,"
            "previous_status,previous_json,frozen_by,frozen_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, task_id, risk_level, action, state, reason, previous_status,
             json.dumps(previous, ensure_ascii=False, sort_keys=True), frozen_by,
             frozen_at, now, now),
        )
        return dict(self.isolation_by_id(cursor.lastrowid))

    def update_isolation_state(self, isolation_id: int, state: str, now: str, *,
                               actor_field: str | None = None, actor: str | None = None,
                               at_field: str | None = None) -> None:
        assignments = "state=?,updated_at=?"
        params: list[Any] = [state, now]
        if actor_field and at_field:
            assignments += f",{actor_field}=?,{at_field}=?"
            params.extend([actor, now])
        params.append(isolation_id)
        self.connection.execute(
            f"UPDATE radiation_isolations SET {assignments} WHERE id=?", params
        )

    def list_isolations(self, *, event_id: int | None = None, state: str | None = None,
                        task_id: int | None = None, limit: int = 500) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if event_id is not None:
            clauses.append("event_id=?")
            values.append(event_id)
        if state is not None:
            clauses.append("state=?")
            values.append(state)
        if task_id is not None:
            clauses.append("task_id=?")
            values.append(task_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        values.append(limit)
        rows = self.connection.execute(
            "SELECT * FROM radiation_isolations" + where + " ORDER BY id LIMIT ?", values
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 豁免 ----------

    def add_exemption(self, *, isolation_id: int, event_id: int, task_id: int,
                      actor: str, reason: str, valid_until: str | None, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO radiation_exemptions(isolation_id,event_id,task_id,actor,reason,"
            "valid_until,created_at) VALUES(?,?,?,?,?,?,?)",
            (isolation_id, event_id, task_id, actor, reason, valid_until, now),
        )
        return dict(self.connection.execute(
            "SELECT * FROM radiation_exemptions WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    def list_exemptions(self, *, isolation_id: int | None = None,
                        event_id: int | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if isolation_id is not None:
            clauses.append("isolation_id=?")
            values.append(isolation_id)
        if event_id is not None:
            clauses.append("event_id=?")
            values.append(event_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            "SELECT * FROM radiation_exemptions" + where + " ORDER BY id", values
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 结果标注 ----------

    def annotation(self, event_id: int, task_id: int, result_version: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_result_annotations WHERE event_id=? AND task_id=? "
            "AND result_version=?",
            (event_id, task_id, result_version),
        ).fetchone()

    def annotation_by_id(self, annotation_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM radiation_result_annotations WHERE id=?", (annotation_id,)
        ).fetchone()

    def create_annotation(self, *, event_id: int, task_id: int, result_version: int,
                          confidence: str, reason: str, flagged_by: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO radiation_result_annotations(event_id,task_id,result_version,confidence,"
            "state,reason,flagged_by,flagged_at,created_at) VALUES(?,?,?,?,'active',?,?,?,?)",
            (event_id, task_id, result_version, confidence, reason, flagged_by, now, now),
        )
        return dict(self.annotation_by_id(cursor.lastrowid))

    def update_annotation(self, annotation_id: int, **fields: Any) -> None:
        assignments = ",".join(f"{key}=?" for key in fields)
        self.connection.execute(
            f"UPDATE radiation_result_annotations SET {assignments} WHERE id=?",
            (*fields.values(), annotation_id),
        )

    def list_annotations(self, *, event_id: int | None = None, task_id: int | None = None,
                         state: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if event_id is not None:
            clauses.append("event_id=?")
            values.append(event_id)
        if task_id is not None:
            clauses.append("task_id=?")
            values.append(task_id)
        if state is not None:
            clauses.append("state=?")
            values.append(state)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        values.append(limit)
        rows = self.connection.execute(
            "SELECT * FROM radiation_result_annotations" + where + " ORDER BY id LIMIT ?", values
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 时间线 ----------

    def next_journal_seq(self, event_id: int) -> int:
        value = self.connection.execute(
            "SELECT COALESCE(MAX(seq),0)+1 FROM radiation_journal WHERE event_id=?", (event_id,)
        ).fetchone()[0]
        return int(value)

    def add_journal(self, *, event_id: int, seq: int, occurred_at: str, actor: str,
                    action: str, task_id: int | None, detail: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO radiation_journal(event_id,seq,occurred_at,actor,action,task_id,"
            "detail_json) VALUES(?,?,?,?,?,?,?)",
            (event_id, seq, occurred_at, actor, action, task_id,
             json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )

    def journal(self, event_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM radiation_journal WHERE event_id=? ORDER BY seq", (event_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 计算任务（只读/状态更新） ----------

    def task_by_id(self, task_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT t.*,tpl.code AS template_code,tpl.algorithm AS template_algorithm "
            "FROM compute_tasks t JOIN compute_templates tpl ON tpl.id=t.template_id WHERE t.id=?",
            (task_id,),
        ).fetchone()

    def list_all_tasks(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT t.*,tpl.code AS template_code,tpl.algorithm AS template_algorithm "
            "FROM compute_tasks t JOIN compute_templates tpl ON tpl.id=t.template_id ORDER BY t.id"
        ).fetchall()

    def freeze_task(self, task_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE compute_tasks SET status='frozen',lease_owner='',lease_expires_at='',"
            "updated_at=?,version=version+1 WHERE id=?",
            (now, task_id),
        )

    def unfreeze_task(self, task_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE compute_tasks SET status='queued',available_at=?,lease_owner='',"
            "lease_expires_at='',updated_at=?,version=version+1 WHERE id=? AND status='frozen'",
            (now, now, task_id),
        )

    def requeue_task(self, task_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE compute_tasks SET status='queued',available_at=?,lease_owner='',"
            "lease_expires_at='',finished_at=NULL,updated_at=?,version=version+1 WHERE id=?",
            (now, now, task_id),
        )

    def task_results(self, task_id: int) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM compute_results WHERE task_id=? ORDER BY version", (task_id,)
        ).fetchall()

    def results_in_window(self, task_id: int, start: str, end: str | None) -> list[sqlite3.Row]:
        if end:
            return self.connection.execute(
                "SELECT * FROM compute_results WHERE task_id=? AND created_at>=? AND created_at<=? "
                "ORDER BY version",
                (task_id, start, end),
            ).fetchall()
        return self.connection.execute(
            "SELECT * FROM compute_results WHERE task_id=? AND created_at>=? ORDER BY version",
            (task_id, start),
        ).fetchall()
