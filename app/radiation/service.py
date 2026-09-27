from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import get_connection, transaction

RISK_LEVELS = ("critical", "normal", "maintenance")
RISK_LABELS = {"critical": "关键诊断", "normal": "普通批处理", "maintenance": "维护类任务"}
EVENT_STATUSES = ("active", "resolved")
QUARANTINE_STATUSES = ("frozen", "exempt", "unfrozen")
CONFIDENCE_LEVELS = ("suspect", "confirmed_clean", "recomputed_clean")
CONFIDENCE_LABELS = {
    "suspect": "可能受辐射影响",
    "confirmed_clean": "人工核验可信",
    "recomputed_clean": "辐射后重算可信",
}
FREEZABLE_TASK_STATUSES = ("queued", "running")

DEFAULT_POLICY = {
    "freeze_risk_levels": ["normal", "maintenance"],
    "keep_risk_levels": ["critical"],
    "freeze_task_statuses": ["queued"],
    "freeze_running": True,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS radiation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('advisory','watch','warning','severe')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','resolved')),
    started_at TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    ended_at TEXT,
    source TEXT NOT NULL DEFAULT 'ground-station',
    description TEXT NOT NULL DEFAULT '',
    policy_version INTEGER NOT NULL DEFAULT 1,
    payload_json TEXT NOT NULL DEFAULT '{}',
    deduplicated_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS radiation_policy_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL UNIQUE,
    rules_json TEXT NOT NULL,
    change_reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS radiation_task_risks (
    compute_task_id INTEGER PRIMARY KEY REFERENCES compute_tasks(id) ON DELETE CASCADE,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('critical','normal','maintenance')),
    declared_by TEXT NOT NULL DEFAULT '',
    declared_at TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS radiation_quarantines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES compute_tasks(id) ON DELETE CASCADE,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('critical','normal','maintenance')),
    status TEXT NOT NULL DEFAULT 'frozen' CHECK(status IN ('frozen','exempt','unfrozen')),
    frozen_from_status TEXT NOT NULL DEFAULT '',
    frozen_by TEXT NOT NULL DEFAULT '',
    frozen_reason TEXT NOT NULL DEFAULT '',
    frozen_at TEXT NOT NULL DEFAULT '',
    batch_key TEXT NOT NULL DEFAULT '',
    exempted_by TEXT,
    exempt_reason TEXT,
    exempted_at TEXT,
    unfrozen_by TEXT,
    unfrozen_reason TEXT,
    unfrozen_at TEXT,
    updated_at TEXT NOT NULL DEFAULT '',
    UNIQUE(event_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_radiation_q_task ON radiation_quarantines(task_id, status);
CREATE INDEX IF NOT EXISTS idx_radiation_q_event ON radiation_quarantines(event_id, status);
CREATE TABLE IF NOT EXISTS radiation_result_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES compute_tasks(id) ON DELETE CASCADE,
    result_version INTEGER NOT NULL,
    confidence TEXT NOT NULL CHECK(confidence IN ('suspect','confirmed_clean','recomputed_clean')),
    flagged_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    annotated_at TEXT NOT NULL,
    UNIQUE(event_id, task_id, result_version)
);
CREATE INDEX IF NOT EXISTS idx_radiation_flags_task ON radiation_result_flags(task_id, result_version);
CREATE TABLE IF NOT EXISTS radiation_policy_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    batch_key TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_radiation_audit_event ON radiation_policy_audit(event_id, id);
CREATE INDEX IF NOT EXISTS idx_radiation_audit_created ON radiation_policy_audit(created_at, id);
"""


def digest(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def ensure_schema() -> None:
    """建表并植入初始策略 v1；幂等，可在每次启动时调用。"""
    connection = get_connection()
    connection.executescript(SCHEMA)
    now = to_storage(SystemClock().now())
    with transaction(immediate=True) as connection:
        existing = connection.execute("SELECT COUNT(*) FROM radiation_policy_versions").fetchone()[0]
        if not existing:
            connection.execute(
                "INSERT INTO radiation_policy_versions(version,rules_json,change_reason,created_by,created_at) VALUES(1,?,?,?,?)",
                (json.dumps(DEFAULT_POLICY, ensure_ascii=False, sort_keys=True), "初始默认隔离策略：关键诊断保留、普通批处理与维护任务冻结", "system", now),
            )
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,reason,after_json,created_at) VALUES(NULL,'policy.bootstrap','system','policy','初始默认策略',?,?)",
                (json.dumps({"version": 1, "rules": DEFAULT_POLICY}, ensure_ascii=False), now),
            )


class RadiationIsolationService:
    """辐射事件、任务风险分级与隔离策略的事务服务（无状态，状态全部落库）。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()

    # ---------- 策略版本 ----------

    def current_policy(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM radiation_policy_versions ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if row is None:  # 未初始化时兜底
            ensure_schema()
            row = self.connection.execute(
                "SELECT * FROM radiation_policy_versions ORDER BY version DESC LIMIT 1"
            ).fetchone()
        result = dict(row)
        result["rules"] = json.loads(result.pop("rules_json"))
        return result

    def list_policy_versions(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id,version,rules_json,change_reason,created_by,created_at FROM radiation_policy_versions ORDER BY version DESC"
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["rules"] = json.loads(item.pop("rules_json"))
            items.append(item)
        return items

    def publish_policy(self, rules: dict[str, Any], change_reason: str, actor: str) -> dict[str, Any]:
        normalized = self._validate_rules(rules)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            current = connection.execute("SELECT MAX(version) FROM radiation_policy_versions").fetchone()[0] or 0
            before_row = connection.execute(
                "SELECT version,rules_json FROM radiation_policy_versions WHERE version=?", (current,)
            ).fetchone()
            before = {"version": before_row["version"], "rules": json.loads(before_row["rules_json"])} if before_row else None
            version = current + 1
            connection.execute(
                "INSERT INTO radiation_policy_versions(version,rules_json,change_reason,created_by,created_at) VALUES(?,?,?,?,?)",
                (version, json.dumps(normalized, ensure_ascii=False, sort_keys=True), change_reason, actor, now),
            )
            after = {"version": version, "rules": normalized}
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,before_json,after_json,created_at) VALUES(NULL,'policy.publish',?,'policy',?,?,?,?,?)",
                (actor, str(version), change_reason, json.dumps(before or {}, ensure_ascii=False), json.dumps(after, ensure_ascii=False), now),
            )
            return after

    @staticmethod
    def _validate_rules(rules: Any) -> dict[str, Any]:
        if not isinstance(rules, dict):
            raise ValidationError("策略规则必须是对象")
        freeze_levels = rules.get("freeze_risk_levels")
        keep_levels = rules.get("keep_risk_levels")
        if not isinstance(freeze_levels, list) or not freeze_levels:
            raise ValidationError("freeze_risk_levels 必须为非空数组")
        if not isinstance(keep_levels, list):
            raise ValidationError("keep_risk_levels 必须为数组")
        allowed = set(RISK_LEVELS)
        bad = {*freeze_levels, *keep_levels} - allowed
        if bad:
            raise ValidationError("存在未知的风险等级", context={"levels": sorted(bad)})
        overlap = set(freeze_levels) & set(keep_levels)
        if overlap:
            raise ValidationError("同一风险等级不能既冻结又保留", context={"levels": sorted(overlap)})
        if set(freeze_levels) | set(keep_levels) != allowed:
            raise ValidationError("策略必须覆盖全部风险等级 critical/normal/maintenance")
        statuses = rules.get("freeze_task_statuses", ["queued"])
        if not isinstance(statuses, list) or not set(statuses) <= {"queued", "running"} or not statuses:
            raise ValidationError("freeze_task_statuses 只能取 queued/running 且不能为空")
        if not isinstance(rules.get("freeze_running", True), bool):
            raise ValidationError("freeze_running 必须是布尔值")
        return {
            "freeze_risk_levels": sorted(freeze_levels),
            "keep_risk_levels": sorted(keep_levels),
            "freeze_task_statuses": sorted(set(statuses)),
            "freeze_running": rules.get("freeze_running", True),
        }

    # ---------- 风险分级 ----------

    def declare_task_risk(self, task_id: int, risk_level: str, actor: str, note: str = "") -> dict[str, Any]:
        if risk_level not in RISK_LEVELS:
            raise ValidationError("未知风险等级", context={"risk_level": risk_level})
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            task = connection.execute("SELECT id FROM compute_tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise NotFoundError("计算任务不存在")
            before_row = connection.execute("SELECT * FROM radiation_task_risks WHERE compute_task_id=?", (task_id,)).fetchone()
            before = dict(before_row) if before_row else None
            connection.execute(
                "INSERT INTO radiation_task_risks(compute_task_id,risk_level,declared_by,declared_at,note,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(compute_task_id) DO UPDATE SET risk_level=excluded.risk_level,declared_by=excluded.declared_by,declared_at=excluded.declared_at,note=excluded.note,updated_at=excluded.updated_at",
                (task_id, risk_level, actor, now, note, now),
            )
            after = dict(connection.execute("SELECT * FROM radiation_task_risks WHERE compute_task_id=?", (task_id,)).fetchone())
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,before_json,after_json,created_at) VALUES(NULL,'task.classify',?,'task',?,?,?,?,?)",
                (actor, str(task_id), note, json.dumps(before or {}, ensure_ascii=False), json.dumps(after, ensure_ascii=False), now),
            )
            return after

    def list_task_risks(self, risk_level: str | None = None) -> list[dict[str, Any]]:
        if risk_level:
            rows = self.connection.execute(
                "SELECT * FROM radiation_task_risks WHERE risk_level=? ORDER BY compute_task_id", (risk_level,)
            ).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM radiation_task_risks ORDER BY compute_task_id").fetchall()
        return [dict(row) for row in rows]

    # ---------- 辐射事件摄入（幂等） ----------

    def ingest_event(self, payload: dict[str, Any], actor: str = "ground-station") -> dict[str, Any]:
        now_value = self.clock.now()
        now = to_storage(now_value)
        started_at = to_storage(from_storage(payload["started_at"]) or now_value)
        detected_value = from_storage(payload["detected_at"]) if payload.get("detected_at") else now_value
        detected_at = to_storage(detected_value)
        if started_at > detected_at:
            raise ValidationError("辐射开始时间不能晚于告警接收时间")
        severity = payload.get("severity") or "warning"
        if severity not in ("advisory", "watch", "warning", "severe"):
            raise ValidationError("未知告警级别", context={"severity": severity})
        with transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM radiation_events WHERE external_id=?", (payload["external_id"],)
            ).fetchone()
            if existing is not None:
                # 重复告警：只累计次数，绝不生成重复隔离
                connection.execute(
                    "UPDATE radiation_events SET deduplicated_count=deduplicated_count+1 WHERE id=?",
                    (existing["id"],),
                )
                connection.execute(
                    "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,after_json,created_at) VALUES(?,?,'ground-station','event',?,?,'{}',?)",
                    (existing["id"], "event.duplicate_alert", str(existing["id"]), "重复告警已忽略", now),
                )
                result = dict(connection.execute("SELECT * FROM radiation_events WHERE id=?", (existing["id"],)).fetchone())
                result["deduplicated"] = True
                result["quarantine"] = self._event_quarantine_summary(connection, result["id"])
                return result

            policy = self._policy_row(connection)
            cursor = connection.execute(
                "INSERT INTO radiation_events(external_id,event_type,severity,status,started_at,detected_at,source,description,policy_version,payload_json,created_at) "
                "VALUES(?,?,?,'active',?,?,?,?,?,?,?)",
                (
                    payload["external_id"], payload.get("event_type") or "solar_particle", severity, started_at, detected_at,
                    payload.get("source") or "ground-station", payload.get("description") or "",
                    policy["version"], json.dumps(payload.get("payload") or {}, ensure_ascii=False), now,
                ),
            )
            event_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,after_json,created_at) VALUES(?,?,'ground-station','event',?,?,?)",
                (event_id, "event.ingest", str(event_id), json.dumps({"external_id": payload["external_id"], "policy_version": policy["version"]}, ensure_ascii=False), now),
            )
            summary = self._apply_isolation(connection, event_id, policy, started_at, detected_at, now)
            result = dict(connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone())
            result["deduplicated"] = False
            result["quarantine"] = self._quarantine_view(connection, event_id, summary)
            return result

    def _apply_isolation(self, connection: sqlite3.Connection, event_id: int, policy: sqlite3.Row,
                         started_at: str, detected_at: str, now: str) -> dict[str, Any]:
        rules = json.loads(policy["rules_json"])
        freeze_levels = set(rules["freeze_risk_levels"])
        freezable_statuses = set(rules["freeze_task_statuses"])
        if rules.get("freeze_running"):
            freezable_statuses.add("running")
        batch_key = digest({"event": event_id, "kind": "auto-freeze", "at": detected_at})

        rows = connection.execute(
            "SELECT t.id AS task_id, t.status AS task_status, COALESCE(r.risk_level,'normal') AS risk_level "
            "FROM compute_tasks t LEFT JOIN radiation_task_risks r ON r.compute_task_id=t.id ORDER BY t.id"
        ).fetchall()
        frozen: list[int] = []
        already_held: list[int] = []
        reason = f"辐射事件 #{event_id} 自动隔离（风险等级命中冻结策略）"
        for row in rows:
            if row["risk_level"] not in freeze_levels:
                continue
            if row["task_status"] in freezable_statuses:
                # UNIQUE(event_id,task_id) 保证同一事件不会重复隔离
                connection.execute(
                    "INSERT INTO radiation_quarantines(event_id,task_id,risk_level,status,frozen_from_status,frozen_by,frozen_reason,frozen_at,batch_key,updated_at) "
                    "VALUES(?,?,?,'frozen',?,?,?,?,?,?) "
                    "ON CONFLICT(event_id,task_id) DO NOTHING",
                    (event_id, row["task_id"], row["risk_level"],
                     row["task_status"], "system:radiation-policy", reason, now, batch_key, now),
                )
                # 运行中的任务冻结即释放租约，解冻后重新排队，避免出现无主 running
                connection.execute(
                    "UPDATE compute_tasks SET status='frozen',lease_owner='',lease_expires_at='',updated_at=?,version=version+1 WHERE id=? AND status IN ('queued','running')",
                    (now, row["task_id"]),
                )
                frozen.append(row["task_id"])
                connection.execute(
                    "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,after_json,batch_key,created_at) VALUES(?,?,'ground-station','task',?,?,?,?,?)",
                    (event_id, "quarantine.freeze", str(row["task_id"]), reason,
                     json.dumps({"task_id": row["task_id"], "from_status": row["task_status"]}, ensure_ascii=False), batch_key, now),
                )
            elif row["task_status"] == "frozen":
                # 已被其它活跃事件冻结：登记关联，但不重复改变状态
                connection.execute(
                    "INSERT INTO radiation_quarantines(event_id,task_id,risk_level,status,frozen_from_status,frozen_by,frozen_reason,frozen_at,batch_key,updated_at) "
                    "VALUES(?, ?,?,'frozen','','system:radiation-policy',?,'',?,?) "
                    "ON CONFLICT(event_id,task_id) DO NOTHING",
                    (event_id, row["task_id"], row["risk_level"], reason, batch_key, now),
                )
                already_held.append(row["task_id"])

        flagged = self._flag_results_in_window(connection, event_id, started_at, detected_at, now)
        return {"frozen_task_ids": frozen, "already_held_task_ids": already_held,
                "flagged_result_count": len(flagged), "batch_key": batch_key,
                "policy_version": policy["version"]}

    def _flag_results_in_window(self, connection: sqlite3.Connection, event_id: int,
                                window_start: str, window_end: str, now: str,
                                actor: str = "system:radiation-policy") -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT cr.task_id AS task_id, cr.version AS result_version, cr.created_at AS produced_at "
            "FROM compute_results cr WHERE cr.created_at>=? AND cr.created_at<=? "
            "AND NOT EXISTS(SELECT 1 FROM radiation_result_flags f WHERE f.event_id=? AND f.task_id=cr.task_id AND f.result_version=cr.version) "
            "ORDER BY cr.task_id, cr.version",
            (window_start, window_end, event_id),
        ).fetchall()
        reason = f"结果产生于辐射事件 #{event_id} 作用窗口内，自动标记为可疑"
        flagged: list[dict[str, Any]] = []
        for row in rows:
            connection.execute(
                "INSERT INTO radiation_result_flags(event_id,task_id,result_version,confidence,flagged_by,reason,annotated_at) VALUES(?,?,?,'suspect',?,?,?)",
                (event_id, row["task_id"], row["result_version"], actor, reason, now),
            )
            flagged.append(dict(row))
        if flagged:
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,after_json,created_at) VALUES(?,?,'system:radiation-policy','result','window',?,?,?)",
                (event_id, "result.flag", reason, json.dumps({"flags": flagged}, ensure_ascii=False), now),
            )
        return flagged

    # ---------- 事件查询与回放 ----------

    def list_events(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute("SELECT * FROM radiation_events WHERE status=? ORDER BY id DESC", (status,)).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM radiation_events ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

    def get_event(self, event_id: int) -> dict[str, Any]:
        event = self.connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone()
        if event is None:
            raise NotFoundError("辐射事件不存在")
        result = dict(event)
        result["quarantine"] = self._event_quarantine_summary(self.connection, event_id)
        return result

    def replay_event(self, event_id: int) -> dict[str, Any]:
        event = self.connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone()
        if event is None:
            raise NotFoundError("辐射事件不存在")
        quarantines = [dict(row) for row in self.connection.execute(
            "SELECT q.*, t.status AS current_task_status FROM radiation_quarantines q "
            "JOIN compute_tasks t ON t.id=q.task_id WHERE q.event_id=? ORDER BY q.id", (event_id,)
        ).fetchall()]
        flags = [dict(row) for row in self.connection.execute(
            "SELECT * FROM radiation_result_flags WHERE event_id=? ORDER BY task_id,result_version", (event_id,)
        ).fetchall()]
        timeline = [dict(row) for row in self.connection.execute(
            "SELECT id,action,actor,target_type,target_id,reason,before_json,after_json,batch_key,created_at "
            "FROM radiation_policy_audit WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall()]
        affected_task_ids = sorted({q["task_id"] for q in quarantines} | {f["task_id"] for f in flags})
        return {
            "event": dict(event),
            "affected_task_ids": affected_task_ids,
            "quarantines": quarantines,
            "result_flags": flags,
            "timeline": timeline,
        }

    @staticmethod
    def _quarantine_view(connection: sqlite3.Connection, event_id: int,
                         action: dict[str, Any] | None = None) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS amount FROM radiation_quarantines WHERE event_id=? GROUP BY status", (event_id,)
        ).fetchall()
        counts = {row["status"]: row["amount"] for row in rows}
        suspect = connection.execute(
            "SELECT COUNT(*) FROM radiation_result_flags WHERE event_id=? AND confidence='suspect'", (event_id,)
        ).fetchone()[0]
        view = {"frozen": counts.get("frozen", 0), "exempt": counts.get("exempt", 0),
                "unfrozen": counts.get("unfrozen", 0), "suspect_results": suspect}
        if action is not None:
            view["frozen_task_ids"] = action["frozen_task_ids"]
            view["already_held_task_ids"] = action["already_held_task_ids"]
            view["flagged_result_count"] = action["flagged_result_count"]
            view["batch_key"] = action["batch_key"]
            view["policy_version"] = action["policy_version"]
        return view

    @staticmethod
    def _event_quarantine_summary(connection: sqlite3.Connection, event_id: int) -> dict[str, Any]:
        return RadiationIsolationService._quarantine_view(connection, event_id)

    def resolve_event(self, event_id: int, actor: str, reason: str = "") -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            event = connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone()
            if event is None:
                raise NotFoundError("辐射事件不存在")
            if event["status"] == "resolved":
                raise ConflictError("该辐射事件已经结束")
            before = dict(event)
            connection.execute("UPDATE radiation_events SET status='resolved',ended_at=? WHERE id=?", (now, event_id))
            # 结束前再扫描一次作用窗口，把关键任务在事件末期产出的结果也补标
            flagged = self._flag_results_in_window(connection, event_id, event["started_at"], now, now)
            after = dict(connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone())
            connection.execute(
                "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,before_json,after_json,created_at) VALUES(?,?,?,'event',?,?,?,?,?)",
                (event_id, "event.resolve", actor, str(event_id), reason,
                 json.dumps({"status": before["status"]}, ensure_ascii=False),
                 json.dumps({"status": "resolved", "late_flagged": len(flagged)}, ensure_ascii=False), now),
            )
            after["quarantine"] = self._event_quarantine_summary(connection, event_id)
            return after

    # ---------- 批量冻结 / 解冻 / 豁免 ----------

    def freeze_many(self, event_id: int, task_ids: list[int], actor: str, reason: str) -> dict[str, Any]:
        return self._batch_quarantine(event_id, task_ids, actor, reason, "frozen")

    def unfreeze_many(self, event_id: int, task_ids: list[int], actor: str, reason: str) -> dict[str, Any]:
        return self._batch_quarantine(event_id, task_ids, actor, reason, "unfrozen")

    def exempt_many(self, event_id: int, task_ids: list[int], actor: str, reason: str) -> dict[str, Any]:
        return self._batch_quarantine(event_id, task_ids, actor, reason, "exempt")

    def _batch_quarantine(self, event_id: int, task_ids: list[int], actor: str, reason: str, target: str) -> dict[str, Any]:
        ordered_ids = list(dict.fromkeys(task_ids))
        batch_key = digest({"event": event_id, "target": target, "ids": ordered_ids, "actor": actor})
        now = to_storage(self.clock.now())
        succeeded: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        with transaction(immediate=True) as connection:
            event = connection.execute("SELECT * FROM radiation_events WHERE id=?", (event_id,)).fetchone()
            if event is None:
                raise NotFoundError("辐射事件不存在")
            for task_id in ordered_ids:
                try:
                    outcome = self._mutate_quarantine(connection, event, task_id, target, actor, reason, batch_key, now)
                    succeeded.append({"task_id": task_id, **outcome})
                except (NotFoundError, ConflictError) as exc:
                    failed.append({"task_id": task_id, "code": exc.code, "message": exc.message})
        return {"batch_key": batch_key, "target": target, "succeeded": succeeded, "failed": failed}

    def _mutate_quarantine(self, connection: sqlite3.Connection, event: sqlite3.Row, task_id: int,
                           target: str, actor: str, reason: str, batch_key: str, now: str) -> dict[str, Any]:
        task = connection.execute("SELECT * FROM compute_tasks WHERE id=?", (task_id,)).fetchone()
        if task is None:
            raise NotFoundError("计算任务不存在")
        q = connection.execute(
            "SELECT * FROM radiation_quarantines WHERE event_id=? AND task_id=?", (event["id"], task_id)
        ).fetchone()
        risk_level = connection.execute(
            "SELECT risk_level FROM radiation_task_risks WHERE compute_task_id=?", (task_id,)
        ).fetchone()
        risk = risk_level["risk_level"] if risk_level else "normal"

        if target == "frozen":
            if q is None and task["status"] not in FREEZABLE_TASK_STATUSES and task["status"] != "frozen":
                raise ConflictError(f"任务当前状态 {task['status']} 已终态，不能再冻结")
            if q is None:
                connection.execute(
                    "INSERT INTO radiation_quarantines(event_id,task_id,risk_level,status,frozen_from_status,frozen_by,frozen_reason,frozen_at,batch_key,updated_at) "
                    "VALUES(?,?,?,'frozen',?,?,?,?,?,?)",
                    (event["id"], task_id, risk, task["status"], actor, reason, now, batch_key, now),
                )
            else:
                connection.execute(
                    "UPDATE radiation_quarantines SET status='frozen',frozen_by=?,frozen_reason=COALESCE(NULLIF(frozen_reason,''),?),frozen_at=COALESCE(NULLIF(frozen_at,''),?),batch_key=?,updated_at=? WHERE id=?",
                    (actor, reason, now, batch_key, now, q["id"]),
                )
            froze_task = False
            if task["status"] in FREEZABLE_TASK_STATUSES:
                connection.execute(
                    "UPDATE compute_tasks SET status='frozen',lease_owner='',lease_expires_at='',updated_at=?,version=version+1 WHERE id=? AND status IN ('queued','running')",
                    (now, task_id),
                )
                froze_task = True
            self._audit(connection, event["id"], "quarantine.manual_freeze", actor, task_id, reason,
                        {"previous_status": q["status"] if q else None, "task_status": task["status"]},
                        {"status": "frozen", "froze_task": froze_task}, batch_key, now)
            return {"status": "frozen", "froze_task": froze_task}

        if q is None:
            raise ConflictError("该任务未受此事件隔离，无需解冻/豁免")
        before_status = q["status"]
        if target == "exempt":
            if before_status == "exempt":
                raise ConflictError("该任务已处于豁免状态")
            connection.execute(
                "UPDATE radiation_quarantines SET status='exempt',exempted_by=?,exempt_reason=?,exempted_at=?,updated_at=? WHERE id=?",
                (actor, reason, now, now, q["id"]),
            )
            self._audit(connection, event["id"], "quarantine.exempt", actor, task_id, reason,
                        {"status": before_status}, {"status": "exempt"}, batch_key, now)
            release = self._release_task_if_unheld(connection, task_id, now)
            return {"status": "exempt", **release}

        if target == "unfrozen":
            if before_status == "unfrozen":
                raise ConflictError("该任务已经解冻")
            connection.execute(
                "UPDATE radiation_quarantines SET status='unfrozen',unfrozen_by=?,unfrozen_reason=?,unfrozen_at=?,updated_at=? WHERE id=?",
                (actor, reason, now, now, q["id"]),
            )
            self._audit(connection, event["id"], "quarantine.unfreeze", actor, task_id, reason,
                        {"status": before_status}, {"status": "unfrozen"}, batch_key, now)
            release = self._release_task_if_unheld(connection, task_id, now)
            return {"status": "unfrozen", **release}

        raise ConflictError("未知隔离操作")  # pragma: no cover

    def _release_task_if_unheld(self, connection: sqlite3.Connection, task_id: int, now: str) -> dict[str, Any]:
        """若没有其它活跃事件仍冻结该任务，则恢复排队；否则保持冻结并回报持有事件。"""
        others = connection.execute(
            "SELECT q.event_id FROM radiation_quarantines q JOIN radiation_events e ON e.id=q.event_id "
            "WHERE q.task_id=? AND q.status='frozen' AND e.status='active' ORDER BY q.event_id",
            (task_id,),
        ).fetchall()
        holding = [row["event_id"] for row in others]
        if holding:
            return {"resumed": False, "still_held_by_event_ids": holding}
        task = connection.execute("SELECT status FROM compute_tasks WHERE id=?", (task_id,)).fetchone()
        if task["status"] == "frozen":
            # 运行中被冻结的任务租约已失效，统一回到排队重新调度
            connection.execute(
                "UPDATE compute_tasks SET status='queued',available_at=?,updated_at=?,version=version+1 WHERE id=?",
                (now, now, task_id),
            )
            return {"resumed": True, "restored_status": "queued", "still_held_by_event_ids": []}
        return {"resumed": False, "restored_status": task["status"], "still_held_by_event_ids": []}

    # ---------- 结果可信度 ----------

    def annotate_result(self, event_id: int, task_id: int, result_version: int,
                        confidence: str, actor: str, reason: str) -> dict[str, Any]:
        if confidence not in CONFIDENCE_LEVELS:
            raise ValidationError("未知可信度等级")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            event = connection.execute("SELECT id FROM radiation_events WHERE id=?", (event_id,)).fetchone()
            if event is None:
                raise NotFoundError("辐射事件不存在")
            result = connection.execute(
                "SELECT 1 FROM compute_results WHERE task_id=? AND version=?", (task_id, result_version)
            ).fetchone()
            if result is None:
                raise NotFoundError("结果版本不存在")
            before = connection.execute(
                "SELECT * FROM radiation_result_flags WHERE event_id=? AND task_id=? AND result_version=?",
                (event_id, task_id, result_version),
            ).fetchone()
            connection.execute(
                "INSERT INTO radiation_result_flags(event_id,task_id,result_version,confidence,flagged_by,reason,annotated_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(event_id,task_id,result_version) DO UPDATE SET confidence=excluded.confidence,flagged_by=excluded.flagged_by,reason=excluded.reason,annotated_at=excluded.annotated_at",
                (event_id, task_id, result_version, confidence, actor, reason, now),
            )
            after = dict(connection.execute(
                "SELECT * FROM radiation_result_flags WHERE event_id=? AND task_id=? AND result_version=?",
                (event_id, task_id, result_version),
            ).fetchone())
            self._audit(connection, event_id, "result.annotate", actor, task_id, reason,
                        dict(before) if before else {}, after, "", now)
            return after

    def list_result_flags(self, task_id: int | None = None) -> list[dict[str, Any]]:
        if task_id is not None:
            rows = self.connection.execute(
                "SELECT * FROM radiation_result_flags WHERE task_id=? ORDER BY id", (task_id,)
            ).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM radiation_result_flags ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    # ---------- 任务隔离视图 / 调度守卫 / 快照 ----------

    def isolation_state(self, task_id: int) -> dict[str, Any]:
        task = self.connection.execute(
            "SELECT t.id,t.status,t.project_code,COALESCE(r.risk_level,'normal') AS risk_level "
            "FROM compute_tasks t LEFT JOIN radiation_task_risks r ON r.compute_task_id=t.id WHERE t.id=?",
            (task_id,),
        ).fetchone()
        if task is None:
            raise NotFoundError("计算任务不存在")
        holding = [dict(row) for row in self.connection.execute(
            "SELECT q.event_id,q.status AS quarantine_status,e.external_id,e.status AS event_status,q.exempt_reason,q.unfrozen_reason "
            "FROM radiation_quarantines q JOIN radiation_events e ON e.id=q.event_id WHERE q.task_id=? ORDER BY q.event_id",
            (task_id,),
        ).fetchall()]
        active_holds = [item["event_id"] for item in holding
                        if item["quarantine_status"] == "frozen" and item["event_status"] == "active"]
        flags = [dict(row) for row in self.connection.execute(
            "SELECT event_id,result_version,confidence,flagged_by,reason,annotated_at FROM radiation_result_flags WHERE task_id=? ORDER BY id",
            (task_id,),
        ).fetchall()]
        return {
            "task_id": task_id,
            "task_status": task["status"],
            "project_code": task["project_code"],
            "risk_level": task["risk_level"],
            "risk_label": RISK_LABELS[task["risk_level"]],
            "is_frozen": bool(active_holds) or task["status"] == "frozen",
            "holding_event_ids": active_holds,
            "quarantines": holding,
            "result_flags": flags,
        }

    def is_task_blocked(self, task_id: int) -> bool:
        """供调度器使用：任务是否仍被任一活跃事件冻结（含重启后的状态还原）。"""
        row = self.connection.execute(
            "SELECT EXISTS(SELECT 1 FROM radiation_quarantines q JOIN radiation_events e ON e.id=q.event_id "
            "WHERE q.task_id=? AND q.status='frozen' AND e.status='active')",
            (task_id,),
        ).fetchone()
        task = self.connection.execute("SELECT status FROM compute_tasks WHERE id=?", (task_id,)).fetchone()
        return bool(row[0]) or (task is not None and task["status"] == "frozen")

    def snapshot(self) -> dict[str, Any]:
        def scalar(sql: str, *params: Any) -> int:
            return int(self.connection.execute(sql, params).fetchone()[0])

        policy = self.current_policy()
        return {
            "policy_version": policy["version"],
            "events": {
                "active": scalar("SELECT COUNT(*) FROM radiation_events WHERE status='active'"),
                "resolved": scalar("SELECT COUNT(*) FROM radiation_events WHERE status='resolved'"),
                "total": scalar("SELECT COUNT(*) FROM radiation_events"),
            },
            "quarantines": {
                "frozen": scalar("SELECT COUNT(*) FROM radiation_quarantines WHERE status='frozen'"),
                "exempt": scalar("SELECT COUNT(*) FROM radiation_quarantines WHERE status='exempt'"),
                "unfrozen": scalar("SELECT COUNT(*) FROM radiation_quarantines WHERE status='unfrozen'"),
            },
            "tasks": {
                "frozen": scalar("SELECT COUNT(*) FROM compute_tasks WHERE status='frozen'"),
                "critical": scalar("SELECT COUNT(*) FROM radiation_task_risks WHERE risk_level='critical'"),
                "normal_declared": scalar("SELECT COUNT(*) FROM radiation_task_risks WHERE risk_level='normal'"),
                "maintenance": scalar("SELECT COUNT(*) FROM radiation_task_risks WHERE risk_level='maintenance'"),
            },
            "results": {
                "suspect": scalar("SELECT COUNT(*) FROM radiation_result_flags WHERE confidence='suspect'"),
                "confirmed_clean": scalar("SELECT COUNT(*) FROM radiation_result_flags WHERE confidence='confirmed_clean'"),
                "recomputed_clean": scalar("SELECT COUNT(*) FROM radiation_result_flags WHERE confidence='recomputed_clean'"),
            },
        }

    # ---------- 内部工具 ----------

    def _policy_row(self, connection: sqlite3.Connection) -> sqlite3.Row:
        return connection.execute("SELECT * FROM radiation_policy_versions ORDER BY version DESC LIMIT 1").fetchone()

    @staticmethod
    def _audit(connection: sqlite3.Connection, event_id: int | None, action: str, actor: str,
               task_id: int, reason: str, before: dict[str, Any], after: dict[str, Any],
               batch_key: str, now: str) -> None:
        connection.execute(
            "INSERT INTO radiation_policy_audit(event_id,action,actor,target_type,target_id,reason,before_json,after_json,batch_key,created_at) VALUES(?,?,?,'task',?,?,?,?,?,?)",
            (event_id, action, actor, str(task_id), reason,
             json.dumps(before, ensure_ascii=False, sort_keys=True, default=str),
             json.dumps(after, ensure_ascii=False, sort_keys=True, default=str), batch_key, now),
        )
