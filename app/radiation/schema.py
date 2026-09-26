"""辐射事件与任务隔离领域的 SQLite 表结构。"""

from __future__ import annotations

import sqlite3

from app.database import get_connection

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS radiation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_code TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('advisory','warning','alert','critical')),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','resolved')),
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    ingested_by TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    resolve_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_radiation_events_status ON radiation_events(status, occurred_at);

CREATE TABLE IF NOT EXISTS radiation_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    default_risk_level TEXT NOT NULL DEFAULT 'batch',
    change_reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 0 CHECK(is_current IN (0,1)),
    UNIQUE(code, version)
);
CREATE INDEX IF NOT EXISTS idx_radiation_policies_current ON radiation_policies(code, is_current);

CREATE TABLE IF NOT EXISTS radiation_task_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL CHECK(target_type IN ('task','template','project')),
    target_key TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('critical','sensitive','batch')),
    reason TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_type, target_key)
);

CREATE TABLE IF NOT EXISTS radiation_isolations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES compute_tasks(id) ON DELETE CASCADE,
    risk_level TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('freeze','keep')),
    state TEXT NOT NULL CHECK(state IN ('frozen','exempted','released','kept')),
    reason TEXT NOT NULL DEFAULT '',
    previous_status TEXT NOT NULL DEFAULT '',
    previous_json TEXT NOT NULL DEFAULT '{}',
    frozen_by TEXT NOT NULL DEFAULT '',
    frozen_at TEXT,
    exempted_by TEXT NOT NULL DEFAULT '',
    exempted_at TEXT,
    released_by TEXT NOT NULL DEFAULT '',
    released_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(event_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_radiation_isolations_state ON radiation_isolations(state, event_id);
CREATE INDEX IF NOT EXISTS idx_radiation_isolations_task ON radiation_isolations(task_id, state);

CREATE TABLE IF NOT EXISTS radiation_exemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    isolation_id INTEGER NOT NULL REFERENCES radiation_isolations(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES compute_tasks(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    valid_until TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_radiation_exemptions_isolation ON radiation_exemptions(isolation_id, id);

CREATE TABLE IF NOT EXISTS radiation_result_annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES compute_tasks(id) ON DELETE CASCADE,
    result_version INTEGER NOT NULL,
    confidence TEXT NOT NULL CHECK(confidence IN ('suspect','verified')),
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','cleared','replayed')),
    reason TEXT NOT NULL DEFAULT '',
    flagged_by TEXT NOT NULL,
    flagged_at TEXT NOT NULL,
    cleared_by TEXT NOT NULL DEFAULT '',
    cleared_at TEXT,
    clear_reason TEXT NOT NULL DEFAULT '',
    replayed_by TEXT NOT NULL DEFAULT '',
    replayed_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(event_id, task_id, result_version),
    FOREIGN KEY(task_id, result_version) REFERENCES compute_results(task_id, version) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_radiation_annotations_task ON radiation_result_annotations(task_id, state);
CREATE INDEX IF NOT EXISTS idx_radiation_annotations_event ON radiation_result_annotations(event_id, state);

CREATE TABLE IF NOT EXISTS radiation_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES radiation_events(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    task_id INTEGER,
    detail_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(event_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_radiation_journal_event ON radiation_journal(event_id, seq);
"""

# 与 app.database.SCHEMA 中 compute_tasks 定义保持一致，仅在状态约束中增加 frozen。
COMPUTE_TASKS_REBUILD = r"""
CREATE TABLE compute_tasks__radiation_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER NOT NULL REFERENCES compute_templates(id) ON DELETE RESTRICT,
    project_code TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    parameter_digest TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50 CHECK(priority BETWEEN 0 AND 100),
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','cancel_requested','cancelled','succeeded','failed','frozen')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT NOT NULL DEFAULT '',
    current_result_version INTEGER,
    last_error_code TEXT NOT NULL DEFAULT '',
    last_error_message TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(requested_by, idempotency_key)
);
"""

DEFAULT_POLICY_RULES = {
    "critical": {"action": "keep", "annotate_results": False},
    "sensitive": {"action": "freeze", "annotate_results": True},
    "batch": {"action": "freeze", "annotate_results": True},
    "default": {"action": "freeze", "annotate_results": True},
}


def _compute_tasks_supports_frozen(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='compute_tasks'"
    ).fetchone()
    return row is not None and "frozen" in (row[0] or "")


def _migrate_compute_tasks(connection: sqlite3.Connection) -> None:
    """旧库的 compute_tasks 状态约束没有 frozen，按 SQLite 推荐步骤重建该表。"""
    if _compute_tasks_supports_frozen(connection):
        return
    # 连接为 autocommit（isolation_level=None），逐条执行 DDL/DML 即可
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute(COMPUTE_TASKS_REBUILD)
        connection.execute(
            "INSERT INTO compute_tasks__radiation_new "
            "SELECT id,template_id,project_code,requested_by,parameters_json,parameter_digest,"
            "priority,idempotency_key,status,attempt_count,max_attempts,available_at,lease_owner,"
            "lease_expires_at,current_result_version,last_error_code,last_error_message,version,"
            "started_at,finished_at,created_at,updated_at FROM compute_tasks"
        )
        connection.execute("DROP TABLE compute_tasks")
        connection.execute("ALTER TABLE compute_tasks__radiation_new RENAME TO compute_tasks")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_compute_tasks_queue "
            "ON compute_tasks(status,priority DESC,available_at,created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_compute_tasks_owner "
            "ON compute_tasks(requested_by,status,created_at)"
        )
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def ensure_schema(now: str | None = None) -> None:
    """创建辐射领域表、迁移冻结状态并写入内置默认策略（幂等）。"""
    import json

    from app.core.clock import to_storage, utc_now

    stamp = now or to_storage(utc_now())
    connection = get_connection()
    connection.executescript(SCHEMA)
    _migrate_compute_tasks(connection)
    # 重建 compute_tasks 后再执行一次，确保索引与辐射表完整
    connection.executescript(SCHEMA)
    exists = connection.execute(
        "SELECT 1 FROM radiation_policies WHERE code='default' AND version=1"
    ).fetchone()
    if exists is None:
        connection.execute(
            "INSERT INTO radiation_policies(code,version,name,rules_json,default_risk_level,"
            "change_reason,created_by,created_at,is_current) VALUES('default',1,'默认辐射隔离策略',?,?,?,"
            "'system',?,1)",
            (
                json.dumps(DEFAULT_POLICY_RULES, ensure_ascii=False, sort_keys=True),
                "batch",
                "关键诊断任务保留，普通批处理冻结并标注结果",
                stamp,
            ),
        )
