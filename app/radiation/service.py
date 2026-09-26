from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import get_connection, transaction
from app.radiation.repository import RadiationRepository

FREEZABLE_STATUSES = {"queued", "running"}
# 回放时允许重新排队的终态
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "cancel_requested"}


def screen_task_against_active_events(connection: sqlite3.Connection, task: sqlite3.Row | dict[str, Any],
                                      now: str, *, actor: str = "compute-submit") -> list[int]:
    """计算任务提交成功后在同一事务内按全部活跃事件筛查。

    返回该任务被冻结的事件 id 列表；辐射表尚未初始化时直接跳过。
    """
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='radiation_policies'"
    ).fetchone() is None:
        return []
    repository = RadiationRepository(connection)
    policy_row = repository.current_policy("default")
    if policy_row is None:
        return []
    rules = json.loads(policy_row["rules_json"])
    service = RadiationService(connection)
    frozen_events: list[int] = []
    for event_row in repository.active_events():
        outcome = service._apply_one(
            repository, dict(event_row), dict(task), rules, now,
            actor=actor, reason="告警期间新提交任务自动筛查", window_end=now,
        )
        if outcome == "frozen":
            frozen_events.append(int(event_row["id"]))
    return frozen_events


class RadiationService:
    """辐射事件下的任务风险分级、隔离、豁免、结果标注与回放。"""

    def __init__(self, connection: sqlite3.Connection | None = None,
                 clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------
    # 事件接入（重复告幂等）
    # ------------------------------------------------------------------

    def ingest_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        occurred = self._normalize_time(payload.get("occurred_at"), now)
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            existing = repository.event_by_code(payload["event_code"])
            if existing is not None:
                if existing["status"] != "active":
                    raise ConflictError("辐射事件已结束，不能对同一事件编码重复接入；请使用新的事件编码")
                repository.mark_duplicate(existing["id"], now)
                self._journal(repository, existing["id"], now,
                              payload["ingested_by"], "duplicate_alert", None,
                              {"source": payload["source"], "severity": payload["severity"]})
                return self._event_detail(repository, repository.event_by_id(existing["id"]),
                                          duplicate=True)
            event = repository.create_event(
                event_code=payload["event_code"], source=payload["source"],
                severity=payload["severity"], title=payload["title"],
                description=payload["description"], region=payload["region"],
                occurred_at=occurred, ingested_by=payload["ingested_by"], now=now,
            )
            self._journal(repository, event["id"], now, payload["ingested_by"],
                          "event_received", None, {"severity": payload["severity"]})
            policy = self._current_policy(repository)
            rules = json.loads(policy["rules_json"])
            for task in repository.list_all_tasks():
                self._apply_one(repository, event, dict(task), rules, now,
                                actor=payload["ingested_by"], reason="告警接入自动隔离",
                                window_end=now)
            return self._event_detail(repository, repository.event_by_id(event["id"]))

    def list_events(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        return self.repository().list_events(status=status, limit=max(1, min(limit, 500)))

    def get_event(self, event_id: int) -> dict[str, Any]:
        with transaction() as connection:
            repository = RadiationRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("辐射事件不存在")
            return self._event_detail(repository, event)

    def resolve_event(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("辐射事件不存在")
            if event["status"] != "active":
                raise ConflictError("辐射事件已经结束")
            policy = self._current_policy(repository)
            rules = json.loads(policy["rules_json"])
            # 解除前再补齐事件窗口内产生的结果标注
            for isolation in repository.list_isolations(event_id=event_id):
                task = repository.task_by_id(isolation["task_id"])
                if task is not None:
                    self._annotate_window(repository, event, dict(task), rules,
                                          isolation["risk_level"], now,
                                          actor=payload["actor"])
            if payload.get("release_isolations", True):
                self._release(repository, event_id, payload["actor"],
                              "事件结束：" + payload["reason"], now,
                              include_exempted=True)
            repository.resolve_event(event_id, payload["actor"], payload["reason"], now)
            self._journal(repository, event_id, now, payload["actor"], "event_resolved", None,
                          {"reason": payload["reason"],
                           "release_isolations": bool(payload.get("release_isolations", True))})
            return self._event_detail(repository, repository.event_by_id(event_id))

    # ------------------------------------------------------------------
    # 策略（版本化 + 操作者）
    # ------------------------------------------------------------------

    def get_policy(self, version: int | None = None) -> dict[str, Any]:
        repository = self.repository()
        row = self._current_policy(repository) if version is None else repository.policy_by_version("default", version)
        if row is None:
            raise NotFoundError("策略版本不存在")
        return self._policy_dict(row)

    def list_policies(self) -> list[dict[str, Any]]:
        return [self._policy_dict(row) for row in self.repository().list_policies()]

    def update_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        rules = dict(payload["rules"])
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            current = self._current_policy(repository)
            next_version = int(current["version"]) + 1 if current else 1
            if current is not None:
                before = self._policy_dict(current)
                if before["rules"] == rules and before["default_risk_level"] == payload["default_risk_level"]:
                    raise ConflictError("新策略与当前版本完全相同，无需生成新版本")
            created = repository.create_policy_version(
                code="default", version=next_version, name=payload["name"], rules=rules,
                default_risk_level=payload["default_risk_level"],
                change_reason=payload["change_reason"], actor=payload["actor"], now=now,
            )
            return self._policy_dict(created)

    # ------------------------------------------------------------------
    # 风险档案
    # ------------------------------------------------------------------

    def upsert_profile(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            return RadiationRepository(connection).upsert_profile(
                target_type=payload["target_type"], target_key=payload["target_key"],
                risk_level=payload["risk_level"], reason=payload["reason"],
                actor=payload["actor"], now=now,
            )

    def list_profiles(self) -> list[dict[str, Any]]:
        return self.repository().list_profiles()

    # ------------------------------------------------------------------
    # 批量冻结 / 解冻
    # ------------------------------------------------------------------

    def batch_freeze(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event_code = payload.get("event_code")
            if event_code:
                event_row = repository.event_by_code(event_code)
                if event_row is None:
                    raise NotFoundError("辐射事件不存在")
                if event_row["status"] != "active":
                    raise ConflictError("辐射事件已经结束，不能继续冻结")
                event = dict(event_row)
            else:
                event_code = "MANUAL-" + self._short_digest(
                    [payload["actor"], payload["reason"], payload.get("task_ids", []), now]
                )
                if repository.event_by_code(event_code) is not None:
                    raise ConflictError("同参数手工冻结批次已经存在")
                event = repository.create_event(
                    event_code=event_code, source="manual", severity="alert",
                    title="人工批量冻结", description=payload["reason"], region="",
                    occurred_at=now, ingested_by=payload["actor"], now=now,
                )
                self._journal(repository, event["id"], now, payload["actor"],
                              "event_received", None, {"source": "manual"})
            policy = self._current_policy(repository)
            rules = json.loads(policy["rules_json"])
            requested = list(dict.fromkeys(payload.get("task_ids") or []))
            succeeded: list[dict[str, Any]] = []
            failed: list[dict[str, Any]] = []
            if requested:
                tasks = []
                for task_id in requested:
                    row = repository.task_by_id(task_id)
                    if row is None:
                        failed.append({"task_id": task_id, "code": "not_found",
                                       "message": "计算任务不存在"})
                    else:
                        tasks.append(dict(row))
            else:
                tasks = [dict(row) for row in repository.list_all_tasks()]
            for task in tasks:
                outcome = self._apply_one(
                    repository, event, task, rules, now, actor=payload["actor"],
                    reason=payload["reason"], forced_action="freeze",
                    forced_risk=payload.get("risk_level"), window_end=now,
                )
                if outcome in {"already_isolated"}:
                    failed.append({"task_id": task["id"], "code": "conflict",
                                   "message": "该事件下已存在隔离记录"})
                else:
                    isolation = repository.isolation(event["id"], task["id"])
                    succeeded.append({"task_id": task["id"], "outcome": outcome,
                                      "risk_level": isolation["risk_level"],
                                      "state": isolation["state"]})
            return {"event_id": event["id"], "event_code": event["event_code"],
                    "succeeded": succeeded, "failed": failed}

    def unfreeze(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("辐射事件不存在")
            task_ids = payload.get("task_ids") or None
            return self._release(
                repository, event_id, payload["actor"], payload["reason"], now,
                include_exempted=bool(payload.get("include_exempted", False)),
                task_ids=task_ids,
            )

    # ------------------------------------------------------------------
    # 人工豁免
    # ------------------------------------------------------------------

    def exempt(self, event_id: int, task_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        valid_until = self._normalize_valid_until(payload.get("valid_until"))
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event, isolation = self._require_isolation(repository, event_id, task_id)
            if event["status"] != "active":
                raise ConflictError("辐射事件已经结束")
            if isolation["state"] != "frozen":
                raise ConflictError(f"隔离当前状态为 {isolation['state']}，无需豁免")
            repository.update_isolation_state(
                isolation["id"], "exempted", now,
                actor_field="exempted_by", actor=payload["actor"], at_field="exempted_at",
            )
            task = repository.task_by_id(task_id)
            if task is not None and task["status"] == "frozen":
                repository.unfreeze_task(task_id, now)
            exemption = repository.add_exemption(
                isolation_id=isolation["id"], event_id=event_id, task_id=task_id,
                actor=payload["actor"], reason=payload["reason"],
                valid_until=valid_until, now=now,
            )
            self._journal(repository, event_id, now, payload["actor"], "exempt", task_id,
                          {"reason": payload["reason"], "valid_until": valid_until,
                           "exemption_id": exemption["id"]})
            return {"isolation": self._isolation_dict(repository.isolation_by_id(isolation["id"])),
                    "exemption": exemption}

    def exempt_many(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("辐射事件不存在")
            if payload.get("task_ids"):
                raw = [(task_id, repository.isolation(event_id, task_id))
                       for task_id in dict.fromkeys(payload["task_ids"])]
                for missing_task_id, missing in raw:
                    if missing is None:
                        failed.append({"task_id": missing_task_id, "code": "not_found",
                                       "message": "该事件下不存在此任务的隔离记录"})
                isolations = [row for _, row in raw if row is not None]
            else:
                isolations = [repository.isolation_by_id(item["id"])
                              for item in repository.list_isolations(event_id=event_id,
                                                                     state="frozen")]
            succeeded: list[dict[str, Any]] = []
            failed: list[dict[str, Any]] = []
            valid_until = self._normalize_valid_until(payload.get("valid_until"))
            for isolation in isolations:
                if isolation is None:
                    continue
                task_id = int(isolation["task_id"])
                if isolation["state"] != "frozen" or event["status"] != "active":
                    failed.append({"task_id": task_id, "code": "conflict",
                                   "message": f"隔离状态 {isolation['state']} 不能豁免"})
                    continue
                repository.update_isolation_state(
                    isolation["id"], "exempted", now,
                    actor_field="exempted_by", actor=payload["actor"], at_field="exempted_at",
                )
                task = repository.task_by_id(task_id)
                if task is not None and task["status"] == "frozen":
                    repository.unfreeze_task(task_id, now)
                exemption = repository.add_exemption(
                    isolation_id=isolation["id"], event_id=event_id, task_id=task_id,
                    actor=payload["actor"], reason=payload["reason"],
                    valid_until=valid_until, now=now,
                )
                self._journal(repository, event_id, now, payload["actor"], "exempt", task_id,
                              {"reason": payload["reason"], "valid_until": valid_until,
                               "exemption_id": exemption["id"]})
                succeeded.append({"task_id": task_id, "exemption_id": exemption["id"],
                                  "valid_until": valid_until})
            return {"event_id": event_id, "succeeded": succeeded, "failed": failed}

    def list_exemptions(self, event_id: int | None = None) -> list[dict[str, Any]]:
        return self.repository().list_exemptions(event_id=event_id)

    # ------------------------------------------------------------------
    # 结果可信度标注
    # ------------------------------------------------------------------

    def list_annotations(self, *, event_id: int | None = None, task_id: int | None = None,
                         state: str | None = None) -> list[dict[str, Any]]:
        return self.repository().list_annotations(event_id=event_id, task_id=task_id, state=state)

    def clear_annotation(self, annotation_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            row = repository.annotation_by_id(annotation_id)
            if row is None:
                raise NotFoundError("结果标注不存在")
            if row["state"] != "active":
                raise ConflictError(f"标注当前状态为 {row['state']}，不能解除")
            repository.update_annotation(
                annotation_id, state="cleared", confidence="verified",
                cleared_by=payload["actor"], cleared_at=now, clear_reason=payload["reason"],
            )
            self._journal(repository, row["event_id"], now, payload["actor"],
                          "result_verified", row["task_id"],
                          {"annotation_id": annotation_id, "result_version": row["result_version"],
                           "reason": payload["reason"]})
            return dict(repository.annotation_by_id(annotation_id))

    # ------------------------------------------------------------------
    # 按事件回放
    # ------------------------------------------------------------------

    def replay_event(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("辐射事件不存在")
            annotations = repository.list_annotations(event_id=event_id, state="active")
            wanted = set(payload.get("task_ids") or [])

            def selected(task_id: int) -> bool:
                return not wanted or task_id in wanted

            requeued: list[dict[str, Any]] = []
            skipped: list[dict[str, Any]] = []
            affected_task_ids = list(dict.fromkeys(
                item["task_id"] for item in annotations if selected(item["task_id"])
            ))
            # 仍处于冻结的受影响任务即使没有结果标注，也在回放时一并解冻
            for item in repository.list_isolations(event_id=event_id, state="frozen"):
                if selected(item["task_id"]) and item["task_id"] not in affected_task_ids:
                    affected_task_ids.append(item["task_id"])
            for task_id in affected_task_ids:
                task = repository.task_by_id(task_id)
                if task is None:
                    skipped.append({"task_id": task_id, "code": "not_found",
                                    "message": "计算任务不存在"})
                    continue
                versions = [item["result_version"]
                            for item in annotations
                            if item["task_id"] == task_id and item["state"] == "active"]
                if task["status"] == "frozen":
                    repository.unfreeze_task(task_id, now)
                    action = "unfrozen"
                elif task["status"] in TERMINAL_STATUSES:
                    repository.requeue_task(task_id, now)
                    action = "requeued"
                else:
                    action = f"already_{task['status']}"
                isolation = repository.isolation(event_id, task_id)
                if isolation is not None and isolation["state"] == "frozen":
                    repository.update_isolation_state(
                        isolation["id"], "released", now,
                        actor_field="released_by", actor=payload["actor"],
                        at_field="released_at",
                    )
                for item in annotations:
                    if item["task_id"] == task_id and item["state"] == "active":
                        repository.update_annotation(item["id"], state="replayed",
                                                      replayed_by=payload["actor"],
                                                      replayed_at=now)
                self._journal(repository, event_id, now, payload["actor"], "replay", task_id,
                              {"reason": payload["reason"], "result_versions": versions,
                               "action": action})
                requeued.append({"task_id": task_id, "action": action,
                                 "result_versions": versions})
            return {"event_id": event_id, "replayed": requeued, "skipped": skipped}

    # ------------------------------------------------------------------
    # 隔离查询
    # ------------------------------------------------------------------

    def list_isolations(self, *, event_id: int | None = None, state: str | None = None,
                        task_id: int | None = None) -> list[dict[str, Any]]:
        rows = self.repository().list_isolations(event_id=event_id, state=state, task_id=task_id)
        return [self._isolation_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # 重启对账：以数据库中的隔离记录为准，还原/修复任务冻结状态
    # ------------------------------------------------------------------

    def reconcile(self) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        refrozen: list[int] = []
        restored: list[int] = []
        with transaction(immediate=True) as connection:
            repository = RadiationRepository(connection)
            frozen_ids = {
                int(row["task_id"])
                for row in connection.execute(
                    "SELECT DISTINCT i.task_id FROM radiation_isolations i "
                    "JOIN radiation_events e ON e.id=i.event_id "
                    "WHERE i.state='frozen' AND e.status='active'"
                ).fetchall()
            }
            for task in repository.list_all_tasks():
                task_id = int(task["id"])
                if task["status"] == "frozen" and task_id not in frozen_ids:
                    connection.execute(
                        "UPDATE compute_tasks SET status='queued',available_at=?,"
                        "lease_owner='',lease_expires_at='',updated_at=?,version=version+1 "
                        "WHERE id=? AND status='frozen'",
                        (now, now, task_id),
                    )
                    restored.append(task_id)
                elif task["status"] not in {"frozen"} and task_id in frozen_ids:
                    if task["status"] in FREEZABLE_STATUSES:
                        repository.freeze_task(task_id, now)
                        refrozen.append(task_id)
        return {"refrozen": refrozen, "restored": restored}

    # ------------------------------------------------------------------
    # 内部：单任务隔离决策（同时服务于事件接入、手工冻结与新任务筛查）
    # ------------------------------------------------------------------

    def _apply_one(self, repository: RadiationRepository, event: dict[str, Any],
                   task: dict[str, Any], rules: dict[str, Any], now: str, *,
                   actor: str, reason: str, forced_action: str | None = None,
                   forced_risk: str | None = None,
                   window_end: str) -> str:
        if repository.isolation(event["id"], task["id"]) is not None:
            return "already_isolated"
        risk_level = forced_risk or self._resolve_risk(repository, task, rules)
        rule = rules.get(risk_level) or rules["default"]
        action = forced_action or rule["action"]
        if action == "keep":
            repository.create_isolation(
                event_id=event["id"], task_id=task["id"], risk_level=risk_level,
                action="keep", state="kept", reason=reason,
                previous_status=task["status"], previous=task,
                frozen_by="", frozen_at=None, now=now,
            )
            self._journal(repository, event["id"], now, actor, "keep", task["id"],
                          {"risk_level": risk_level})
            outcome = "kept"
        elif task["status"] in FREEZABLE_STATUSES:
            repository.create_isolation(
                event_id=event["id"], task_id=task["id"], risk_level=risk_level,
                action="freeze", state="frozen", reason=reason,
                previous_status=task["status"], previous=task,
                frozen_by=actor, frozen_at=now, now=now,
            )
            repository.freeze_task(task["id"], now)
            self._journal(repository, event["id"], now, actor, "freeze", task["id"],
                          {"risk_level": risk_level, "previous_status": task["status"]})
            outcome = "frozen"
        else:
            # 终态任务无法冻结，仅保留记录并标注结果
            repository.create_isolation(
                event_id=event["id"], task_id=task["id"], risk_level=risk_level,
                action="freeze", state="kept",
                reason=f"{reason}（任务处于终态 {task['status']}，未冻结）",
                previous_status=task["status"], previous=task,
                frozen_by="", frozen_at=None, now=now,
            )
            self._journal(repository, event["id"], now, actor, "skip_terminal", task["id"],
                          {"risk_level": risk_level, "status": task["status"]})
            outcome = "terminal_kept"
        if rule.get("annotate_results", True):
            self._annotate_window(repository, event, task, rules, risk_level, window_end,
                                  actor=actor)
        return outcome

    def _annotate_window(self, repository: RadiationRepository, event: dict[str, Any],
                         task: dict[str, Any], rules: dict[str, Any], risk_level: str,
                         window_end: str, *, actor: str) -> int:
        rule = rules.get(risk_level) or rules.get("default") or {}
        if not rule.get("annotate_results", True):
            return 0
        amount = 0
        for result in repository.results_in_window(task["id"], event["occurred_at"], window_end):
            if repository.annotation(event["id"], task["id"], int(result["version"])) is not None:
                continue
            repository.create_annotation(
                event_id=event["id"], task_id=task["id"],
                result_version=int(result["version"]), confidence="suspect",
                reason=f"辐射事件 {event['event_code']} 窗口内产生，可能受辐射影响",
                flagged_by=actor, now=window_end,
            )
            self._journal(repository, event["id"], window_end, actor, "result_flagged",
                          task["id"], {"result_version": int(result["version"])})
            amount += 1
        return amount

    def _resolve_risk(self, repository: RadiationRepository, task: dict[str, Any],
                      rules: dict[str, Any]) -> str:
        for target_type, target_key in (
            ("task", str(task["id"])),
            ("template", str(task["template_code"])),
            ("project", str(task["project_code"])),
        ):
            profile = repository.profile(target_type, target_key)
            if profile is not None:
                return str(profile["risk_level"])
        policy = self._current_policy(repository)
        return str(policy["default_risk_level"])

    def _release(self, repository: RadiationRepository, event_id: int, actor: str,
                 reason: str, now: str, *, include_exempted: bool,
                 task_ids: set[int] | list[int] | None = None) -> dict[str, Any]:
        wanted = set(task_ids) if task_ids else None
        released: list[int] = []
        for item in repository.list_isolations(event_id=event_id):
            if wanted is not None and item["task_id"] not in wanted:
                continue
            if item["state"] == "frozen":
                repository.update_isolation_state(
                    item["id"], "released", now,
                    actor_field="released_by", actor=actor, at_field="released_at",
                )
                task = repository.task_by_id(item["task_id"])
                if task is not None and task["status"] == "frozen":
                    repository.unfreeze_task(item["task_id"], now)
                released.append(int(item["task_id"]))
                self._journal(repository, event_id, now, actor, "release", item["task_id"],
                              {"reason": reason})
            elif include_exempted and item["state"] == "exempted":
                repository.update_isolation_state(
                    item["id"], "released", now,
                    actor_field="released_by", actor=actor, at_field="released_at",
                )
                released.append(int(item["task_id"]))
                self._journal(repository, event_id, now, actor, "release", item["task_id"],
                              {"reason": reason, "previously": "exempted"})
        return {"event_id": event_id, "released": released}

    # ------------------------------------------------------------------
    # 内部：装配与工具
    # ------------------------------------------------------------------

    def repository(self) -> RadiationRepository:
        return RadiationRepository(self.connection)

    @staticmethod
    def _current_policy(repository: RadiationRepository) -> sqlite3.Row:
        policy = repository.current_policy("default")
        if policy is None:
            raise ConflictError("尚未初始化辐射隔离策略")
        return policy

    @staticmethod
    def _require_isolation(repository: RadiationRepository, event_id: int,
                           task_id: int) -> tuple[dict[str, Any], sqlite3.Row]:
        event = repository.event_by_id(event_id)
        if event is None:
            raise NotFoundError("辐射事件不存在")
        isolation = repository.isolation(event_id, task_id)
        if isolation is None:
            raise NotFoundError("该事件下不存在此任务的隔离记录")
        return dict(event), isolation

    @staticmethod
    def _journal(repository: RadiationRepository, event_id: int, now: str, actor: str,
                 action: str, task_id: int | None, detail: dict[str, Any]) -> None:
        seq = repository.next_journal_seq(event_id)
        repository.add_journal(event_id=event_id, seq=seq, occurred_at=now, actor=actor,
                               action=action, task_id=task_id, detail=detail)

    @staticmethod
    def _normalize_time(value: str | None, default: str | None) -> str:
        if not value:
            if default is None:
                raise ValidationError("时间格式不正确，应为 ISO8601")
            return default
        parsed = from_storage(value)
        if parsed is None:
            raise ValidationError("时间格式不正确，应为 ISO8601")
        return to_storage(parsed)

    def _normalize_valid_until(self, value: str | None) -> str | None:
        if not value:
            return None
        parsed = from_storage(value)
        if parsed is None:
            raise ValidationError("时间格式不正确，应为 ISO8601")
        if parsed <= self.clock.now():
            raise ValidationError("豁免有效期必须晚于当前时间")
        return to_storage(parsed)

    @staticmethod
    def _short_digest(parts: list[Any]) -> str:
        import hashlib

        text = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(text.encode()).hexdigest()[:16].upper()

    @staticmethod
    def _policy_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        data = dict(row)
        data["rules"] = json.loads(data.pop("rules_json"))
        return data

    @staticmethod
    def _isolation_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        data = dict(row)
        data["previous"] = json.loads(data.pop("previous_json", "{}") or "{}")
        return data

    def _event_detail(self, repository: RadiationRepository,
                      event: sqlite3.Row | dict[str, Any], *, duplicate: bool = False) -> dict[str, Any]:
        event_id = int(dict(event)["id"])
        isolations = repository.list_isolations(event_id=event_id)
        annotations = repository.list_annotations(event_id=event_id)
        state_counts: dict[str, int] = {}
        for item in isolations:
            state_counts[item["state"]] = state_counts.get(item["state"], 0) + 1
        annotation_counts: dict[str, int] = {}
        for item in annotations:
            annotation_counts[item["state"]] = annotation_counts.get(item["state"], 0) + 1
        return {
            "event": dict(event),
            "duplicate": duplicate,
            "isolation_counts": state_counts,
            "annotation_counts": annotation_counts,
            "isolations": [self._isolation_dict(item) for item in isolations],
            "journal": repository.journal(event_id),
        }
