from __future__ import annotations

from fastapi import APIRouter, Query

from app.radiation.schemas import (
    BatchExempt,
    BatchFreeze,
    BatchUnfreeze,
    EventResolve,
    PolicyPublish,
    RadiationAlert,
    ResultAnnotation,
    TaskRiskDeclare,
)
from app.radiation.service import RadiationIsolationService

router = APIRouter(prefix="/api/radiation", tags=["辐射事件任务隔离"])


def service() -> RadiationIsolationService:
    return RadiationIsolationService()


# ---------- 辐射事件 ----------

@router.post("/events", status_code=201)
def ingest_event(payload: RadiationAlert):
    """接收地面站高能粒子告警；重复 external_id 不会重复隔离。"""
    return service().ingest_event(payload.model_dump())


@router.get("/events")
def list_events(status: str | None = Query(default=None, pattern="^(active|resolved)$")):
    return {"items": service().list_events(status)}


@router.get("/events/{event_id}")
def get_event(event_id: int):
    return service().get_event(event_id)


@router.get("/events/{event_id}/replay")
def replay_event(event_id: int):
    """按事件回放所有受影响任务、隔离记录、结果标注与操作时间线。"""
    return service().replay_event(event_id)


@router.post("/events/{event_id}/resolve")
def resolve_event(event_id: int, payload: EventResolve, actor: str = Query(..., min_length=1)):
    return service().resolve_event(event_id, actor, payload.reason)


# ---------- 批量冻结 / 解冻 / 豁免 ----------

@router.post("/events/{event_id}/freeze")
def freeze_many(event_id: int, payload: BatchFreeze, actor: str = Query(..., min_length=1)):
    return service().freeze_many(event_id, payload.task_ids, actor, payload.reason)


@router.post("/events/{event_id}/unfreeze")
def unfreeze_many(event_id: int, payload: BatchUnfreeze, actor: str = Query(..., min_length=1)):
    return service().unfreeze_many(event_id, payload.task_ids, actor, payload.reason)


@router.post("/events/{event_id}/exempt")
def exempt_many(event_id: int, payload: BatchExempt, actor: str = Query(..., min_length=1)):
    """带原因的人工豁免：任务在本事件下保持运行。"""
    return service().exempt_many(event_id, payload.task_ids, actor, payload.reason)


# ---------- 风险分级 ----------

@router.put("/tasks/{task_id}/risk")
def declare_task_risk(task_id: int, payload: TaskRiskDeclare, actor: str = Query(..., min_length=1)):
    return service().declare_task_risk(task_id, payload.risk_level, actor, payload.note)


@router.get("/task-risks")
def list_task_risks(risk_level: str | None = Query(default=None, pattern="^(critical|normal|maintenance)$")):
    return {"items": service().list_task_risks(risk_level)}


@router.get("/tasks/{task_id}/isolation")
def task_isolation(task_id: int):
    return service().isolation_state(task_id)


# ---------- 结果可信度 ----------

@router.post("/events/{event_id}/tasks/{task_id}/results/{result_version}/annotation")
def annotate_result(event_id: int, task_id: int, result_version: int,
                    payload: ResultAnnotation, actor: str = Query(..., min_length=1)):
    return service().annotate_result(event_id, task_id, result_version, payload.confidence, actor, payload.reason)


@router.get("/result-flags")
def list_result_flags(task_id: int | None = None):
    return {"items": service().list_result_flags(task_id)}


# ---------- 策略版本 ----------

@router.get("/policy")
def current_policy():
    return service().current_policy()


@router.post("/policy", status_code=201)
def publish_policy(payload: PolicyPublish, actor: str = Query(..., min_length=1)):
    """发布新版本隔离策略，记录操作者与变更原因，历史版本完整保留。"""
    return service().publish_policy(payload.rules, payload.change_reason, actor)


@router.get("/policy/versions")
def list_policy_versions():
    return {"items": service().list_policy_versions()}


# ---------- 全局快照 ----------

@router.get("/snapshot")
def snapshot():
    return service().snapshot()
