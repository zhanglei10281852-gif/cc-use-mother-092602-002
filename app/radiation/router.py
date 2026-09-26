from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from app.radiation.schemas import (
    AnnotationClear,
    BatchFreeze,
    EventExemptionCreate,
    EventIngest,
    EventResolve,
    EventUnfreeze,
    ExemptionCreate,
    PolicyUpdate,
    ProfileUpsert,
    ReplayRequest,
)
from app.radiation.service import RadiationService

router = APIRouter(prefix="/api/radiation", tags=["辐射事件任务隔离"])


def service() -> RadiationService:
    return RadiationService()


# ---------- 辐射事件 ----------

@router.post("/events")
def ingest_event(payload: EventIngest):
    result = service().ingest_event(payload.model_dump())
    return JSONResponse(status_code=200 if result.get("duplicate") else 201, content=result)


@router.get("/events")
def list_events(status: str | None = Query(default=None, pattern="^(active|resolved)$"),
                limit: int = Query(default=100, ge=1, le=500)):
    return {"items": service().list_events(status=status, limit=limit)}


@router.get("/events/{event_id}")
def get_event(event_id: int):
    return service().get_event(event_id)


@router.post("/events/{event_id}/resolve")
def resolve_event(event_id: int, payload: EventResolve):
    return service().resolve_event(event_id, payload.model_dump())


@router.get("/events/{event_id}/journal")
def event_journal(event_id: int):
    return {"items": service().get_event(event_id)["journal"]}


# ---------- 策略版本 ----------

@router.get("/policies/current")
def current_policy():
    return service().get_policy()


@router.get("/policies/versions/{version}")
def policy_version(version: int):
    return service().get_policy(version)


@router.get("/policies")
def list_policies():
    return {"items": service().list_policies()}


@router.post("/policies", status_code=201)
def update_policy(payload: PolicyUpdate):
    return service().update_policy(payload.model_dump())


# ---------- 风险档案 ----------

@router.put("/profiles")
def upsert_profile(payload: ProfileUpsert):
    return service().upsert_profile(payload.model_dump())


@router.get("/profiles")
def list_profiles():
    return {"items": service().list_profiles()}


# ---------- 批量冻结 / 解冻 ----------

@router.post("/freeze")
def batch_freeze(payload: BatchFreeze):
    return service().batch_freeze(payload.model_dump())


@router.post("/events/{event_id}/unfreeze")
def unfreeze(event_id: int, payload: EventUnfreeze):
    return service().unfreeze(event_id, payload.model_dump())


# ---------- 人工豁免 ----------

@router.post("/events/{event_id}/tasks/{task_id}/exempt", status_code=201)
def exempt_task(event_id: int, task_id: int, payload: ExemptionCreate):
    return service().exempt(event_id, task_id, payload.model_dump())


@router.post("/events/{event_id}/exemptions", status_code=201)
def exempt_many(event_id: int, payload: EventExemptionCreate):
    return service().exempt_many(event_id, payload.model_dump())


@router.get("/exemptions")
def list_exemptions(event_id: int | None = None):
    return {"items": service().list_exemptions(event_id)}


# ---------- 隔离查询 ----------

@router.get("/isolations")
def list_isolations(event_id: int | None = None,
                    state: str | None = Query(default=None,
                                              pattern="^(frozen|exempted|released|kept)$"),
                    task_id: int | None = None):
    return {"items": service().list_isolations(event_id=event_id, state=state, task_id=task_id)}


# ---------- 结果可信度标注 ----------

@router.get("/annotations")
def list_annotations(event_id: int | None = None, task_id: int | None = None,
                     state: str | None = Query(default=None,
                                               pattern="^(active|cleared|replayed)$")):
    return {"items": service().list_annotations(event_id=event_id, task_id=task_id, state=state)}


@router.post("/annotations/{annotation_id}/clear")
def clear_annotation(annotation_id: int, payload: AnnotationClear):
    return service().clear_annotation(annotation_id, payload.model_dump())


# ---------- 按事件回放 ----------

@router.post("/events/{event_id}/replay")
def replay_event(event_id: int, payload: ReplayRequest):
    return service().replay_event(event_id, payload.model_dump())


# ---------- 重启对账 ----------

@router.post("/reconcile")
def reconcile():
    return service().reconcile()
