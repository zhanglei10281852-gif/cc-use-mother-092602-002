from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["critical", "normal", "maintenance"]
Severity = Literal["advisory", "watch", "warning", "severe"]
Confidence = Literal["suspect", "confirmed_clean", "recomputed_clean"]


class RadiationAlert(BaseModel):
    external_id: str = Field(min_length=2, max_length=120)
    event_type: str = Field(default="solar_particle", min_length=2, max_length=80)
    severity: Severity = "warning"
    started_at: str = Field(min_length=4, max_length=40)
    detected_at: str | None = Field(default=None, max_length=40)
    source: str = Field(default="ground-station", max_length=120)
    description: str = Field(default="", max_length=2000)
    payload: dict[str, Any] = Field(default_factory=dict)


class PolicyPublish(BaseModel):
    rules: dict[str, Any]
    change_reason: str = Field(min_length=2, max_length=1000)


class TaskRiskDeclare(BaseModel):
    risk_level: RiskLevel
    note: str = Field(default="", max_length=1000)


class BatchFreeze(BaseModel):
    task_ids: list[int] = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=2, max_length=1000)


class BatchUnfreeze(BaseModel):
    task_ids: list[int] = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=2, max_length=1000)


class BatchExempt(BatchUnfreeze):
    pass


class ResultAnnotation(BaseModel):
    confidence: Confidence
    reason: str = Field(min_length=2, max_length=1000)


class EventResolve(BaseModel):
    reason: str = Field(default="辐射事件结束，解除应急状态", min_length=2, max_length=1000)
