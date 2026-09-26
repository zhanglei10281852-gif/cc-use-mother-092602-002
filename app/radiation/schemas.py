from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

RiskLevel = Literal["critical", "sensitive", "batch"]
Severity = Literal["advisory", "warning", "alert", "critical"]


class EventIngest(BaseModel):
    event_code: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
    source: str = Field(min_length=1, max_length=120)
    severity: Severity = "alert"
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=4000)
    region: str = Field(default="", max_length=120)
    occurred_at: str | None = Field(default=None, description="事件发生时间，ISO8601，缺省取接收时间")
    ingested_by: str = Field(min_length=1, max_length=120)


class PolicyRule(BaseModel):
    action: Literal["freeze", "keep"]
    annotate_results: bool = True


class PolicyUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    rules: dict[str, PolicyRule]
    default_risk_level: RiskLevel = "batch"
    actor: str = Field(min_length=1, max_length=120)
    change_reason: str = Field(min_length=2, max_length=1000)

    @model_validator(mode="after")
    def validate_rules(self) -> "PolicyUpdate":
        unknown = set(self.rules) - {"critical", "sensitive", "batch", "default"}
        if unknown:
            raise ValueError(f"策略包含未知风险等级：{sorted(unknown)}")
        if "default" not in self.rules:
            raise ValueError("策略必须包含 default 兜底规则")
        return self


class ProfileUpsert(BaseModel):
    target_type: Literal["task", "template", "project"]
    target_key: str = Field(min_length=1, max_length=160)
    risk_level: RiskLevel
    reason: str = Field(default="", max_length=1000)
    actor: str = Field(min_length=1, max_length=120)


class ExemptionCreate(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    valid_until: str | None = Field(default=None, description="豁免有效期，ISO8601，缺省为长期有效")


class EventExemptionCreate(ExemptionCreate):
    task_ids: list[int] = Field(default_factory=list, max_length=500,
                                description="为空时对该事件下全部冻结任务豁免")


class BatchFreeze(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    event_code: str | None = Field(default=None, description="缺省时写入 manual 事件")
    task_ids: list[int] = Field(default_factory=list, max_length=500,
                                description="为空时按当前策略冻结全部可冻结任务")
    risk_level: RiskLevel | None = Field(default=None, description="手工指定风险等级，缺省按档案与策略解析")


class EventResolve(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    release_isolations: bool = True


class AnnotationClear(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    confidence: Literal["verified"] = "verified"


class ReplayRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    task_ids: list[int] = Field(default_factory=list, max_length=500,
                                description="为空时回放该事件下全部可疑结果对应任务")


class EventUnfreeze(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=1000)
    task_ids: list[int] = Field(default_factory=list, max_length=500,
                                description="为空时解除该事件下全部冻结隔离")
    include_exempted: bool = Field(default=False, description="是否同时解除已豁免的隔离记录")
