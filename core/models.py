"""Data models shared across the pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class EventModel(BaseModel):
    """Normalized CloudTrail event representation used by the aggregator."""

    event_time: datetime = Field(..., description="Timestamp when the action occurred")
    principal_arn: str = Field(..., description="Authenticated identity executing the action")
    principal_type: str = Field(..., description="Type of identity (user, role, assumed-role, service)")
    account_id: str = Field(..., description="AWS account ID associated with the principal")
    region: str = Field("", description="AWS region where the event occurred")
    event_source: str = Field(..., description="AWS service endpoint emitting the event")
    action: str = Field(..., description="AWS API action, e.g., s3:GetObject")
    request_parameters: dict[str, Any] = Field(default_factory=dict)
    response_elements: dict[str, Any] = Field(default_factory=dict)
    resource_arns: list[str] = Field(default_factory=list)
    error_code: Optional[str] = Field(default=None)
    aws_service: str = Field(..., description="Short service prefix derived from event_source")
    is_read_only: bool = Field(default=False)
    is_denied_pre_policy: bool = Field(default=False, description="True if AccessDenied prior to policy generation")


class ActionRecord(BaseModel):
    """Aggregated view of service actions performed by a principal."""

    principal_arn: str
    service: str
    action: str
    count: int = 0
    resources: list[str] = Field(default_factory=list)
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    last_seen: Optional[datetime] = None

    def register(self, event: "EventModel") -> None:
        self.count += 1
        if event.event_time and (self.last_seen is None or event.event_time > self.last_seen):
            self.last_seen = event.event_time
        for resource in event.resource_arns:
            if resource not in self.resources:
                self.resources.append(resource)


class PolicyStatement(BaseModel):
    """IAM policy statement with minimal metadata for diffing and simulation."""

    sid: str | None = None
    effect: str = "Allow"
    actions: list[str] = Field(default_factory=list, alias="Action")
    resources: list[str] = Field(default_factory=list, alias="Resource")
    conditions: dict[str, Any] = Field(default_factory=dict, alias="Condition")

    model_config = {
        "populate_by_name": True,
        "use_enum_values": True,
    }


class PolicyDoc(BaseModel):
    """Least-privilege policy document composed of IAM statements."""

    version: str = Field(default="2012-10-17", alias="Version")
    statements: list[PolicyStatement] = Field(default_factory=list, alias="Statement")

    model_config = {
        "populate_by_name": True,
        "use_enum_values": True,
    }

    @computed_field
    @property
    def services(self) -> list[str]:
        """Return unique AWS services referenced in the policy."""
        services: set[str] = set()
        for statement in self.statements:
            for action in statement.actions:
                services.add(action.split(":", 1)[0])
        return sorted(services)

    @classmethod
    def example(cls, id_hint: str) -> "PolicyDoc":
        return cls(  # type: ignore[arg-type]
            statements=[
                PolicyStatement(
                    sid=f"Allow{ id_hint.capitalize() }Read",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::example-bucket/*"],
                )
            ]
        )


__all__ = ["EventModel", "ActionRecord", "PolicyStatement", "PolicyDoc"]
