"""Aggregate normalized CloudTrail events into actionable metrics."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

import boto3

from core.models import ActionRecord, EventModel


@dataclass(slots=True)
class _AggregateState:
    record: ActionRecord


class ActionAggregator:
    """Group normalized events by principal and action with optional filtering."""

    def __init__(
        self,
        principal_filter: str | None = None,
        exclude_actions: Iterable[str] | str | None = None,
        allow_actions: Iterable[str] | str | None = None,
        allow_principals: Iterable[str] | str | None = None,
        allow_resources: Iterable[str] | str | None = None,
        min_count: int = 1,
        dynamodb_table: Any | str | None = None,
        dynamodb_resource: Any | None = None,
    ) -> None:
        self.principal_pattern = re.compile(principal_filter) if principal_filter else None
        if isinstance(exclude_actions, str):
            self.exclude_patterns = [pat.strip() for pat in exclude_actions.split(",") if pat.strip()]
        else:
            self.exclude_patterns = list(exclude_actions or [])
        if isinstance(allow_actions, str):
            self.allow_patterns = [pat.strip() for pat in allow_actions.split(",") if pat.strip()]
        else:
            self.allow_patterns = list(allow_actions or [])
        if isinstance(allow_principals, str):
            self.allow_principals = [pat.strip() for pat in allow_principals.split(",") if pat.strip()]
        else:
            self.allow_principals = list(allow_principals or [])
        if isinstance(allow_resources, str):
            self.allow_resource_patterns = [pat.strip() for pat in allow_resources.split(",") if pat.strip()]
        else:
            self.allow_resource_patterns = list(allow_resources or [])
        self.min_count = max(min_count, 1)

        if isinstance(dynamodb_table, str):
            resource = dynamodb_resource or boto3.resource("dynamodb")
            self.table = resource.Table(dynamodb_table)
        else:
            self.table = dynamodb_table

    def aggregate(self, events: Iterable[EventModel]) -> list[ActionRecord]:
        states: dict[tuple[str, str, str], _AggregateState] = {}

        for event in events:
            if not self._include_principal(event.principal_arn):
                continue

            action_name = self._normalize_action(event)
            if self._is_excluded(action_name):
                continue

            key = (event.principal_arn, event.aws_service, action_name)
            state = states.get(key)
            if state is None:
                state = _AggregateState(
                    record=ActionRecord(
                        principal_arn=event.principal_arn,
                        service=event.aws_service,
                        action=action_name,
                    )
                )
                states[key] = state

            state.record.register(event)

        records = [
            state.record
            for state in states.values()
            if state.record.count >= self.min_count
            and not self._is_allowlisted(state.record.action, state.record.principal_arn, state.record.resources)
        ]
        records.sort(key=lambda rec: (rec.principal_arn, rec.service, rec.action))

        if self.table is not None and records:
            self._upsert(records)

        return records

    # ------------------------------------------------------------------
    def _include_principal(self, principal: str) -> bool:
        if self.principal_pattern is None:
            return True
        return bool(self.principal_pattern.search(principal))

    def _normalize_action(self, event: EventModel) -> str:
        action = event.action
        if ":" in action:
            return action
        return f"{event.aws_service}:{action}"

    def _is_excluded(self, action: str) -> bool:
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(action, pattern):
                return True
        return False

    def _is_allowlisted(self, action: str, principal: str, resources: list[str]) -> bool:
        for pattern in self.allow_patterns:
            if fnmatch.fnmatch(action, pattern):
                return True
        for pattern in self.allow_principals:
            if fnmatch.fnmatch(principal, pattern):
                return True
        for pattern in self.allow_resource_patterns:
            if any(fnmatch.fnmatch(resource, pattern) for resource in resources):
                return True
        return False

    def _upsert(self, records: Iterable[ActionRecord]) -> None:
        for record in records:
            last_seen_iso = record.last_seen.isoformat() if isinstance(record.last_seen, datetime) else None
            try:
                self.table.update_item(  # type: ignore[no-untyped-call]
                    Key={
                        "principal_arn": record.principal_arn,
                        "service_action": f"{record.service}#{record.action}",
                    },
                    UpdateExpression="SET #cnt = :count, #last = :last, #resources = :resources, #conditions = :conditions",
                    ExpressionAttributeNames={
                        "#cnt": "count",
                        "#last": "last_seen",
                        "#resources": "resources",
                        "#conditions": "conditions",
                    },
                    ExpressionAttributeValues={
                        ":count": record.count,
                        ":last": last_seen_iso,
                        ":resources": record.resources,
                        ":conditions": record.conditions,
                    },
                )
            except Exception:  # pragma: no cover - network/service errors logged upstream
                # DynamoDB persistence is best-effort; failures should not break aggregation.
                continue


__all__ = ["ActionAggregator"]
