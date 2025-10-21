"""Normalize raw CloudTrail events into EventModel instances."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Optional

from core.models import EventModel


def _parse_time(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class EventNormalizer:
    """Convert raw CloudTrail dictionaries into strongly typed EventModel objects."""

    INTERNAL_IDENTITY_TYPES = {"AWSSupportService", "AWSService", "AWSInternal", "Service"}
    INTERNAL_EVENT_SOURCES = {
        "signin.amazonaws.com",
        "health.amazonaws.com",
        "trustedadvisor.amazonaws.com",
    }

    def __init__(self, exclude_internal: bool = False) -> None:
        self.exclude_internal = exclude_internal

    def transform(self, raw_events: Iterable[dict[str, Any]]) -> Iterator[EventModel]:
        for raw in raw_events:
            if self.exclude_internal and self._is_internal_event(raw):
                continue
            model = self._to_model(raw)
            if model is not None:
                yield model

    def _to_model(self, raw: dict[str, Any]) -> Optional[EventModel]:
        event_time = _parse_time(raw.get("eventTime"))
        if event_time is None:
            return None

        identity: dict[str, Any] = raw.get("userIdentity") or {}
        principal_arn, principal_type = self._resolve_principal(identity)
        account_id = self._resolve_account_id(identity)

        event_source = raw.get("eventSource", "unknown.amazonaws.com")
        action = raw.get("eventName", "UnknownAction")
        request_parameters = self._ensure_dict(raw.get("requestParameters"))
        response_elements = self._ensure_dict(raw.get("responseElements"))
        resource_arns = self._extract_resources(raw)
        error_code = raw.get("errorCode")
        aws_service = event_source.split(".", 1)[0]
        read_only = self._coerce_bool(raw.get("readOnly", False))

        return EventModel(
            event_time=event_time,
            principal_arn=principal_arn,
            principal_type=principal_type,
            account_id=account_id,
            region=raw.get("awsRegion", ""),
            event_source=event_source,
            action=action,
            request_parameters=request_parameters,
            response_elements=response_elements,
            resource_arns=resource_arns,
            error_code=error_code,
            aws_service=aws_service,
            is_read_only=read_only,
            is_denied_pre_policy=(error_code == "AccessDenied"),
        )

    def _resolve_principal(self, identity: dict[str, Any]) -> tuple[str, str]:
        issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
        arn = issuer.get("arn") or identity.get("arn") or "unknown"
        raw_type = issuer.get("type") or identity.get("type") or "unknown"
        principal_type = self._normalize_principal_type(raw_type)
        return arn, principal_type

    def _resolve_account_id(self, identity: dict[str, Any]) -> str:
        issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
        account_id = issuer.get("accountId") or identity.get("accountId")
        if account_id is None:
            return ""
        return str(account_id)

    @staticmethod
    def _normalize_principal_type(raw_type: str) -> str:
        mapping = {
            "IAMUser": "user",
            "Root": "root",
            "Role": "role",
            "AssumedRole": "assumed-role",
            "AWSService": "service",
            "AWSAccount": "account",
            "AWSInternal": "service",
            "AWSSupportService": "service",
            "FederatedUser": "assumed-role",
        }
        return mapping.get(raw_type, raw_type.lower() if raw_type else "unknown")

    def _extract_resources(self, raw: dict[str, Any]) -> list[str]:
        resources = raw.get("resources") or []
        arns: list[str] = []
        for entry in resources:
            if not isinstance(entry, dict):
                continue
            arn = entry.get("ARN") or entry.get("arn") or entry.get("resourceARN")
            if arn:
                arns.append(str(arn))
        return arns

    @staticmethod
    def _ensure_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() == "true"
        return bool(value)

    def _is_internal_event(self, raw: dict[str, Any]) -> bool:
        identity: dict[str, Any] = raw.get("userIdentity") or {}
        identity_type = identity.get("type", "")
        if identity_type in self.INTERNAL_IDENTITY_TYPES:
            return True
        event_source = raw.get("eventSource", "") or ""
        if event_source in self.INTERNAL_EVENT_SOURCES:
            return True
        if event_source.startswith("internal."):
            return True
        return False
