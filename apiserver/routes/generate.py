"""API route for generating policies."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any, Tuple

from core.allowlist import load_allowlist
from core.constants import COMPLIANCE_TAGS
from core.models import ActionRecord
from core.policy.generator import PolicyGenerator


def _coerce_actions(raw_actions: list[dict[str, Any]]) -> list[ActionRecord]:
    records: list[ActionRecord] = []
    for item in raw_actions:
        if "action" not in item:
            continue
        principal = item.get("principal_arn") or item.get("principal") or "unknown"
        records.append(
            ActionRecord(
                principal_arn=principal,
                service=item.get("service") or item["action"].split(":", 1)[0],
                action=item["action"],
                count=item.get("count", 1),
                resources=item.get("resources", []),
                conditions=item.get("conditions", []),
            )
        )
    return records


def _filter_allowlist(records: list[ActionRecord], allowlist: dict[str, Any]) -> Tuple[list[ActionRecord], list[dict[str, Any]]]:
    action_patterns = allowlist.get("actions", []) or []
    resource_patterns = allowlist.get("resources", []) or []
    principal_patterns = allowlist.get("principals", []) or []

    def is_allowed(record: ActionRecord) -> bool:
        if any(fnmatch(record.action, pattern) for pattern in action_patterns):
            return True
        if any(fnmatch(record.principal_arn, pattern) for pattern in principal_patterns):
            return True
        if record.resources and any(
            fnmatch(resource, pattern) for pattern in resource_patterns for resource in record.resources
        ):
            return True
        return False

    filtered: list[ActionRecord] = []
    waivers: list[dict[str, Any]] = []
    for record in records:
        if is_allowed(record):
            waivers.append(
                {
                    "action": record.action,
                    "principal": record.principal_arn,
                    "resources": record.resources,
                    "reason": allowlist.get("reason"),
                    "owner": allowlist.get("owner"),
                    "expiresAt": allowlist.get("expiresAt"),
                }
            )
        else:
            filtered.append(record)
    return filtered, waivers


def handle(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("body")
    if isinstance(payload, str):
        data = json.loads(payload or "{}")
    else:
        data = payload or {}

    raw_actions = data.get("actions", [])
    records = _coerce_actions(raw_actions) if isinstance(raw_actions, list) else []

    allowlist = load_allowlist(strict=False)
    filtered_records, waivers = _filter_allowlist(records, allowlist)

    generator = PolicyGenerator()
    policy = generator.build(filtered_records)
    policy_payload = policy.model_dump(by_alias=True)
    meta = {
        "principal": data.get("principalArn") or data.get("principal") or "unknown",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "mode": data.get("mode", "actions"),
        "compliance": COMPLIANCE_TAGS,
        "allowlistWaivers": waivers,
    }
    if allowlist.get("reason"):
        meta["allowlistReason"] = allowlist["reason"]
    if allowlist.get("expiresAt"):
        meta["allowlistExpiresAt"] = allowlist["expiresAt"]
    if allowlist.get("owner"):
        meta["allowlistOwner"] = allowlist["owner"]
    policy_payload["_meta"] = meta
    response_body = {
        "policy": policy_payload,
        "allowlist": {
            "actions": allowlist.get("actions", []),
            "resources": allowlist.get("resources", []),
            "principals": allowlist.get("principals", []),
            "reason": allowlist.get("reason"),
            "owner": allowlist.get("owner"),
            "expiresAt": allowlist.get("expiresAt"),
        },
        "allowlistWaivers": waivers,
        "compliance": COMPLIANCE_TAGS,
    }

    return {
        "statusCode": 200,
        "body": response_body,
    }
