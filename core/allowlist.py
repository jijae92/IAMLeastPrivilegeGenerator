"""Shared helpers for reading the IAMLP allowlist file."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

ALLOWLIST_PATH = Path(".iamlp-allow.json")


def load_allowlist(path: Path = ALLOWLIST_PATH, *, strict: bool | None = None) -> Dict[str, Any]:
    """Load the repo allowlist and optionally enforce expiry."""
    if strict is None:
        strict = bool(os.getenv("CI"))

    if not path.exists():
        return {
            "actions": [],
            "resources": [],
            "principals": [],
            "expiresAt": None,
            "reason": None,
        }

    payload = json.loads(path.read_text(encoding="utf-8"))
    required_keys = ["reason", "owner", "createdAt", "expiresAt"]
    missing = [key for key in required_keys if not payload.get(key)]
    if missing:
        raise RuntimeError(f".iamlp-allow.json missing required keys: {', '.join(missing)}")

    actions = payload.get("actions", []) or []
    resources = payload.get("resources", []) or []
    principals = payload.get("principals", []) or []
    expires_at = payload.get("expiresAt")
    created_at = payload.get("createdAt")

    def parse_timestamp(label: str, value: str) -> datetime:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeError(f"{label} in .iamlp-allow.json is not a valid ISO timestamp") from exc

    created_dt = parse_timestamp("createdAt", created_at)
    expiry_dt = parse_timestamp("expiresAt", expires_at)
    if expiry_dt < created_dt:
        raise RuntimeError(".iamlp-allow.json expiresAt is before createdAt")
    if expiry_dt < datetime.now(tz=timezone.utc):
        message = ".iamlp-allow.json has expired entries."
        if strict:
            raise RuntimeError(message)
        print(f"Warning: {message}", file=sys.stderr)

    return {
        "actions": actions,
        "resources": resources,
        "principals": principals,
        "expiresAt": expires_at,
        "createdAt": created_at,
        "owner": payload.get("owner"),
        "reason": payload.get("reason"),
    }
