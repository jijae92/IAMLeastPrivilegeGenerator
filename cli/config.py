"""Configuration loader for the IAMLP CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULTS = {
    "project_name": "iamlp",
    "default_principal": "arn:aws:iam::123456789012:role/Example",
    "default_format": "json",
    "dynamodb_table": None,
    "deny_threshold": 0.25,
    "include_logs_baseline": False,
}


@dataclass(slots=True)
class Settings:
    project_name: str = DEFAULTS["project_name"]
    default_principal: str = DEFAULTS["default_principal"]
    default_format: str = DEFAULTS["default_format"]
    dynamodb_table: str | None = DEFAULTS["dynamodb_table"]
    deny_threshold: float = DEFAULTS["deny_threshold"]
    include_logs_baseline: bool = DEFAULTS["include_logs_baseline"]

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Settings":
        return cls(
            project_name=data.get("project_name", DEFAULTS["project_name"]),
            default_principal=data.get("default_principal", DEFAULTS["default_principal"]),
            default_format=data.get("default_format", DEFAULTS["default_format"]),
            dynamodb_table=data.get("dynamodb_table", DEFAULTS["dynamodb_table"]),
            deny_threshold=float(data.get("deny_threshold", DEFAULTS["deny_threshold"])),
            include_logs_baseline=bool(data.get("include_logs_baseline", DEFAULTS["include_logs_baseline"])),
        )

    def merge_cli(self, format_override: str | None = None, include_logs: bool | None = None) -> "Settings":
        return Settings(
            project_name=self.project_name,
            default_principal=self.default_principal,
            default_format=format_override or self.default_format,
            dynamodb_table=self.dynamodb_table,
            deny_threshold=self.deny_threshold,
            include_logs_baseline=self.include_logs_baseline if include_logs is None else include_logs,
        )


def load_settings(path: Path) -> Settings:
    if not path.exists():
        return Settings()

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError("Configuration file must be a mapping of keys to values.")

    return Settings.from_mapping(data)


__all__ = ["Settings", "load_settings"]
