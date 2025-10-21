"""Output helpers for the IAMLP CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, List

from pydantic import BaseModel

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "NOTE": "note",
}


def _default_serializer(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def emit(data: Any, fmt: str, output_path: Path | None = None) -> None:
    if fmt == "json":
        rendered = json.dumps(data, indent=2, default=_default_serializer)
    elif fmt == "md":
        rendered = _to_markdown(data)
    elif fmt == "table":
        rendered = _to_table(data)
    elif fmt == "sarif":
        rendered = _to_sarif(data)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
    else:
        print(rendered)


def write_jsonl(records: Iterable[Any], output_path: Path | None = None) -> None:
    lines = [json.dumps(record, default=_default_serializer) for record in records]
    rendered = "\n".join(lines)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + ("\n" if rendered and not rendered.endswith("\n") else ""), encoding="utf-8")
    else:
        if rendered:
            print(rendered)


def load_json_objects(path: Path) -> list[Any]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _to_markdown(data: Any) -> str:
    if isinstance(data, list):
        if not data:
            return "(no data)"
        if not isinstance(data[0], dict):
            return "\n".join(f"- {item}" for item in data)
        headers = sorted({key for row in data if isinstance(row, dict) for key in row.keys()})
        lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
        for row in data:
            values = [str(row.get(header, "")) for header in headers]
            lines.append("| " + " | ".join(values) + " |")
        return "\n".join(lines)
    if isinstance(data, dict):
        lines = ["| Key | Value |", "| --- | --- |"]
        for key, value in data.items():
            lines.append(f"| {key} | {value} |")
        return "\n".join(lines)
    return str(data)


def _to_table(data: Any) -> str:
    if isinstance(data, list) and data and isinstance(data[0], dict):
        headers = sorted({key for row in data for key in row.keys()})
        widths = {header: max(len(header), *(len(str(row.get(header, ""))) for row in data)) for header in headers}
        header_line = " ".join(header.ljust(widths[header]) for header in headers)
        sep_line = " ".join("-" * widths[header] for header in headers)
        rows = [" ".join(str(row.get(header, "")).ljust(widths[header]) for header in headers) for row in data]
        return "\n".join([header_line, sep_line, *rows])
    if isinstance(data, dict):
        width = max(len(str(key)) for key in data.keys()) if data else 0
        return "\n".join(f"{str(key).ljust(width)} : {value}" for key, value in data.items())
    if isinstance(data, list):
        return "\n".join(str(item) for item in data)
    return str(data)

def _to_sarif(data: Any) -> str:
    results: List[dict[str, Any]] = []

    def add_result(rule_id: str, message: str, severity: str, properties: dict[str, Any] | None = None) -> None:
        level = SARIF_LEVELS.get(severity.upper(), "note")
        result: dict[str, Any] = {
            "ruleId": rule_id or "result",
            "level": level,
            "message": {"text": message},
        }
        if properties:
            result["properties"] = properties
        results.append(result)

    if isinstance(data, dict):
        summary = data.get("summary")
        if summary:
            add_result("summary", json.dumps(summary, ensure_ascii=False), "info", summary)
        details = data.get("details") or []
        if isinstance(details, list):
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                action = detail.get("action") or detail.get("ruleId") or "detail"
                before = detail.get("before")
                after = detail.get("after")
                severity = detail.get("severity", "info")
                message = f"{action}: {before} -> {after}" if before is not None and after is not None else json.dumps(detail, ensure_ascii=False)
                add_result(str(action), message, severity, detail)
        cases = data.get("cases") or []
        if isinstance(cases, list) and cases:
            for case in cases:
                if not isinstance(case, dict):
                    continue
                action = case.get("action") or "case"
                before = case.get("before")
                after = case.get("after")
                message = f"{action}: {before} -> {after}" if before and after else json.dumps(case, ensure_ascii=False)
                severity = "info"
                add_result(str(action), message, severity, case)
    elif isinstance(data, list):
        for idx, item in enumerate(data, start=1):
            message = json.dumps(item, ensure_ascii=False) if isinstance(item, dict) else str(item)
            add_result(f"item-{idx}", message, "info", item if isinstance(item, dict) else None)
    else:
        add_result("result", str(data), "info")

    if not results:
        add_result("result", json.dumps(data, ensure_ascii=False), "info")

    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": {"name": "IAM Least-Privilege Generator"}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


__all__ = ["emit", "write_jsonl", "load_json_objects"]
