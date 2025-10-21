#!/usr/bin/env python3
"""Generate SARIF and Markdown summaries from pip-audit JSON with allowlist context."""

from __future__ import annotations

import argparse
import json
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List

from core.allowlist import load_allowlist

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def load_vulnerabilities(path: Path, allowlist: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    patterns = (
        (allowlist.get("actions") or [])
        + (allowlist.get("resources") or [])
        + (allowlist.get("principals") or [])
    )

    def is_waived(package: str, vuln_id: str) -> bool:
        return any(fnmatch(package or "", pattern) or fnmatch(vuln_id or "", pattern) for pattern in patterns)

    findings: List[Dict[str, Any]] = []
    for dep in data.get("dependencies", []):
        name = dep.get("name")
        version = dep.get("version")
        for vuln in dep.get("vulns") or dep.get("vulnerabilities") or []:
            severity = (vuln.get("severity") or "INFO").upper()
            vuln_id = vuln.get("id") or "UNKNOWN"
            findings.append(
                {
                    "package": name,
                    "version": version,
                    "id": vuln_id,
                    "severity": severity,
                    "description": vuln.get("description") or "",
                    "fix": ", ".join(vuln.get("fix_versions") or []) or "-",
                    "waived": is_waived(name or "", vuln_id),
                }
            )
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["package"], item["id"]))
    return findings


def write_sarif(findings: List[Dict[str, Any]], sarif_path: Path) -> None:
    results = []
    for item in findings:
        message = f"{item['package']}@{item['version']} - {item['id']}: {item['description']}".strip()
        results.append(
            {
                "ruleId": item["id"],
                "level": SARIF_LEVEL.get(item["severity"], "note"),
                "message": {"text": message},
                "properties": {
                    "severity": item["severity"],
                    "package": item["package"],
                    "version": item["version"],
                    "fix": item["fix"],
                    "waived": item.get("waived", False),
                },
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": {"name": "pip-audit"}},
                "results": results,
            }
        ],
    }
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def build_markdown(findings: List[Dict[str, Any]], top: int, allowlist: Dict[str, Any]) -> str:
    if not findings:
        summary = "✅ pip-audit: no vulnerabilities detected."
    else:
        header = "| Severity | Package | Version | Vulnerability | Fix | Waived |\n| --- | --- | --- | --- | --- | --- |"
        rows = []
        for item in findings[:top]:
            rows.append(
                f"| {item['severity']} | {item['package']} | {item['version']} | {item['id']} | {item['fix']} | {item.get('waived', False)} |"
            )
        body = "\n".join([header, *rows])
        summary = f"⚠️ **pip-audit findings (top {min(top, len(findings))})**\n\n{body}"

    allowlist_section = _allowlist_markdown(allowlist)
    return f"{summary}\n\n{allowlist_section}"


def _allowlist_markdown(allowlist: Dict[str, Any]) -> str:
    if not allowlist:
        return "(no allowlist entries)"
    entries = []
    for typ, patterns in (
        ("Action", allowlist.get("actions", [])),
        ("Resource", allowlist.get("resources", [])),
        ("Principal", allowlist.get("principals", [])),
    ):
        for pattern in patterns or []:
            entries.append((typ, pattern))
    if not entries:
        return "(no allowlist entries)"
    header = "| Type | Pattern | Owner | Expires | Reason |\n| --- | --- | --- | --- | --- |"
    rows = [
        f"| {typ} | {pattern} | {allowlist.get('owner','-')} | {allowlist.get('expiresAt','-')} | {allowlist.get('reason','-')} |"
        for typ, pattern in entries
    ]
    return f"📄 **Allowlist**\n\n{header}\n" + "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize pip-audit output")
    parser.add_argument("--input", required=True, type=Path, help="Path to pip-audit JSON")
    parser.add_argument("--sarif", required=True, type=Path, help="Output SARIF path")
    parser.add_argument("--top", type=int, default=10, help="Top N findings for comment table")
    parser.add_argument("--output", type=Path, help="Optional markdown output path")
    parser.add_argument("--allowlist", type=Path, default=Path(".iamlp-allow.json"), help="Allowlist file path")
    args = parser.parse_args()

    allowlist_info: Dict[str, Any] = {}
    if args.allowlist and args.allowlist.exists():
        allowlist_info = load_allowlist(args.allowlist)

    findings = load_vulnerabilities(args.input, allowlist_info)
    write_sarif(findings, args.sarif)

    markdown = build_markdown(findings, args.top, allowlist_info)
    if args.output:
        args.output.write_text(markdown, encoding="utf-8")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
