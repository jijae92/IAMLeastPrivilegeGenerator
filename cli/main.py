"""Command line interface for IAM Least-Privilege workflows."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, List, Tuple

from datetime import datetime, timezone
from fnmatch import fnmatch

from cli import config, output
from core import models
from core.aggregator.actions import ActionAggregator
from core.allowlist import load_allowlist
from core.constants import COMPLIANCE_TAGS
from core.inference.arn_rules import ArnRuleRegistry
from core.parser.cloudtrail_reader import CloudTrailReader
from core.parser.normalizer import EventNormalizer
from core.policy.diff import PolicyDiff
from core.policy.generator import PolicyGenerator
from core.policy.simulator import PolicySimulator, SimulationCase

class CLIError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iamlp", description="IAM Least-Privilege toolkit")
    parser.add_argument("--config", type=Path, default=Path("iamlp.yml"), help="Path to CLI configuration file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # parse -----------------------------------------------------------------
    parse_cmd = subparsers.add_parser("parse", help="Normalize CloudTrail events")
    source = parse_cmd.add_mutually_exclusive_group(required=True)
    source.add_argument("--local-dir", type=Path)
    source.add_argument("--s3-bucket")
    parse_cmd.add_argument("--prefix", default="")
    parse_cmd.add_argument("--start")
    parse_cmd.add_argument("--end")
    parse_cmd.add_argument("--principal-filter")
    parse_cmd.add_argument("--exclude-internal", action="store_true")
    parse_cmd.add_argument("--output", type=Path)
    parse_cmd.add_argument("--format", choices=["json", "md", "table"], help="Output format override")

    # aggregate --------------------------------------------------------------
    agg_cmd = subparsers.add_parser("aggregate", help="Aggregate normalized events")
    agg_source = agg_cmd.add_mutually_exclusive_group(required=True)
    agg_source.add_argument("--events", type=Path)
    agg_source.add_argument("--local-dir", type=Path)
    agg_source.add_argument("--s3-bucket")
    agg_cmd.add_argument("--prefix", default="")
    agg_cmd.add_argument("--start")
    agg_cmd.add_argument("--end")
    agg_cmd.add_argument("--principal-filter")
    agg_cmd.add_argument("--exclude-actions")
    agg_cmd.add_argument("--allow-actions")
    agg_cmd.add_argument("--min-count", type=int, default=1)
    agg_cmd.add_argument("--dynamodb-table")
    agg_cmd.add_argument("--output", type=Path)
    agg_cmd.add_argument("--format", choices=["json", "md", "table"], help="Output format override")

    # infer ------------------------------------------------------------------
    infer_cmd = subparsers.add_parser("infer", help="Infer resource ARNs for events")
    infer_cmd.add_argument("--events", type=Path, required=True)
    infer_cmd.add_argument("--output", type=Path)
    infer_cmd.add_argument("--format", choices=["json", "md", "table"], help="Output format override")

    # generate ---------------------------------------------------------------
    gen_cmd = subparsers.add_parser("generate", help="Create IAM policies from aggregates")
    gen_cmd.add_argument("--from-agg", required=True, help="Path to ActionRecord JSON or dynamodb://TABLE")
    gen_cmd.add_argument("--mode", choices=["actions", "resources"], default="actions")
    gen_cmd.add_argument("--include-logs-baseline", action="store_true")
    gen_cmd.add_argument("--output", type=Path)
    gen_cmd.add_argument("--principal-arn", help="Principal ARN to annotate in generated metadata")
    gen_cmd.add_argument("--format", choices=["json", "md", "table"], help="Output format override")

    # diff / simulate --------------------------------------------------------
    diff_cmd = subparsers.add_parser("diff", help="Compare policies using simulation")
    diff_cmd.add_argument("--before", required=True, type=Path)
    diff_cmd.add_argument("--after", required=True, type=Path)
    diff_cmd.add_argument("--cases", type=Path, required=True)
    diff_cmd.add_argument("--deny-threshold", type=float)
    diff_cmd.add_argument("--output", type=Path)
    diff_cmd.add_argument("--format", choices=["json", "md", "table"], help="Output format override")

    # alias for simulate
    simulate_cmd = subparsers.add_parser("simulate", help=argparse.SUPPRESS)
    simulate_cmd.add_argument("--before", required=True, type=Path)
    simulate_cmd.add_argument("--after", required=True, type=Path)
    simulate_cmd.add_argument("--cases", type=Path, required=True)
    simulate_cmd.add_argument("--deny-threshold", type=float)
    simulate_cmd.add_argument("--output", type=Path)
    simulate_cmd.add_argument("--format", choices=["json", "md", "table"], help=argparse.SUPPRESS)

    return parser


def app(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = config.load_settings(args.config)
        format_override = getattr(args, "format", None)
        effective_format = format_override or settings.default_format

        if args.command == "parse":
            return _cmd_parse(args, settings.merge_cli(format_override=effective_format))
        if args.command == "aggregate":
            return _cmd_aggregate(args, settings.merge_cli(format_override=effective_format))
        if args.command == "infer":
            return _cmd_infer(args, settings.merge_cli(format_override=effective_format))
        if args.command == "generate":
            include_logs = args.include_logs_baseline or settings.include_logs_baseline
            merged = settings.merge_cli(format_override=effective_format, include_logs=include_logs)
            return _cmd_generate(args, merged)
        if args.command in {"diff", "simulate"}:
            merged = settings.merge_cli(format_override=effective_format)
            return _cmd_diff(args, merged)
    except CLIError as exc:
        print(exc, file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - unexpected errors bubble up
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# Command implementations


def _cmd_parse(args: argparse.Namespace, settings: config.Settings) -> int:
    if args.local_dir:
        source = args.local_dir
        reader = CloudTrailReader(str(source), start=args.start, end=args.end)
    else:
        if not args.s3_bucket:
            raise CLIError("--s3-bucket is required when --local-dir is not provided")
        prefix = args.prefix or ""
        source = f"s3://{args.s3_bucket}/{prefix}".rstrip("/")
        reader = CloudTrailReader(source, start=args.start, end=args.end)

    normalizer = EventNormalizer(exclude_internal=args.exclude_internal)
    principal_pattern = re.compile(args.principal_filter) if args.principal_filter else None

    events: List[models.EventModel] = []
    for event in normalizer.transform(reader.load()):
        if principal_pattern and not principal_pattern.search(event.principal_arn):
            continue
        events.append(event)

    records = [event.model_dump(mode="json") for event in events]

    if settings.default_format == "json" and not args.output:
        output.write_jsonl(records, output_path=None)
    else:
        fmt = settings.default_format
        if fmt == "json":
            output.write_jsonl(records, output_path=args.output)
        else:
            output.emit(records, fmt, output_path=args.output)
    return 0


def _cmd_aggregate(args: argparse.Namespace, settings: config.Settings) -> int:
    events = _load_events_from_args(args)
    allowlist = load_allowlist()
    allow_actions = args.allow_actions or ",".join(allowlist["actions"])
    allow_principals = ",".join(allowlist["principals"])
    allow_resources = ",".join(allowlist["resources"])
    aggregator = ActionAggregator(
        principal_filter=args.principal_filter,
        exclude_actions=args.exclude_actions,
        allow_actions=allow_actions,
        allow_principals=allow_principals,
        allow_resources=allow_resources,
        min_count=args.min_count,
        dynamodb_table=args.dynamodb_table or settings.dynamodb_table,
    )
    records = aggregator.aggregate(events)
    payload = [record.model_dump(mode="json") for record in records]
    output.emit(payload, settings.default_format, output_path=args.output)
    return 0


def _cmd_infer(args: argparse.Namespace, settings: config.Settings) -> int:
    events = _load_event_file(args.events)
    registry = ArnRuleRegistry()
    inferred = []
    for event in events:
        arns = registry.infer(event)
        inferred.append(
            {
                "action": event.action,
                "service": event.aws_service,
                "principal": event.principal_arn,
                "resources": sorted(arns),
            }
        )
    output.emit(inferred, settings.default_format, output_path=args.output)
    return 0


def _cmd_generate(args: argparse.Namespace, settings: config.Settings) -> int:
    records = _load_aggregates(args.from_agg)
    allowlist = load_allowlist()
    filtered_records, waivers = _apply_allowlist(records, allowlist)
    generator = PolicyGenerator(mode=args.mode, include_logs_baseline=settings.include_logs_baseline)
    policy = generator.build(filtered_records)
    policy_dict = policy.model_dump(by_alias=True)
    meta = {
        "principal": args.principal_arn or settings.default_principal,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "compliance": COMPLIANCE_TAGS,
        "allowlistWaivers": waivers,
    }
    if allowlist.get("reason"):
        meta["allowlistReason"] = allowlist["reason"]
    if allowlist.get("expiresAt"):
        meta["allowlistExpiresAt"] = allowlist["expiresAt"]
    if allowlist.get("owner"):
        meta["allowlistOwner"] = allowlist["owner"]
    policy_dict["_meta"] = meta

    overflow_payloads: list[dict[str, object]] = []
    for index, doc in enumerate(generator.additional_policies, start=1):
        doc_payload = doc.model_dump(by_alias=True)
        doc_payload["_meta"] = {**meta, "overflowIndex": index}
        overflow_payloads.append(doc_payload)

    payload = {
        "policy": policy_dict,
        "overflowPolicies": overflow_payloads,
        "compliance": COMPLIANCE_TAGS,
        "allowlist": _allowlist_entries(allowlist),
        "allowlistWaivers": waivers,
    }
    output.emit(payload, settings.default_format, output_path=args.output)
    return 0


def _cmd_diff(args: argparse.Namespace, settings: config.Settings) -> int:
    before = _load_policy(args.before)
    after = _load_policy(args.after)
    cases_data = output.load_json_objects(args.cases)
    cases = [SimulationCase(action=item["action"], resource=item.get("resource", "*"), context=item.get("context")) for item in cases_data]
    simulator = PolicySimulator()
    results = simulator.compare(before, after, cases)

    before_denies = sum(1 for row in results if row["before"] == "Deny")
    after_denies = sum(1 for row in results if row["after"] == "Deny")

    diff = PolicyDiff(before, after)
    metrics = diff.as_json(access_denied_before=before_denies, access_denied_after=after_denies)

    before_action_total = PolicyDiff._count_actions(before)
    allow_delta = metrics.get("allowedActionDelta", 0)
    allow_reduced_pct = 0.0
    if before_action_total > 0 and allow_delta < 0:
        allow_reduced_pct = round((-allow_delta / before_action_total) * 100, 1)

    resource_concrete_pct = round((metrics.get("resourceReductionRatio", 0) or 0) * 100, 1)
    deny_change = after_denies - before_denies
    summary = {
        "allow_reduced_pct": allow_reduced_pct,
        "resource_concrete_pct": resource_concrete_pct,
        "deny_change": deny_change,
        "high_risk_reduced": metrics.get("highRiskServiceReduction", 0),
    }

    allowlist = load_allowlist()
    details = _resource_differences(before, after, allowlist)
    for result in results:
        action = result.get("action", "")
        res_after = [result.get("after")] if result.get("after") else []
        if _is_allowlisted(action, "", res_after, allowlist):
            result["waived"] = True
            result["reason"] = allowlist.get("reason")
            result["owner"] = allowlist.get("owner")
            result["expiresAt"] = allowlist.get("expiresAt")

    payload = {
        "summary": summary,
        "details": details,
        "cases": results,
        "metrics": metrics,
        "compliance": COMPLIANCE_TAGS,
        "allowlist": _allowlist_entries(allowlist),
        "allowlistWaivers": _allowlist_waiver_rows(allowlist),
    }

    fmt = args.format or settings.default_format
    output.emit(payload, fmt, output_path=args.output)

    threshold = args.deny_threshold if args.deny_threshold is not None else settings.deny_threshold
    if before_denies == 0 and after_denies > 0:
        return 3
    if before_denies > 0:
        increase = after_denies - before_denies
        if increase > 0 and increase / before_denies > threshold:
            return 3
    return 0


# ---------------------------------------------------------------------------
# Helpers


def _load_events_from_args(args: argparse.Namespace) -> List[models.EventModel]:
    if getattr(args, "events", None):
        return _load_event_file(args.events)
    if args.local_dir:
        reader = CloudTrailReader(str(args.local_dir), start=args.start, end=args.end)
        normalizer = EventNormalizer()
        return list(normalizer.transform(reader.load()))
    if args.s3_bucket:
        source = f"s3://{args.s3_bucket}/{args.prefix or ''}".rstrip("/")
        reader = CloudTrailReader(source, start=args.start, end=args.end)
        normalizer = EventNormalizer()
        return list(normalizer.transform(reader.load()))
    raise CLIError("Must provide --events, --local-dir, or --s3-bucket for aggregation")


def _load_event_file(path: Path) -> List[models.EventModel]:
    objects = output.load_json_objects(path)
    return [models.EventModel.model_validate(obj) for obj in objects]


def _load_aggregates(identifier: str) -> List[models.ActionRecord]:
    if identifier.startswith("dynamodb://"):
        raise CLIError("DynamoDB aggregation lookup not yet implemented")
    path = Path(identifier)
    objects = output.load_json_objects(path)
    return [models.ActionRecord.model_validate(obj) for obj in objects]


def _load_policy(path: Path) -> models.PolicyDoc:
    data = json.loads(path.read_text(encoding="utf-8"))
    return models.PolicyDoc.model_validate(data)


def main() -> None:
    raise SystemExit(app())


def _apply_allowlist(records: Iterable[models.ActionRecord], allowlist: dict[str, Any]) -> tuple[list[models.ActionRecord], list[dict[str, Any]]]:
    filtered: list[models.ActionRecord] = []
    waivers: list[dict[str, Any]] = []
    for record in records:
        principal = getattr(record, "principal_arn", "")
        resources = getattr(record, "resources", [])
        if _is_allowlisted(record.action, principal, resources, allowlist):
            waivers.append(
                {
                    "action": record.action,
                    "principal": principal,
                    "resources": resources,
                    "reason": allowlist.get("reason"),
                    "owner": allowlist.get("owner"),
                    "expiresAt": allowlist.get("expiresAt"),
                }
            )
        else:
            filtered.append(record)
    return filtered, waivers


def _resource_differences(before: models.PolicyDoc, after: models.PolicyDoc, allowlist: dict[str, Any]) -> list[dict[str, Any]]:
    def collect(policy: models.PolicyDoc) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for statement in policy.statements:
            resources = statement.resources or ["*"]
            normalized = [resource or "*" for resource in resources]
            for action in statement.actions:
                mapping[action] = normalized
        return mapping

    before_map = collect(before)
    after_map = collect(after)
    details: list[dict[str, str]] = []
    for action in sorted(set(before_map) | set(after_map)):
        before_resources = before_map.get(action, ["*"])
        after_resources = after_map.get(action, ["*"])
        if before_resources != after_resources:
            detail: dict[str, Any] = {
                "action": action,
                "before": ", ".join(before_resources),
                "after": ", ".join(after_resources),
            }
            if _is_allowlisted(action, "", after_resources, allowlist):
                detail["waived"] = True
                detail["reason"] = allowlist.get("reason")
                detail["owner"] = allowlist.get("owner")
                detail["expiresAt"] = allowlist.get("expiresAt")
            details.append(detail)
    return details


def _allowlist_entries(allowlist: dict[str, Any]) -> dict[str, Any]:
    return {
        "actions": allowlist.get("actions", []),
        "resources": allowlist.get("resources", []),
        "principals": allowlist.get("principals", []),
        "reason": allowlist.get("reason"),
        "owner": allowlist.get("owner"),
        "createdAt": allowlist.get("createdAt"),
        "expiresAt": allowlist.get("expiresAt"),
    }


def _allowlist_waiver_rows(allowlist: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    reason = allowlist.get("reason")
    owner = allowlist.get("owner")
    expires = allowlist.get("expiresAt")

    for action in allowlist.get("actions", []) or []:
        entries.append({"type": "action", "pattern": action, "reason": reason, "owner": owner, "expiresAt": expires})
    for resource in allowlist.get("resources", []) or []:
        entries.append({"type": "resource", "pattern": resource, "reason": reason, "owner": owner, "expiresAt": expires})
    for principal in allowlist.get("principals", []) or []:
        entries.append({"type": "principal", "pattern": principal, "reason": reason, "owner": owner, "expiresAt": expires})
    return entries


def _is_allowlisted(action: str, principal: str, resources: Iterable[str], allowlist: dict[str, Any]) -> bool:
    if any(fnmatch(action, pattern) for pattern in allowlist.get("actions", []) or []):
        return True
    if principal and any(fnmatch(principal, pattern) for pattern in allowlist.get("principals", []) or []):
        return True
    resource_patterns = allowlist.get("resources", []) or []
    if resource_patterns:
        for resource in resources or []:
            if any(fnmatch(resource, pattern) for pattern in resource_patterns):
                return True
    return False


if __name__ == "__main__":
    main()
