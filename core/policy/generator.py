"""Generate IAM policies from aggregated action records."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable, Tuple

from core.aggregator.conditions import ConditionReducer
from core.inference.arn_rules import ArnRuleRegistry
from core.inference.resource_level import ResourceLevelIndex
from core.models import ActionRecord, PolicyDoc, PolicyStatement


class PolicyGenerator:
    """Compose IAM policy documents using aggregated action usage."""

    def __init__(
        self,
        arn_rules: ArnRuleRegistry | None = None,
        resource_levels: ResourceLevelIndex | None = None,
        condition_reducer: ConditionReducer | None = None,
        *,
        mode: str = "actions",
        include_logs_baseline: bool = False,
        principal_arn: str | None = None,
        max_statements: int | None = None,
    ) -> None:
        if mode not in {"actions", "resources"}:
            raise ValueError("mode must be 'actions' or 'resources'")
        self.arn_rules = arn_rules or ArnRuleRegistry()
        self.resource_levels = resource_levels or ResourceLevelIndex()
        self.condition_reducer = condition_reducer or ConditionReducer()
        self.mode = mode
        self.include_logs_baseline = include_logs_baseline
        self.principal_arn = principal_arn
        self.max_statements = max_statements
        self.additional_policies: list[PolicyDoc] = []

    def build(self, actions: Iterable[ActionRecord]) -> PolicyDoc:
        records = list(actions)
        self.additional_policies = []

        if not records:
            return PolicyDoc(statements=[])  # type: ignore[arg-type]

        statements = self._compose_statements(records)

        if self.include_logs_baseline and any(record.service == "lambda" for record in records):
            statements.append(self._logs_baseline_statement())

        policies = self._chunk_statements(statements)
        self.additional_policies = policies[1:]
        return policies[0]

    # ------------------------------------------------------------------
    def _compose_statements(self, records: list[ActionRecord]) -> list[PolicyStatement]:
        grouped: dict[Tuple[str, Tuple[str, ...], str], set[str]] = {}
        conditions_map: dict[Tuple[str, Tuple[str, ...], str], dict[str, object]] = {}
        counters: dict[str, int] = defaultdict(int)
        statements: list[PolicyStatement] = []

        for record in records:
            service = record.service
            resources = self._determine_resources(record)
            condition_dict = self.condition_reducer.merge(record.conditions)
            condition_key = json.dumps(condition_dict, sort_keys=True) if condition_dict else "{}"
            key = (service, resources, condition_key)

            if key not in grouped:
                grouped[key] = set()
                conditions_map[key] = condition_dict
            grouped[key].add(record.action)

        for (service, resources, condition_key), actions in sorted(grouped.items()):
            counters[service] += 1
            sid = self._build_sid(service, counters[service])
            condition_dict = conditions_map[(service, resources, condition_key)]
            statement = PolicyStatement(  # type: ignore[arg-type]
                sid=sid,
                actions=sorted(actions),
                resources=list(resources),
                conditions=condition_dict,
            )
            statements.append(statement)

        return statements

    def _determine_resources(self, record: ActionRecord) -> Tuple[str, ...]:
        resources = tuple(sorted({*record.resources})) if record.resources else tuple()

        if resources:
            return resources

        # Attempt inference through registry when action supports resource scoping and mode permits.
        if self.mode == "resources" and self.resource_levels.allows_scoping(record.action):
            inferred = self.arn_rules.infer_from_record(record)
            if inferred:
                return tuple(sorted(inferred))

        return ("*",)

    def _logs_baseline_statement(self) -> PolicyStatement:
        sid = self._build_sid("logs", 1)
        actions = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ]
        resources = ["arn:aws:logs:*:*:log-group:/aws/lambda/*"]
        return PolicyStatement(  # type: ignore[arg-type]
            sid=sid,
            actions=actions,
            resources=resources,
            conditions={},
        )

    def _chunk_statements(self, statements: list[PolicyStatement]) -> list[PolicyDoc]:
        if not self.max_statements or len(statements) <= self.max_statements:
            return [PolicyDoc(statements=statements)]  # type: ignore[arg-type]

        chunks: list[list[PolicyStatement]] = []
        for index in range(0, len(statements), self.max_statements):
            chunks.append(statements[index : index + self.max_statements])
        return [PolicyDoc(statements=chunk) for chunk in chunks]  # type: ignore[arg-type]

    @staticmethod
    def _build_sid(service: str, counter: int) -> str:
        prefix = service.replace(":", "_").replace("-", "_")[:40] or "svc"
        sid = f"{prefix}_allow_{counter:03d}"
        return sid[:128]
