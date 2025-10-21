"""Compute policy change metrics and render reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Sequence

from core.models import PolicyDoc

HIGH_RISK_SERVICES = {"iam", "kms", "organizations", "sts"}


@dataclass(slots=True)
class PolicyDiff:
    before: PolicyDoc
    after: PolicyDoc

    def statement_delta(self) -> int:
        return len(self.after.statements) - len(self.before.statements)

    def allowed_action_delta(self) -> int:
        return self._count_actions(self.after) - self._count_actions(self.before)

    def resource_reduction_ratio(self) -> float:
        before_resources = self._count_resources(self.before)
        after_resources = self._count_resources(self.after)
        if before_resources == 0:
            return 0.0
        reduction = before_resources - after_resources
        return max(reduction / before_resources, 0.0)

    def high_risk_reduction(self) -> int:
        return self._high_risk(self.before) - self._high_risk(self.after)

    def as_json(self, access_denied_before: int = 0, access_denied_after: int = 0) -> dict[str, Any]:
        return {
            "statementDelta": self.statement_delta(),
            "allowedActionDelta": self.allowed_action_delta(),
            "resourceReductionRatio": self.resource_reduction_ratio(),
            "accessDeniedReduction": self._denied_reduction(access_denied_before, access_denied_after),
            "highRiskServiceReduction": self.high_risk_reduction(),
        }

    def as_markdown(self, access_denied_before: int = 0, access_denied_after: int = 0, top_n: int = 5) -> str:
        json_report = self.as_json(access_denied_before, access_denied_after)
        lines = ["| Metric | Value |", "| --- | --- |"]
        for key, value in json_report.items():
            lines.append(f"| {key} | {value} |")
        top_changes = self._top_service_changes(top_n)
        if top_changes:
            lines.append("\n**Top Risk Reductions**")
            lines.append("| Service | Before Actions | After Actions |")
            lines.append("| --- | --- | --- |")
            for service, before_count, after_count in top_changes:
                lines.append(f"| {service} | {before_count} | {after_count} |")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _denied_reduction(self, before: int, after: int) -> float:
        if before <= 0:
            return 0.0
        reduction = before - after
        return max(reduction / before, 0.0)

    @staticmethod
    def _count_actions(policy: PolicyDoc) -> int:
        total = 0
        for statement in policy.statements:
            total += len(statement.actions)
        return total

    @staticmethod
    def _count_resources(policy: PolicyDoc) -> int:
        total = 0
        for statement in policy.statements:
            total += len(statement.resources)
        return total

    @staticmethod
    def _high_risk(policy: PolicyDoc) -> int:
        total = 0
        for statement in policy.statements:
            for action in statement.actions:
                if action.split(":", 1)[0] in HIGH_RISK_SERVICES:
                    total += 1
        return total

    def _top_service_changes(self, limit: int) -> List[tuple[str, int, int]]:
        before_counts = self._service_counts(self.before)
        after_counts = self._service_counts(self.after)
        entries: List[tuple[str, int, int]] = []
        for service in set(before_counts) | set(after_counts):
            before = before_counts.get(service, 0)
            after = after_counts.get(service, 0)
            if before > after:
                entries.append((service, before, after))
        entries.sort(key=lambda item: item[0])
        return entries[:limit]

    @staticmethod
    def _service_counts(policy: PolicyDoc) -> dict[str, int]:
        counts: dict[str, int] = {}
        for statement in policy.statements:
            for action in statement.actions:
                service = action.split(":", 1)[0]
                counts[service] = counts.get(service, 0) + 1
        return counts


__all__ = ["PolicyDiff", "HIGH_RISK_SERVICES"]
