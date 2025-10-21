"""Simulate IAM policy effects using AWS or local evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - boto3 optional in some environments
    boto3 = None

from core.models import PolicyDoc


@dataclass
class SimulationCase:
    action: str
    resource: str = "*"
    context: Dict[str, Any] | None = None


class PolicySimulator:
    """Evaluate before/after policies against test cases."""

    def __init__(self, client: Any | None = None) -> None:
        self._client = client or (boto3.client("iam") if boto3 else None)

    def compare(
        self,
        before: PolicyDoc,
        after: PolicyDoc,
        cases: Iterable[SimulationCase],
    ) -> list[dict[str, Any]]:
        tests = list(cases)
        before_results = self._run(before, tests)
        after_results = self._run(after, tests)

        diff: list[dict[str, Any]] = []
        for case in tests:
            key = (case.action, case.resource)
            before_effect = before_results.get(key, "Deny")
            after_effect = after_results.get(key, "Deny")
            diff.append(
                {
                    "action": case.action,
                    "resource": case.resource,
                    "context": case.context or {},
                    "before": before_effect,
                    "after": after_effect,
                }
            )
        return diff

    def _run(self, policy: PolicyDoc, cases: List[SimulationCase]) -> Dict[tuple[str, str], str]:
        if self._client:
            return self._aws_simulate(policy, cases)
        return self._local_simulate(policy, cases)

    def _aws_simulate(self, policy: PolicyDoc, cases: List[SimulationCase]) -> Dict[tuple[str, str], str]:
        statements = [statement.model_dump(by_alias=True, exclude_none=True) for statement in policy.statements]
        context_entries = []
        for case in cases:
            ctx = case.context or []
            if isinstance(ctx, list):
                for entry in ctx:
                    if isinstance(entry, dict) and {"ContextKeyName", "ContextKeyType", "ContextKeyValues"} <= entry.keys():
                        context_entries.append(entry)
            elif isinstance(ctx, dict) and {"ContextKeyName", "ContextKeyType", "ContextKeyValues"} <= ctx.keys():
                context_entries.append(ctx)  # pragma: no cover - rarely used

        kwargs = {
            "PolicyInputList": [{"Version": policy.version, "Statement": statements}],
            "ActionNames": [case.action for case in cases],
            "ResourceArns": [case.resource for case in cases],
        }
        if context_entries:
            kwargs["ContextEntries"] = context_entries
        try:
            response = self._client.simulate_custom_policy(**kwargs)  # type: ignore[no-untyped-call]
        except Exception:  # pragma: no cover - network/service errors
            return self._local_simulate(policy, cases)

        results: Dict[tuple[str, str], str] = {}
        for entry in response.get("EvaluationResults", []):
            action = entry.get("EvalActionName", "")
            resource = entry.get("EvalResourceName", "*")
            decision = entry.get("EvalDecision", "implicitDeny")
            results[(action, resource)] = "Allow" if decision == "allowed" else "Deny"
        return results

    def _local_simulate(self, policy: PolicyDoc, cases: List[SimulationCase]) -> Dict[tuple[str, str], str]:
        results: Dict[tuple[str, str], str] = {}
        for case in cases:
            decision = "Deny"
            for statement in policy.statements:
                if statement.effect != "Allow":
                    continue
                if not self._action_matches(case.action, statement.actions):
                    continue
                if not self._resource_matches(case.resource, statement.resources):
                    continue
                decision = "Allow"
                break
            results[(case.action, case.resource)] = decision
        return results

    @staticmethod
    def _action_matches(action: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if pattern == action:
                return True
            if pattern.endswith("*") and action.startswith(pattern[:-1]):
                return True
        return False

    @staticmethod
    def _resource_matches(resource: str, patterns: list[str]) -> bool:
        if not patterns:
            return resource == "*"
        for pattern in patterns:
            if pattern == "*" or pattern == resource:
                return True
            if pattern.endswith("*") and resource.startswith(pattern[:-1]):
                return True
        return False


__all__ = ["PolicySimulator", "SimulationCase"]
