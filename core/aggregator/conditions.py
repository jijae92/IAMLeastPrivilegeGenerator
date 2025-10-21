"""Condition merging strategies for IAM statements."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable


class ConditionReducer:
    """Merge condition dictionaries while preserving least-privilege semantics."""

    def merge(self, conditions: Iterable[dict[str, object]]) -> dict[str, object]:
        merged: Dict[str, object] = {}
        for condition in conditions:
            for operator, value in condition.items():
                if operator not in merged:
                    merged[operator] = value
                else:
                    merged[operator] = self._combine_values(merged[operator], value)
        return merged

    @staticmethod
    def _combine_values(existing: object, new: object) -> object:
        if isinstance(existing, list) and isinstance(new, list):
            return sorted({*existing, *new})
        if isinstance(existing, str) and isinstance(new, str):
            if existing == new:
                return existing
            return sorted({existing, new})  # type: ignore[return-value]
        return new
