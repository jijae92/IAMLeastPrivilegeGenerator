"""Inference utilities for deriving IAM resource scopes."""

from .arn_rules import ArnRuleRegistry
from .resource_level import ResourceLevelIndex

__all__ = ["ArnRuleRegistry", "ResourceLevelIndex"]
