"""API routes."""

from .generate import handle as generate
from .stats import handle as stats

__all__ = ["generate", "stats"]
