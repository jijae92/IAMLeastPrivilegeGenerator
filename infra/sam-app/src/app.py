"""SAM Lambda handler shim."""

from __future__ import annotations

from apiserver.app import lambda_handler as api_lambda_handler


def lambda_handler(event, context):
    """Forward events to the shared API handler."""
    return api_lambda_handler(event, context)
