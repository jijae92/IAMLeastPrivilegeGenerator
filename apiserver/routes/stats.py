"""API route for returning aggregated metrics."""

from __future__ import annotations

from typing import Any


def handle(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": 200,
        "body": {
            "message": "Usage statistics not implemented yet",
            "requestedPath": event.get("path"),
        },
    }
