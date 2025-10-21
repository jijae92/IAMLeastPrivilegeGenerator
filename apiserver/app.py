"""Entrypoint compatible with AWS Lambda + API Gateway."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict

from apiserver.routes import generate, stats

RouteHandler = Callable[[dict[str, Any]], dict[str, Any]]


ROUTES: Dict[str, RouteHandler] = {
    "GET /stats": stats.handle,
    "POST /generate": generate.handle,
}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    method = event.get("httpMethod", "GET")
    path = event.get("resource") or event.get("path", "/")
    key = f"{method.upper()} {path}"
    handler = ROUTES.get(key)

    if not handler:
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"message": "Route not found"}),
        }

    response = handler(event)
    response.setdefault("headers", {"Content-Type": "application/json"})
    if "body" in response and not isinstance(response["body"], str):
        response["body"] = json.dumps(response["body"])
    return response
