"""Aggregator smoke tests."""

from __future__ import annotations

from datetime import datetime, timezone

from core.aggregator.actions import ActionAggregator
from core.models import EventModel


class DummyTable:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def update_item(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def _event(**overrides) -> EventModel:
    data = dict(
        event_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        principal_arn="arn:aws:iam::123456789012:user/Alice",
        principal_type="user",
        account_id="123456789012",
        region="us-east-1",
        event_source="s3.amazonaws.com",
        action="GetObject",
        request_parameters={},
        response_elements={},
        resource_arns=["arn:aws:s3:::example/*"],
        error_code=None,
        aws_service="s3",
        is_read_only=False,
        is_denied_pre_policy=False,
    )
    data.update(overrides)
    return EventModel(**data)


def test_action_aggregator_counts_events():
    aggregator = ActionAggregator()
    records = aggregator.aggregate([_event()])
    assert len(records) == 1
    record = records[0]
    assert record.count == 1
    assert record.last_seen.year == 2024
    assert record.resources == ["arn:aws:s3:::example/*"]


def test_action_aggregator_applies_principal_filter():
    aggregator = ActionAggregator(principal_filter=r"Bob$")
    assert aggregator.aggregate([_event()]) == []


def test_action_aggregator_excludes_patterns():
    aggregator = ActionAggregator(exclude_actions="s3:Get*")
    assert aggregator.aggregate([_event(action="GetObject")]) == []


def test_action_aggregator_respects_min_count():
    aggregator = ActionAggregator(min_count=2)
    events = [_event(), _event()]
    records = aggregator.aggregate(events)
    assert len(records) == 1
    assert records[0].count == 2


def test_action_aggregator_honors_allowlist():
    aggregator = ActionAggregator(min_count=5, allow_actions="s3:GetObject")
    records = aggregator.aggregate([_event()])
    assert records == []


def test_action_aggregator_honors_resource_allowlist():
    aggregator = ActionAggregator(min_count=5, allow_resources=["arn:aws:s3:::example/*"])
    records = aggregator.aggregate([_event()])
    assert records == []


def test_action_aggregator_upserts_to_dynamodb():
    table = DummyTable()
    aggregator = ActionAggregator(dynamodb_table=table)
    records = aggregator.aggregate([_event()])
    assert table.calls, "Expected DynamoDB upsert"
    call = table.calls[0]
    assert call["Key"]["principal_arn"].endswith("Alice")
    assert records[0].count == 1
