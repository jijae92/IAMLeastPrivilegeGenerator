"""Parser module smoke tests."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Iterator

import pytest

from core.parser.cloudtrail_reader import CloudTrailReader
from core.parser.normalizer import EventNormalizer

FIXTURE = Path("tests/fixtures/cloudtrail/multi_events.json")


def _fixture_payload() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def _write_fixture(path: Path) -> None:
    path.write_text(_fixture_payload(), encoding="utf-8")


def test_cloudtrail_reader_loads_directory(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _write_fixture(logs_dir / "events.json")

    reader = CloudTrailReader(str(logs_dir))
    records = list(reader.load())

    assert len(records) == 8
    assert records[0]["eventName"] == "GetObject"


def test_cloudtrail_reader_supports_gzip(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    gz_path = logs_dir / "events.json.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        handle.write(_fixture_payload())

    reader = CloudTrailReader(str(logs_dir))
    records = list(reader.load())

    assert len(records) == 8


def test_cloudtrail_reader_respects_time_window(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _write_fixture(logs_dir / "events.json")

    reader = CloudTrailReader(str(logs_dir), start="2024-01-01T05:00:00Z")
    records = list(reader.load())
    assert len(records) == 3


def test_cloudtrail_reader_handles_s3(monkeypatch):
    payload = _fixture_payload()

    class DummyClient:
        def __init__(self):
            self.calls = []

        def get_paginator(self, name):
            assert name == "list_objects_v2"

            class Paginator:
                def paginate(self_inner, **kwargs):
                    yield {"Contents": [{"Key": "prefix/events.json"}]}

            return Paginator()

        def get_object(self, Bucket, Key):  # noqa: N802
            self.calls.append((Bucket, Key))
            return {"Body": DummyBody(payload.encode("utf-8"))}

    class DummyBody:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def read(self):
            return self.data

    monkeypatch.setattr("core.parser.cloudtrail_reader.boto3", type("B", (), {"client": lambda *_: DummyClient()})())

    reader = CloudTrailReader("s3://bucket/prefix")
    records = list(reader.load())
    assert len(records) == 8


def test_normalizer_builds_event_model(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    _write_fixture(logs_dir / "events.json")

    reader = CloudTrailReader(str(logs_dir))
    normalizer = EventNormalizer()

    events = list(normalizer.transform(reader.load()))
    assert len(events) == 8
    s3_event = events[0]
    assert s3_event.principal_arn.endswith("user/Alice")
    assert s3_event.aws_service == "s3"
    assert s3_event.action == "GetObject"
    assert any(e.principal_arn.endswith("role/AppRole") for e in events)


def test_normalizer_excludes_internal_events():
    raw_event = {
        "eventTime": "2024-01-01T00:00:00Z",
        "eventSource": "health.amazonaws.com",
        "eventName": "DescribeEvents",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "type": "AWSService",
            "arn": "arn:aws:iam::123456789012:role/ServiceRole",
        },
        "requestParameters": {},
        "responseElements": {},
        "resources": [],
    }

    normalizer = EventNormalizer(exclude_internal=True)
    assert list(normalizer.transform([raw_event])) == []
