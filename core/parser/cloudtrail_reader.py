"""Utilities for loading CloudTrail logs from S3 or the local filesystem."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

import boto3


def _coerce_datetime(value: datetime | str | None) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _parse_event_time(event: dict[str, Any]) -> Optional[datetime]:
    raw_time = event.get("eventTime")
    if raw_time is None:
        return None
    if isinstance(raw_time, datetime):
        return raw_time
    return _coerce_datetime(str(raw_time))


def _iter_records(payload: str) -> Iterator[dict[str, Any]]:
    stripped = payload.strip()
    if not stripped:
        return
    if stripped.startswith("{"):
        data = json.loads(stripped)
        if isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                for record in data["Records"]:
                    if isinstance(record, dict):
                        yield record
                return
            yield data
            return
    if stripped.startswith("["):
        data = json.loads(stripped)
        for record in data:
            if isinstance(record, dict):
                yield record
        return
    for line in stripped.splitlines():
        if line.strip():
            record = json.loads(line)
            if isinstance(record, dict):
                yield record


@dataclass(slots=True)
class CloudTrailReader:
    """Load CloudTrail events from local directories/files or S3 prefixes."""

    source: str
    start: datetime | str | None = None
    end: datetime | str | None = None
    s3_client: Any | None = None

    _start_dt: Optional[datetime] = field(init=False, default=None)
    _end_dt: Optional[datetime] = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._start_dt = _coerce_datetime(self.start)
        self._end_dt = _coerce_datetime(self.end)
        if self._start_dt and self._end_dt and self._start_dt > self._end_dt:
            raise ValueError("start must be earlier than end")

    def load(self) -> Iterator[dict[str, Any]]:
        """Yield CloudTrail events from the configured source."""
        if self.source.startswith("s3://"):
            yield from self._load_from_s3()
        else:
            yield from self._load_from_path(Path(self.source))

    # Local file handling -------------------------------------------------
    def _load_from_path(self, path: Path) -> Iterator[dict[str, Any]]:
        if not path.exists():
            raise FileNotFoundError(path)
        if path.is_file():
            yield from self._load_file(path)
            return
        files = sorted(
            p
            for p in path.rglob("*")
            if p.is_file() and (p.suffix == ".json" or p.name.endswith(".json.gz"))
        )
        for file_path in files:
            yield from self._load_file(file_path)

    def _load_file(self, path: Path) -> Iterator[dict[str, Any]]:
        open_fn = gzip.open if path.suffix == ".gz" else open
        mode = "rt" if path.suffix == ".gz" else "r"
        with open_fn(path, mode, encoding="utf-8") as handle:  # type: ignore[arg-type]
            payload = handle.read()
        for record in self._filter_by_time(_iter_records(payload)):
            yield record

    # S3 handling ---------------------------------------------------------
    def _load_from_s3(self) -> Iterator[dict[str, Any]]:
        bucket, prefix = self._parse_s3_url(self.source)
        client = self.s3_client or boto3.client("s3")
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
                payload = body.decode("utf-8") if not key.endswith(".gz") else gzip.decompress(body).decode("utf-8")
                for record in self._filter_by_time(_iter_records(payload)):
                    yield record

    @staticmethod
    def _parse_s3_url(url: str) -> tuple[str, str]:
        _, _, rest = url.partition("s3://")
        bucket, _, key = rest.partition("/")
        if not bucket:
            raise ValueError("S3 URL must include a bucket name.")
        return bucket, key

    # Helpers --------------------------------------------------------------
    def _filter_by_time(self, records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for record in records:
            event_time = _parse_event_time(record)
            if self._start_dt and event_time and event_time < self._start_dt:
                continue
            if self._end_dt and event_time and event_time > self._end_dt:
                continue
            yield record
