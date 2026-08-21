"""Timestamp helpers."""

from datetime import UTC, datetime


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
