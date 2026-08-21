"""Metadata-only adapters for public file-host object APIs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PIXELDRAIN_HOSTS = {
    "pixeldrain.com",
    "pixeldrain.net",
    "pixeldra.in",
    "pixeldrain.nl",
    "pixeldrain.biz",
    "pixeldrain.tech",
    "pixeldrain.dev",
}
PIXELDRAIN_OBJECT_PATH = re.compile(r"^/(?:u|api/file)/([A-Za-z0-9_-]{2,128})(?:/|$)")
PIXELDRAIN_METADATA_FIELDS = (
    "success",
    "id",
    "name",
    "size",
    "mime_type",
    "hash_sha256",
    "date_upload",
    "date_last_view",
    "availability",
    "availability_message",
    "abuse_type",
    "abuse_reporter_name",
    "can_download",
    "value",
    "message",
    "extra",
)
BITEBLOB_HOSTS = {"biteblob.com", "www.biteblob.com"}
BITEBLOB_INFORMATION_PATH = re.compile(r"^/Information/[^/?#]+/?$", re.IGNORECASE)
BITEBLOB_DOWNLOAD_PATH = re.compile(r"^/Download/[^/?#]+/?$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class HostVerificationRequest:
    provider: str
    object_id: str
    url: str


def host_verification_request(url: str) -> HostVerificationRequest | None:
    """Return a bounded public metadata endpoint for a recognized file-host URL."""
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower().removeprefix("www.")
    if hostname not in PIXELDRAIN_HOSTS:
        return None
    match = PIXELDRAIN_OBJECT_PATH.match(parts.path)
    if not match:
        return None
    object_id = match.group(1)
    netloc = parts.netloc
    endpoint = urlunsplit((parts.scheme, netloc, f"/api/file/{object_id}/info", "", ""))
    return HostVerificationRequest(provider="pixeldrain", object_id=object_id, url=endpoint)


def normalized_host_metadata(provider: str, payload: Any) -> dict[str, Any]:
    """Retain stable evidentiary fields and discard unrelated account/UI data."""
    if provider != "pixeldrain" or not isinstance(payload, dict):
        return {}
    return {key: payload[key] for key in PIXELDRAIN_METADATA_FIELDS if key in payload}


def host_metadata_classification(provider: str, status_code: int | None, metadata: dict[str, Any]) -> str:
    """Classify host-native metadata without treating access controls as proof of deletion."""
    if status_code in {404, 410}:
        return "DEAD"
    if status_code == 451:
        return "TAKEN_DOWN"
    if status_code is None or status_code >= 500:
        return "UNKNOWN"
    if status_code in {401, 403, 429}:
        return "BLOCKED"
    if provider == "pixeldrain" and status_code == 200 and metadata.get("success") is True:
        availability = str(metadata.get("availability", "")).strip()
        abuse_type = str(metadata.get("abuse_type", "")).strip()
        if availability == "unavailable_for_legal_reasons" or (
            abuse_type and metadata.get("can_download") is False
        ):
            return "TAKEN_DOWN"
        if availability or metadata.get("can_download") is False:
            return "LIVE_RESTRICTED"
        return "CONFIRMED_METADATA_ONLY"
    return "UNKNOWN"


def reference_route_classification(url: str, status_code: int | None, content_type: str) -> str:
    """Classify responsive host routes without implying that an archive payload is live."""
    if status_code is None or not 200 <= status_code < 400 or "html" not in content_type.casefold():
        return ""
    parts = urlsplit(url)
    hostname = (parts.hostname or "").casefold()
    if hostname not in BITEBLOB_HOSTS:
        return ""
    if BITEBLOB_INFORMATION_PATH.match(parts.path):
        return "LISTING_LIVE"
    if BITEBLOB_DOWNLOAD_PATH.match(parts.path):
        return "DOWNLOAD_ROUTE_LIVE"
    return ""
