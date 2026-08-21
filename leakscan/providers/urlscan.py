"""urlscan.io public search API provider."""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import unquote

import httpx

from ..models import SearchResult
from ..utils.urls import normalize_url
from .base import ProviderUnavailable, SearchProvider, is_probable_hash, query_anchor

URLSCAN_RESERVED = set(r'+-=><!(){}[]^"~*?:\\/')
LOG = logging.getLogger(__name__)


def escape_urlscan_query(value: str) -> str:
    """Escape Elasticsearch query-string reserved characters for a quoted literal."""
    return "".join(f"\\{character}" if character in URLSCAN_RESERVED else character for character in value)


class URLScanProvider(SearchProvider):
    name = "urlscan"
    query_capabilities = frozenset({"filename", "identifier", "url", "phrase"})

    def request_key(self, query: str) -> str:
        if is_probable_hash(query):
            return ""
        return query.replace('"', "").strip().casefold()

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        headers = {}
        api_key = os.getenv("URLSCAN_API_KEY", "").strip()
        if api_key:
            headers["api-key"] = api_key
        cleaned = " ".join(query.replace('"', "").split())
        escaped = escape_urlscan_query(cleaned)
        urlscan_query = (
            f'(page.url:"{escaped}" OR task.url:"{escaped}" '
            f'OR page.title:"{escaped}" OR filename:"{escaped}")'
        )
        data = await self.get_json(
            client, "https://urlscan.io/api/v1/search/",
            params={"q": urlscan_query, "size": min(limit, 100)}, headers=headers,
        )
        output: list[SearchResult] = []
        detail_output: list[SearchResult] = []
        detail_scans = 0
        detail_scan_limit = min(5, self.max_result_pages_per_query)
        for item in data.get("results", [])[:limit]:
            page = item.get("page", {})
            task = item.get("task", {})
            url = page.get("url") or task.get("url")
            if url:
                record_id = str(item.get("_id", ""))
                output.append(SearchResult(
                    url=url, title=page.get("title", ""),
                    excerpt=f"urlscan result {record_id}; domain {page.get('domain', '')}",
                    provider=self.name, query=query, published=task.get("time", ""),
                    source_url=f"https://urlscan.io/result/{record_id}/" if record_id else "",
                    record_id=record_id, metadata=item,
                ))
            if api_key and record_id and detail_scans < detail_scan_limit:
                detail_scans += 1
                try:
                    result_data = await self.get_json(
                        client,
                        f"https://urlscan.io/api/v1/result/{record_id}/",
                        headers=headers,
                    )
                except (ProviderUnavailable, httpx.HTTPError, ValueError) as exc:
                    LOG.warning("[URLSCAN-DETAIL] %s %s", record_id, exc)
                    continue
                detail_output.extend(self._request_metadata_results(
                    result_data, query, record_id, limit - len(detail_output)
                ))
        deduplicated: list[SearchResult] = []
        seen: set[str] = set()
        for result in [*detail_output, *output]:
            key = normalize_url(result.url)
            if not key or key in seen:
                continue
            seen.add(key)
            deduplicated.append(result)
            if len(deduplicated) >= limit:
                break
        return deduplicated

    def _request_metadata_results(
        self,
        payload: object,
        query: str,
        record_id: str,
        limit: int,
    ) -> list[SearchResult]:
        if not isinstance(payload, dict):
            return []
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        requests = data.get("requests") if isinstance(data, dict) else []
        if not isinstance(requests, list):
            return []
        anchor = query_anchor(query)
        output: list[SearchResult] = []
        for transaction in requests:
            if not isinstance(transaction, dict):
                continue
            request_wrapper = transaction.get("request")
            response_wrapper = transaction.get("response")
            request_record = (
                request_wrapper.get("request", {}) if isinstance(request_wrapper, dict) else {}
            )
            response_record = (
                response_wrapper.get("response", {}) if isinstance(response_wrapper, dict) else {}
            )
            request_url = str(request_record.get("url", ""))
            if not request_url:
                continue
            headers = _urlscan_headers(response_record.get("headers"))
            disposition = headers.get("content-disposition", "")
            disposition_name = _disposition_filename(disposition)
            if not _metadata_record_matches(request_url, disposition_name, anchor):
                continue
            status = response_record.get("status")
            mime_type = str(response_record.get("mimeType") or headers.get("content-type", ""))
            length_text = headers.get("content-length", "")
            size = int(length_text) if length_text.isdigit() else response_record.get("encodedDataLength")
            output.append(SearchResult(
                url=request_url,
                title=disposition_name or unquote(request_url.rsplit("/", 1)[-1]),
                excerpt=(
                    f"urlscan HTTP transaction; status {status}; MIME {mime_type}; "
                    f"size {size if size is not None else 'unknown'}"
                ),
                provider=self.name,
                query=query,
                published=str(payload.get("task", {}).get("time", ""))
                if isinstance(payload.get("task"), dict) else "",
                source_url=f"https://urlscan.io/result/{record_id}/",
                record_id=record_id,
                metadata={
                    "urlscan_request_url": request_url,
                    "status_code": status,
                    "mime_type": mime_type,
                    "content_disposition": disposition,
                    "filename": disposition_name,
                    "size": size,
                    "response_hash": response_record.get("hash", ""),
                    "response_body_bytes_read": 0,
                    "archive_body_bytes_read": 0,
                },
            ))
            if len(output) >= limit:
                break
        return output


def _urlscan_headers(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key).casefold(): str(item) for key, item in value.items()}
    if not isinstance(value, list):
        return {}
    output: dict[str, str] = {}
    for item in value:
        if isinstance(item, dict) and item.get("name"):
            output[str(item["name"]).casefold()] = str(item.get("value", ""))
    return output


def _disposition_filename(value: str) -> str:
    match = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", value, re.IGNORECASE)
    return unquote(match.group(1).strip()) if match else ""


def _metadata_record_matches(url: str, filename: str, anchor: str) -> bool:
    if not anchor:
        return False
    def normalize(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", unquote(value).casefold()).strip()
    needle = normalize(anchor)
    haystack = normalize(f"{url} {filename}")
    return bool(needle and needle in haystack)
