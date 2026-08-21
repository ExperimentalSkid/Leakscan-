"""Bounded HTTP retrieval with redirect validation and binary-download prevention."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from time import monotonic
from typing import Self
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from .config import AppConfig
from .host_verifiers import host_verification_request, normalized_host_metadata
from .models import FetchResult
from .utils.urls import (
    bytes_look_binary,
    content_headers_indicate_binary,
    looks_like_archive_url,
    normalize_url,
    safe_url,
)

LOG = logging.getLogger(__name__)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
ROBOTS_CACHE_SECONDS = 24 * 60 * 60
ROBOTS_MAX_BYTES = 512_000
HOST_METADATA_MAX_BYTES = 128 * 1024


@dataclass(slots=True)
class RobotsPolicy:
    mode: str
    fetched_at: float
    parser: RobotFileParser | None = None
    reason: str = ""


class SafeHTTPClient:
    def __init__(self, config: AppConfig):
        self.config = config
        self.rate_limiter = HostRateLimiter(config.crawl.per_host_delay_seconds)
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.crawl.timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": config.crawl.user_agent, "Accept": "text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1"},
            http2=True,
            event_hooks={"request": [self.rate_limiter.on_request]},
        )
        self._robots: dict[str, RobotsPolicy] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.client.aclose()

    async def _allowed(self, url: str) -> tuple[bool, str]:
        ok, reason = await asyncio.to_thread(
            safe_url,
            url,
            self.config.safety.allowed_schemes,
            self.config.safety.reject_private_networks,
        )
        if not ok:
            return False, reason
        if not self.config.crawl.respect_robots_txt:
            return True, ""
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        cached = self._robots.get(origin)
        if cached is None or monotonic() - cached.fetched_at >= ROBOTS_CACHE_SECONDS:
            self._robots[origin] = await self._load_robots(origin)
        policy = self._robots[origin]
        if policy.mode == "disallow":
            return False, policy.reason or "robots.txt is unreachable"
        if policy.parser is not None and not policy.parser.can_fetch(self.config.crawl.user_agent, url):
            return False, "robots.txt disallows this URL"
        return True, ""

    async def _load_robots(self, origin: str) -> RobotsPolicy:
        initial_url = origin + "/robots.txt"
        current = initial_url
        try:
            for _ in range(6):
                ok, reason = await asyncio.to_thread(
                    safe_url,
                    current,
                    self.config.safety.allowed_schemes,
                    self.config.safety.reject_private_networks,
                )
                if not ok:
                    return RobotsPolicy("disallow", monotonic(), reason=reason)
                request = self.client.build_request(
                    "GET", current, headers={"Range": f"bytes=0-{ROBOTS_MAX_BYTES - 1}"}
                )
                response = await self.client.send(request, stream=True)
                try:
                    if response.status_code in REDIRECT_STATUSES and response.headers.get("location"):
                        destination = normalize_url(urljoin(str(response.url), response.headers["location"]))
                        if not destination:
                            return RobotsPolicy("disallow", monotonic(), reason="invalid robots.txt redirect")
                        current = destination
                        continue
                    if response.status_code == 429 or response.status_code >= 500:
                        return RobotsPolicy(
                            "disallow",
                            monotonic(),
                            reason=f"robots.txt unreachable (HTTP {response.status_code})",
                        )
                    if 400 <= response.status_code < 500:
                        return RobotsPolicy("allow", monotonic())
                    if response.status_code not in {200, 206}:
                        return RobotsPolicy(
                            "disallow",
                            monotonic(),
                            reason=f"unexpected robots.txt status HTTP {response.status_code}",
                        )
                    data = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        remaining = ROBOTS_MAX_BYTES - len(data)
                        if remaining <= 0:
                            break
                        data.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            break
                finally:
                    await response.aclose()
                parser = RobotFileParser()
                parser.set_url(initial_url)
                parser.parse(bytes(data).decode("utf-8", errors="replace").splitlines())
                return RobotsPolicy("rules", monotonic(), parser=parser)
            return RobotsPolicy("disallow", monotonic(), reason="too many robots.txt redirects")
        except (httpx.HTTPError, OSError) as exc:
            return RobotsPolicy("disallow", monotonic(), reason=f"robots.txt unreachable: {type(exc).__name__}")

    async def _headers_only(self, url: str, method: str) -> FetchResult:
        result = FetchResult(original_url=url)
        current = url
        for _ in range(self.config.crawl.max_redirects + 1):
            allowed, reason = await self._allowed(current)
            if not allowed:
                result.final_url = current
                result.blocked_reason = reason
                return result
            headers = {"Range": "bytes=0-0"} if method == "GET" else {}
            request = self.client.build_request(method, current, headers=headers)
            response = await self.client.send(request, stream=True)
            try:
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                result.status_code = response.status_code
                result.headers = response_headers
                result.final_url = str(response.url)
                if response.status_code in REDIRECT_STATUSES and response.headers.get("location"):
                    destination = normalize_url(urljoin(str(response.url), response.headers["location"]))
                    result.redirect_chain.append({
                        "status_code": response.status_code,
                        "url": str(response.url),
                        "location": destination,
                    })
                    if not destination:
                        result.error = "invalid redirect destination"
                        return result
                    current = destination
                    continue
                result.is_binary = (
                    looks_like_archive_url(result.final_url, self.config.safety.archive_extensions)
                    or content_headers_indicate_binary(response_headers, self.config.safety.archive_extensions)
                )
                result.verification_point = {
                    "method": "http_head" if method == "HEAD" else "http_range",
                    "endpoint": result.final_url,
                }
                return result
            finally:
                # No response bytes are consumed for metadata-only probes.
                await response.aclose()
        result.error = "maximum redirect count exceeded"
        return result

    async def probe_metadata(self, url: str) -> FetchResult:
        """Return headers/redirects without consuming the response body."""
        host_request = host_verification_request(url)
        for attempt in range(self.config.crawl.retry_count + 1):
            try:
                if host_request is not None:
                    return await self._probe_host_metadata(url, host_request)
                result = await self._headers_only(url, "HEAD")
                if result.status_code not in {405, 501}:
                    return result
                return await self._headers_only(url, "GET")
            except (httpx.HTTPError, OSError) as exc:
                if attempt >= self.config.crawl.retry_count:
                    return FetchResult(original_url=url, final_url=url, error=f"{type(exc).__name__}: {exc}")
                await asyncio.sleep(self.config.crawl.retry_backoff_seconds * (2**attempt))
        return FetchResult(original_url=url, final_url=url, error="unreachable")

    async def _probe_host_metadata(self, url: str, host_request) -> FetchResult:
        result = FetchResult(original_url=url, final_url=url)
        current = host_request.url
        for _ in range(self.config.crawl.max_redirects + 1):
            allowed, reason = await self._allowed(current)
            if not allowed:
                result.blocked_reason = reason
                result.verification_point = {
                    "method": f"{host_request.provider}_api",
                    "endpoint": current,
                    "object_id": host_request.object_id,
                }
                return result
            request = self.client.build_request("GET", current, headers={"Accept": "application/json"})
            response = await self.client.send(request, stream=True)
            try:
                result.status_code = response.status_code
                result.headers = {key.lower(): value for key, value in response.headers.items()}
                if response.status_code in REDIRECT_STATUSES and response.headers.get("location"):
                    destination = normalize_url(urljoin(str(response.url), response.headers["location"]))
                    result.redirect_chain.append({
                        "status_code": response.status_code,
                        "url": str(response.url),
                        "location": destination,
                    })
                    if not destination:
                        result.error = "invalid host metadata redirect"
                        return result
                    current = destination
                    continue
                data = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    remaining = HOST_METADATA_MAX_BYTES - len(data)
                    if remaining <= 0:
                        result.truncated = True
                        break
                    data.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        result.truncated = True
                        break
            finally:
                await response.aclose()
            payload = {}
            if data:
                try:
                    payload = json.loads(bytes(data))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    if response.status_code < 400:
                        result.error = "host metadata endpoint returned invalid JSON"
            metadata = normalized_host_metadata(host_request.provider, payload)
            result.verification_point = {
                "method": f"{host_request.provider}_api",
                "endpoint": str(response.url),
                "object_id": host_request.object_id,
                "metadata_body_bytes_read": len(data),
                "metadata": metadata,
            }
            return result
        result.error = "maximum host metadata redirect count exceeded"
        return result

    async def fetch_page(self, url: str) -> FetchResult:
        if looks_like_archive_url(url, self.config.safety.archive_extensions):
            return await self.probe_metadata(url)
        for attempt in range(self.config.crawl.retry_count + 1):
            try:
                return await self._fetch_page_once(url)
            except (httpx.HTTPError, OSError) as exc:
                if attempt >= self.config.crawl.retry_count:
                    return FetchResult(original_url=url, final_url=url, error=f"{type(exc).__name__}: {exc}")
                await asyncio.sleep(self.config.crawl.retry_backoff_seconds * (2**attempt))
        return FetchResult(original_url=url, final_url=url, error="unreachable")

    async def _fetch_page_once(self, url: str) -> FetchResult:
        result = FetchResult(original_url=url)
        current = url
        for _ in range(self.config.crawl.max_redirects + 1):
            allowed, reason = await self._allowed(current)
            if not allowed:
                result.final_url = current
                result.blocked_reason = reason
                return result
            request = self.client.build_request("GET", current)
            response = await self.client.send(request, stream=True)
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            result.status_code = response.status_code
            result.headers = response_headers
            result.final_url = str(response.url)
            if response.status_code in REDIRECT_STATUSES and response.headers.get("location"):
                destination = normalize_url(urljoin(str(response.url), response.headers["location"]))
                result.redirect_chain.append({
                    "status_code": response.status_code, "url": str(response.url), "location": destination,
                })
                await response.aclose()
                if not destination:
                    result.error = "invalid redirect destination"
                    return result
                if looks_like_archive_url(destination, self.config.safety.archive_extensions):
                    probe = await self.probe_metadata(destination)
                    probe.original_url = url
                    probe.redirect_chain = [*result.redirect_chain, *probe.redirect_chain]
                    return probe
                current = destination
                continue
            if content_headers_indicate_binary(response_headers, self.config.safety.archive_extensions):
                result.is_binary = True
                await response.aclose()
                return result
            declared = response_headers.get("content-length", "")
            if declared.isdigit() and int(declared) > self.config.crawl.max_html_bytes:
                result.truncated = True
                result.error = f"declared response exceeds max_html_bytes ({declared})"
                await response.aclose()
                return result
            data = bytearray()
            try:
                async for chunk in response.aiter_bytes(chunk_size=16384):
                    if not data and bytes_look_binary(chunk):
                        result.is_binary = True
                        break
                    remaining = self.config.crawl.max_html_bytes - len(data)
                    if remaining <= 0:
                        result.truncated = True
                        break
                    data.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        result.truncated = True
                        break
            finally:
                await response.aclose()
            result.body = bytes(data) if not result.is_binary else b""
            return result
        result.error = "maximum redirect count exceeded"
        return result


class HostRateLimiter:
    """Serialize requests per host and enforce a minimum start-to-start delay."""

    def __init__(self, delay_seconds: float) -> None:
        self.delay_seconds = max(0.0, delay_seconds)
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request: dict[str, float] = defaultdict(float)

    async def wait(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            return
        async with self._host_locks[host]:
            wait = self.delay_seconds - (monotonic() - self._last_request[host])
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request[host] = monotonic()

    async def on_request(self, request: httpx.Request) -> None:
        await self.wait(str(request.url))
