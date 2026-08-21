"""Bounded HTTP retrieval with redirect validation and binary-download prevention."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from time import monotonic
from typing import Self
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from .config import AppConfig
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


class SafeHTTPClient:
    def __init__(self, config: AppConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.crawl.timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": config.crawl.user_agent, "Accept": "text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1"},
            http2=True,
        )
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request: dict[str, float] = defaultdict(float)
        self._robots: dict[str, RobotFileParser | None] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.client.aclose()

    async def _rate_limit(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        async with self._host_locks[host]:
            wait = self.config.crawl.per_host_delay_seconds - (monotonic() - self._last_request[host])
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request[host] = monotonic()

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
        if origin not in self._robots:
            self._robots[origin] = await self._load_robots(origin)
        parser = self._robots[origin]
        if parser is not None and not parser.can_fetch(self.config.crawl.user_agent, url):
            return False, "robots.txt disallows this URL"
        return True, ""

    async def _load_robots(self, origin: str) -> RobotFileParser | None:
        robots_url = origin + "/robots.txt"
        try:
            ok, _ = await asyncio.to_thread(
                safe_url, robots_url, self.config.safety.allowed_schemes,
                self.config.safety.reject_private_networks,
            )
            if not ok:
                return None
            await self._rate_limit(robots_url)
            request = self.client.build_request("GET", robots_url, headers={"Range": "bytes=0-65535"})
            response = await self.client.send(request, stream=True)
            try:
                if response.status_code not in {200, 206}:
                    return None
                data = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    data.extend(chunk)
                    if len(data) >= 65536:
                        break
            finally:
                await response.aclose()
            parser = RobotFileParser()
            parser.set_url(robots_url)
            parser.parse(bytes(data).decode("utf-8", errors="replace").splitlines())
            return parser
        except (httpx.HTTPError, OSError):
            return None

    async def _headers_only(self, url: str, method: str) -> FetchResult:
        result = FetchResult(original_url=url)
        current = url
        for _ in range(self.config.crawl.max_redirects + 1):
            allowed, reason = await self._allowed(current)
            if not allowed:
                result.final_url = current
                result.blocked_reason = reason
                return result
            await self._rate_limit(current)
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
                return result
            finally:
                # No response bytes are consumed for metadata-only probes.
                await response.aclose()
        result.error = "maximum redirect count exceeded"
        return result

    async def probe_metadata(self, url: str) -> FetchResult:
        """Return headers/redirects without consuming the response body."""
        for attempt in range(self.config.crawl.retry_count + 1):
            try:
                result = await self._headers_only(url, "HEAD")
                if result.status_code not in {405, 501}:
                    return result
                return await self._headers_only(url, "GET")
            except (httpx.HTTPError, OSError) as exc:
                if attempt >= self.config.crawl.retry_count:
                    return FetchResult(original_url=url, final_url=url, error=f"{type(exc).__name__}: {exc}")
                await asyncio.sleep(self.config.crawl.retry_backoff_seconds * (2**attempt))
        return FetchResult(original_url=url, final_url=url, error="unreachable")

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
            await self._rate_limit(current)
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
