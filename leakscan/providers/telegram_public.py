"""Case-scoped public Telegram preview monitoring without attachment downloads."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from ..config import AppConfig
from ..models import SearchBatch, SearchResult
from .base import ProviderUnavailable, SearchProvider

TELEGRAM_PUBLIC_HOSTS = {"t.me", "telegram.me", "www.t.me", "www.telegram.me"}
TELEGRAM_ASSET_HOST_SUFFIXES = (".telegram-cdn.org", ".telesco.pe")


class TelegramPublicProvider(SearchProvider):
    """Read explicitly configured public channel previews and outgoing links."""

    name = "telegram_public"
    query_capabilities = frozenset({"filename", "identifier", "phrase", "intent", "url"})
    minimum_request_interval_seconds = 2.0

    def configure(self, config: AppConfig) -> None:
        super().configure(config)
        self.public_channels = list(dict.fromkeys(
            channel
            for value in config.case.public_channels
            if (channel := _public_preview_url(value))
        ))
        self.match_terms = list(dict.fromkeys(
            term.casefold()
            for term in [
                *config.case.item_ids,
                *config.case.filenames,
                *config.case.distinctive_phrases,
                *config.case.aliases,
                *config.case.translated_descriptors,
                *config.case.incident_terms,
            ]
            if term.strip()
        ))
        if not self.match_terms:
            self.match_terms = [
                term.casefold() for term in config.case.actor_aliases if term.strip()
            ]

    def available(self) -> tuple[bool, str]:
        if not getattr(self, "public_channels", []):
            return False, "requires case.public_channels"
        return True, ""

    def request_key(self, query: str) -> str:
        return "case-public-channels" if getattr(self, "public_channels", []) else ""

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        output: list[SearchResult] = []
        pages_fetched = 0
        complete = True
        seen_posts: set[str] = set()
        seen_links: set[str] = set()

        for channel_url in self.public_channels:
            page_url = channel_url
            for _ in range(self.max_result_pages_per_query):
                if not self.can_make_request():
                    complete = False
                    break
                response = await client.get(page_url, headers={"Accept": "text/html"})
                pages_fetched += 1
                if response.status_code == 404:
                    break
                if response.status_code in {401, 403, 429, 451}:
                    raise ProviderUnavailable(
                        f"HTTP {response.status_code}: public channel preview unavailable",
                        status_code=response.status_code,
                    )
                if response.status_code >= 500:
                    raise ProviderUnavailable(
                        f"HTTP {response.status_code}: Telegram preview service error",
                        status_code=response.status_code,
                    )
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                messages = soup.select(".tgme_widget_message[data-post]")
                if not messages:
                    break
                oldest_id: int | None = None
                for message in messages:
                    data_post = str(message.get("data-post", "")).strip()
                    match = re.search(r"/(\d+)$", data_post)
                    if match:
                        message_id = int(match.group(1))
                        oldest_id = message_id if oldest_id is None else min(oldest_id, message_id)
                    if not data_post or data_post in seen_posts:
                        continue
                    seen_posts.add(data_post)
                    text_node = message.select_one(".tgme_widget_message_text")
                    document_names = [
                        node.get_text(" ", strip=True)
                        for node in message.select(".tgme_widget_message_document_title")
                    ]
                    document_sizes = [
                        node.get_text(" ", strip=True)
                        for node in message.select(".tgme_widget_message_document_extra")
                    ]
                    message_text = text_node.get_text(" ", strip=True) if text_node else ""
                    searchable = " ".join([message_text, *document_names]).casefold()
                    if not searchable or not any(term in searchable for term in self.match_terms):
                        continue
                    post_url = f"https://t.me/{data_post}"
                    time_node = message.select_one("time[datetime]")
                    published = str(time_node.get("datetime", "")) if time_node else ""
                    record_metadata = {
                        "channel_preview": channel_url,
                        "post": data_post,
                        "message_text": message_text[:2000],
                        "document_names": document_names,
                        "document_sizes": document_sizes,
                        "attachment_bodies_read": 0,
                    }
                    output.append(SearchResult(
                        url=post_url,
                        title=document_names[0] if document_names else f"Public Telegram post {data_post}",
                        excerpt=message_text[:1000],
                        provider=self.name,
                        query=query,
                        published=published,
                        source_url=post_url,
                        record_id=data_post,
                        reference_kind="public_channel_post",
                        metadata=record_metadata,
                    ))
                    for anchor in message.select("a[href]"):
                        href = str(anchor.get("href", "")).strip()
                        if not _external_http_url(href) or href in seen_links:
                            continue
                        seen_links.add(href)
                        link_title = anchor.get_text(" ", strip=True)
                        if not link_title and document_names:
                            link_title = document_names[0]
                        output.append(SearchResult(
                            url=href,
                            title=link_title,
                            excerpt=message_text[:1000],
                            provider=self.name,
                            query=query,
                            published=published,
                            source_url=post_url,
                            record_id=data_post,
                            metadata={**record_metadata, "outgoing_link": href},
                        ))
                    if len(output) >= limit:
                        return SearchBatch(output[:limit], complete=complete, pages_fetched=pages_fetched)
                if oldest_id is None or oldest_id <= 1:
                    break
                next_url = f"{channel_url}?before={oldest_id}"
                if next_url == page_url:
                    break
                page_url = next_url
            if not complete:
                break
        return SearchBatch(output[:limit], complete=complete, pages_fetched=pages_fetched)


def _public_preview_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"https://t.me/{candidate.lstrip('@')}"
    parts = urlsplit(candidate)
    if (parts.hostname or "").casefold() not in TELEGRAM_PUBLIC_HOSTS:
        return ""
    segments = [segment for segment in parts.path.split("/") if segment]
    if segments and segments[0].casefold() == "s":
        segments = segments[1:]
    if not segments or not re.fullmatch(r"[A-Za-z0-9_]{4,64}", segments[0]):
        return ""
    return urlunsplit(("https", "t.me", f"/s/{segments[0]}", "", ""))


def _external_http_url(value: str) -> bool:
    parts = urlsplit(value)
    hostname = (parts.hostname or "").casefold()
    if parts.scheme not in {"http", "https"} or not hostname:
        return False
    return not (
        hostname in TELEGRAM_PUBLIC_HOSTS or hostname.endswith(TELEGRAM_ASSET_HOST_SUFFIXES)
    )
