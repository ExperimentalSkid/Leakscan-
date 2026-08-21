from __future__ import annotations

import httpx
import pytest

from leakscan.providers.telegram_public import TelegramPublicProvider


@pytest.mark.asyncio
async def test_public_telegram_preview_emits_post_and_outgoing_link_without_attachment_fetch(
    app_config,
) -> None:
    app_config.case.public_channels = ["https://t.me/s/ExampleChannel"]
    app_config.case.incident_terms = ["Example Dataset"]
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, text="""
            <div class="tgme_widget_message" data-post="ExampleChannel/52">
              <time datetime="2025-01-02T03:04:05Z"></time>
              <div class="tgme_widget_message_text">
                Example Dataset mirror
                <a href="https://mirror.example/item/abc123">mirror metadata</a>
              </div>
              <div class="tgme_widget_message_document_title">Example Dataset.7z</div>
              <div class="tgme_widget_message_document_extra">500 MB</div>
            </div>
        """, request=request)

    provider = TelegramPublicProvider()
    provider.configure(app_config)
    provider.max_result_pages_per_query = 1
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        batch = await provider.search(client, '"Example Dataset.7z"', 10)

    assert paths == ["/s/ExampleChannel"]
    assert {result.url for result in batch} == {
        "https://t.me/ExampleChannel/52",
        "https://mirror.example/item/abc123",
    }
    post = next(result for result in batch if result.url.startswith("https://t.me/"))
    mirror = next(result for result in batch if result.url.startswith("https://mirror.example/"))
    assert post.reference_kind == "public_channel_post"
    assert post.metadata["attachment_bodies_read"] == 0
    assert mirror.reference_kind == ""
    assert mirror.source_url == "https://t.me/ExampleChannel/52"


def test_public_telegram_provider_requires_explicit_case_channels(app_config) -> None:
    provider = TelegramPublicProvider()
    provider.configure(app_config)

    assert provider.available() == (False, "requires case.public_channels")
