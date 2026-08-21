"""Search-provider registry."""

from __future__ import annotations

from .archive_org import ArchiveOrgProvider
from .base import SearchProvider
from .brave import BraveProvider
from .commoncrawl import CommonCrawlProvider
from .duckduckgo import DuckDuckGoProvider
from .github import GitHubProvider
from .search_apis import BingProvider, GitLabProvider, GoogleProvider, OTXProvider, VirusTotalProvider
from .urlscan import URLScanProvider


def build_providers() -> dict[str, SearchProvider]:
    instances: list[SearchProvider] = [
        DuckDuckGoProvider(), CommonCrawlProvider(), ArchiveOrgProvider(), URLScanProvider(),
        BraveProvider(), BingProvider(), GoogleProvider(), GitHubProvider(), GitLabProvider(),
        VirusTotalProvider(), OTXProvider(),
    ]
    return {provider.name: provider for provider in instances}


__all__ = ["SearchProvider", "build_providers"]
