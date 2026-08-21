"""Search-provider registry."""

from __future__ import annotations

from .archive_org import ArchiveOrgProvider
from .archive_org_files import ArchiveOrgFilesProvider
from .archive_org_items import ArchiveOrgItemsProvider
from .arquivo_pt import ArquivoPtProvider
from .base import SearchProvider
from .commoncrawl import CommonCrawlProvider
from .duckduckgo import DuckDuckGoProvider
from .gdelt import GDELTProvider
from .github import GitHubProvider
from .github_releases import GitHubReleasesProvider
from .gitlab_assets import GitLabAssetsProvider
from .huggingface import HuggingFaceProvider
from .hybrid_analysis import HybridAnalysisProvider
from .kaggle import KaggleProvider
from .leakix import LeakIXProvider
from .mojeek import MojeekProvider
from .search_apis import BingProvider, GitLabProvider, GoogleProvider, OTXProvider, VirusTotalProvider
from .searxng import SearXNGProvider
from .telegram_public import TelegramPublicProvider
from .urlscan import URLScanProvider


def build_providers() -> dict[str, SearchProvider]:
    instances: list[SearchProvider] = [
        DuckDuckGoProvider(), CommonCrawlProvider(), ArchiveOrgProvider(), ArchiveOrgItemsProvider(),
        ArchiveOrgFilesProvider(), ArquivoPtProvider(), GDELTProvider(), URLScanProvider(),
        TelegramPublicProvider(), BingProvider(), GoogleProvider(), MojeekProvider(), SearXNGProvider(),
        GitHubProvider(), GitHubReleasesProvider(), GitLabProvider(), GitLabAssetsProvider(),
        HuggingFaceProvider(), KaggleProvider(), HybridAnalysisProvider(), LeakIXProvider(),
        VirusTotalProvider(), OTXProvider(),
    ]
    return {provider.name: provider for provider in instances}


__all__ = ["SearchProvider", "build_providers"]
