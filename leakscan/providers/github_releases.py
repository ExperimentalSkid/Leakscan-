"""GitHub release-asset metadata search; asset bodies are never requested."""

from __future__ import annotations

import os
import re

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, metadata_name_matches, query_anchor, strip_archive_suffix


class GitHubReleasesProvider(SearchProvider):
    name = "github_releases"
    api_key_env = "GITHUB_TOKEN"
    query_capabilities = frozenset({"filename", "identifier", "phrase"})
    repositories_per_page = 5

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        output: list[SearchResult] = []
        pages_fetched = 0
        page_size = min(limit, 20)
        anchor = strip_archive_suffix(query_anchor(query), self.archive_extensions).strip()
        if len(anchor) < 3:
            return SearchBatch()
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://api.github.com/search/repositories",
                params={
                    "q": f"{anchor} in:name,description,readme",
                    "per_page": page_size,
                    "page": page,
                },
                headers=headers,
            )
            pages_fetched += 1
            repositories = data.get("items", [])
            for repository in repositories[:self.repositories_per_page]:
                full_name = str(repository.get("full_name") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
                    continue
                if not self.can_make_request():
                    return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
                releases = await self.get_json(
                    client,
                    f"https://api.github.com/repos/{full_name}/releases",
                    params={"per_page": 100},
                    headers=headers,
                )
                for release in releases if isinstance(releases, list) else []:
                    release_url = str(release.get("html_url") or repository.get("html_url") or "")
                    for asset in release.get("assets", []):
                        filename = str(asset.get("name") or "")
                        if not metadata_name_matches(filename, query):
                            continue
                        asset_url = str(asset.get("browser_download_url") or "")
                        if not asset_url:
                            continue
                        output.append(SearchResult(
                            url=asset_url,
                            title=filename,
                            excerpt=f"GitHub release asset in {full_name}; size {asset.get('size', '')}",
                            provider=self.name,
                            query=query,
                            published=str(release.get("published_at") or release.get("created_at") or ""),
                            source_url=release_url,
                            record_id=str(asset.get("id") or f"{full_name}:{filename}"),
                            metadata={
                                "catalog": "github_releases",
                                "repository": full_name,
                                "release_id": release.get("id"),
                                "release_tag": release.get("tag_name"),
                                "release_url": release_url,
                                "asset_id": asset.get("id"),
                                "file_name": filename,
                                "file_size": asset.get("size"),
                                "content_type": asset.get("content_type"),
                                "digest": asset.get("digest"),
                                "download_count": asset.get("download_count"),
                            },
                        ))
            if len(repositories) < page_size:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
