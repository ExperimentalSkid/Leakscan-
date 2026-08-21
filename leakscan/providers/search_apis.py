"""Commercial and public intelligence search APIs."""

from __future__ import annotations

import os

import httpx

from ..models import SearchResult
from .base import SearchProvider, is_probable_hash


class BingProvider(SearchProvider):
    name = "bing"
    api_key_env = "BING_API_KEY"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        endpoint = os.getenv("BING_SEARCH_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search")
        data = await self.get_json(
            client, endpoint, params={"q": query, "count": min(limit, 50), "responseFilter": "Webpages"},
            headers={"Ocp-Apim-Subscription-Key": os.environ["BING_API_KEY"]},
        )
        return [
            SearchResult(url=item.get("url", ""), title=item.get("name", ""), excerpt=item.get("snippet", ""),
                         provider=self.name, query=query, published=item.get("dateLastCrawled", ""), metadata=item)
            for item in data.get("webPages", {}).get("value", [])[:limit] if item.get("url")
        ]


class GoogleProvider(SearchProvider):
    name = "google"

    def available(self) -> tuple[bool, str]:
        missing = [name for name in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID") if not os.getenv(name)]
        return (not missing, f"requires {', '.join(missing)}" if missing else "")

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        output = []
        for start in range(1, min(limit, 100) + 1, 10):
            data = await self.get_json(client, "https://www.googleapis.com/customsearch/v1", params={
                "key": os.environ["GOOGLE_API_KEY"], "cx": os.environ["GOOGLE_CSE_ID"],
                "q": query, "start": start, "num": min(10, limit - len(output)), "safe": self.safe_search,
            })
            for item in data.get("items", []):
                output.append(SearchResult(
                    url=item.get("link", ""), title=item.get("title", ""), excerpt=item.get("snippet", ""),
                    provider=self.name, query=query, metadata=item,
                ))
            if len(output) >= limit or not data.get("queries", {}).get("nextPage"):
                break
        return output[:limit]


class GitLabProvider(SearchProvider):
    name = "gitlab"
    api_key_env = "GITLAB_TOKEN"

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        cleaned = query.replace('"', "").strip()
        data = await self.get_json(
            client, "https://gitlab.com/api/v4/search",
            params={"scope": "blobs", "search": cleaned, "per_page": min(limit, 100)},
            headers={"PRIVATE-TOKEN": os.environ["GITLAB_TOKEN"]},
        )
        return [
            SearchResult(url=item.get("url", ""), title=item.get("filename", ""), excerpt=item.get("data", "")[:500],
                         provider=self.name, query=query, metadata=item)
            for item in data[:limit] if item.get("url")
        ]


class VirusTotalProvider(SearchProvider):
    name = "virustotal"
    api_key_env = "VIRUSTOTAL_API_KEY"

    def request_key(self, query: str) -> str:
        return is_probable_hash(query)

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        digest = is_probable_hash(query)
        if not digest:
            return []
        data = await self.get_json(
            client, f"https://www.virustotal.com/api/v3/files/{digest}",
            headers={"x-apikey": os.environ["VIRUSTOTAL_API_KEY"]},
        )
        attributes = data.get("data", {}).get("attributes", {})
        output = []
        for name in attributes.get("names", [])[:limit]:
            output.append(SearchResult(
                url=f"https://www.virustotal.com/gui/file/{digest}", title=name,
                excerpt=f"VirusTotal public intelligence for {digest}", provider=self.name,
                query=query, metadata={"hash": digest, "name": name},
            ))
        return output


class OTXProvider(SearchProvider):
    name = "otx"

    def request_key(self, query: str) -> str:
        return is_probable_hash(query)

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        digest = is_probable_hash(query)
        if not digest:
            return []
        headers = {"X-OTX-API-KEY": os.environ["OTX_API_KEY"]} if os.getenv("OTX_API_KEY") else {}
        data = await self.get_json(
            client, f"https://otx.alienvault.com/api/v1/indicators/file/{digest}/general", headers=headers
        )
        return [
            SearchResult(
                url=f"https://otx.alienvault.com/indicator/file/{digest}",
                title=pulse.get("name", "OTX pulse"), excerpt=pulse.get("description", "")[:500],
                provider=self.name, query=query, published=pulse.get("created", ""), metadata=pulse,
            )
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:limit]
        ]
