"""Hugging Face Hub repository and file metadata search; no resolver downloads."""

from __future__ import annotations

import os
import re
from urllib.parse import quote, urlsplit

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, metadata_name_matches, query_anchor


class HuggingFaceProvider(SearchProvider):
    name = "huggingface"
    query_capabilities = frozenset({"filename", "identifier", "phrase"})
    repository_types = ("datasets", "models", "spaces")

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = {"Accept": "application/json"}
        if os.getenv("HF_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['HF_TOKEN']}"
        output: list[SearchResult] = []
        requests_fetched = 0
        search_term = query_anchor(query)
        for repository_type in self.repository_types:
            next_url = f"https://huggingface.co/api/{repository_type}"
            params: dict[str, str | int] | None = {
                "search": search_term,
                "limit": min(limit, 50),
                "full": "true",
            }
            for _page in range(self.max_result_pages_per_query):
                if not self.can_make_request():
                    return SearchBatch(output, complete=False, pages_fetched=requests_fetched)
                response = await client.get(next_url, params=params, headers=headers)
                data = self._response_json(response)
                requests_fetched += 1
                for repository in data if isinstance(data, list) else []:
                    self._append_repository(output, repository_type, repository, query)
                next_url = str(response.links.get("next", {}).get("url") or "")
                next_parts = urlsplit(next_url)
                if (
                    not next_url
                    or next_parts.scheme != "https"
                    or next_parts.hostname != "huggingface.co"
                ):
                    break
                params = None
        return SearchBatch(output, pages_fetched=requests_fetched)

    def _append_repository(
        self,
        output: list[SearchResult],
        repository_type: str,
        repository: dict,
        query: str,
    ) -> None:
        repository_id = str(repository.get("id") or repository.get("modelId") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", repository_id):
            return
        repository_url = self._repository_url(repository_type, repository_id)
        revision = str(repository.get("sha") or "main")
        matching_files = [
            sibling for sibling in repository.get("siblings", [])
            if metadata_name_matches(str(sibling.get("rfilename", "")), query)
        ]
        for sibling in matching_files:
            filename = str(sibling.get("rfilename", ""))
            file_url = (
                f"{repository_url}/blob/{quote(revision, safe='')}/"
                f"{quote(filename, safe='/')}"
            )
            output.append(SearchResult(
                url=file_url,
                title=filename,
                excerpt=f"Hugging Face {repository_type[:-1]} file in {repository_id}",
                provider=self.name,
                query=query,
                published=str(repository.get("lastModified") or repository.get("createdAt") or ""),
                source_url=repository_url,
                record_id=f"{repository_type}:{repository_id}:{filename}",
                metadata={
                    "catalog": "huggingface",
                    "repository_type": repository_type[:-1],
                    "repository_id": repository_id,
                    "revision": revision,
                    "file_name": filename,
                    "file_size": sibling.get("size"),
                    "blob_id": sibling.get("blobId"),
                    "lfs": sibling.get("lfs"),
                    "repository_url": repository_url,
                },
            ))
        if not matching_files and metadata_name_matches(repository_id, query):
            output.append(SearchResult(
                url=repository_url,
                title=repository_id,
                excerpt=f"Hugging Face {repository_type[:-1]} repository metadata match",
                provider=self.name,
                query=query,
                published=str(repository.get("lastModified") or repository.get("createdAt") or ""),
                source_url=repository_url,
                record_id=f"{repository_type}:{repository_id}",
                reference_kind="repository_record",
                metadata={
                    "catalog": "huggingface",
                    "repository_type": repository_type[:-1],
                    "repository_id": repository_id,
                    "revision": revision,
                    "repository_url": repository_url,
                },
            ))

    @staticmethod
    def _repository_url(repository_type: str, repository_id: str) -> str:
        prefix = "" if repository_type == "models" else f"/{repository_type}"
        return f"https://huggingface.co{prefix}/{quote(repository_id, safe='/')}"
