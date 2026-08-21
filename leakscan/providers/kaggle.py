"""Kaggle public dataset and file-list metadata search; never downloads datasets."""

from __future__ import annotations

import base64
import os
import re
from urllib.parse import urlencode

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, metadata_name_matches, query_anchor


class KaggleProvider(SearchProvider):
    name = "kaggle"
    query_capabilities = frozenset({"filename", "identifier", "phrase"})
    manifest_datasets_per_page = 5

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        headers = self._headers()
        output: list[SearchResult] = []
        pages_fetched = 0
        page_size = min(limit, 20)
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://www.kaggle.com/api/v1/datasets/list",
                params={
                    "group": "public",
                    "sortBy": "lastUpdated",
                    "search": query_anchor(query),
                    "page": page,
                    "pageSize": page_size,
                },
                headers=headers,
            )
            pages_fetched += 1
            datasets = self._dataset_rows(data)
            for dataset in datasets[:self.manifest_datasets_per_page]:
                dataset_ref = self._dataset_ref(dataset)
                if not dataset_ref:
                    continue
                dataset_url = f"https://www.kaggle.com/datasets/{dataset_ref}"
                files = dataset.get("datasetFiles") or dataset.get("files") or []
                metadata_url = f"https://www.kaggle.com/api/v1/datasets/list/{dataset_ref}"
                if not files:
                    if not self.can_make_request():
                        return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
                    manifest = await self.get_json(
                        client,
                        metadata_url,
                        params={"pageSize": 100},
                        headers=headers,
                    )
                    files = manifest.get("datasetFiles") or manifest.get("files") or []
                matching_files = [
                    item for item in files
                    if metadata_name_matches(str(item.get("name") or item.get("fileName") or ""), query)
                ]
                for item in matching_files:
                    filename = str(item.get("name") or item.get("fileName") or "")
                    select_query = urlencode({"select": filename})
                    output.append(SearchResult(
                        url=f"{dataset_url}?{select_query}",
                        title=filename,
                        excerpt=f"Kaggle dataset file in {dataset_ref}; size {item.get('totalBytes', item.get('size', ''))}",
                        provider=self.name,
                        query=query,
                        published=str(dataset.get("lastUpdated") or dataset.get("updated") or ""),
                        source_url=metadata_url,
                        record_id=f"{dataset_ref}:{filename}",
                        metadata={
                            "catalog": "kaggle",
                            "dataset_ref": dataset_ref,
                            "dataset_title": dataset.get("title"),
                            "file_name": filename,
                            "file_size": item.get("totalBytes", item.get("size")),
                            "creation_date": item.get("creationDate"),
                            "dataset_url": dataset_url,
                            "metadata_url": metadata_url,
                        },
                    ))
                title = str(dataset.get("title") or dataset_ref)
                if not matching_files and metadata_name_matches(f"{dataset_ref} {title}", query):
                    output.append(SearchResult(
                        url=dataset_url,
                        title=title,
                        excerpt=str(dataset.get("subtitle") or dataset.get("description") or "")[:1000],
                        provider=self.name,
                        query=query,
                        published=str(dataset.get("lastUpdated") or dataset.get("updated") or ""),
                        source_url=dataset_url,
                        record_id=dataset_ref,
                        reference_kind="dataset_record",
                        metadata={
                            "catalog": "kaggle",
                            "dataset_ref": dataset_ref,
                            "dataset_title": title,
                            "dataset_url": dataset_url,
                        },
                    ))
            if len(datasets) < page_size:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)

    @staticmethod
    def _dataset_rows(data: object) -> list[dict]:
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            rows = data.get("datasets") or data.get("results") or []
            return [item for item in rows if isinstance(item, dict)]
        return []

    @staticmethod
    def _dataset_ref(dataset: dict) -> str:
        reference = str(dataset.get("ref") or dataset.get("datasetRef") or "").strip("/")
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", reference):
            return reference
        owner = str(dataset.get("ownerRef") or dataset.get("ownerSlug") or "").strip("/")
        slug = str(dataset.get("datasetSlug") or dataset.get("slug") or "").strip("/")
        reference = f"{owner}/{slug}" if owner and slug else ""
        return reference if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", reference) else ""

    @staticmethod
    def _headers() -> dict[str, str]:
        headers = {"Accept": "application/json"}
        username = os.getenv("KAGGLE_USERNAME", "")
        key = os.getenv("KAGGLE_KEY", "")
        if username and key:
            token = base64.b64encode(f"{username}:{key}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers
