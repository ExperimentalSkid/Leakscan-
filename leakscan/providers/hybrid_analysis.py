"""Hybrid Analysis filename/hash metadata search provider; never downloads samples."""

from __future__ import annotations

import os
from urllib.parse import unquote

import httpx

from ..models import SearchResult
from .base import SearchProvider, is_probable_hash


class HybridAnalysisProvider(SearchProvider):
    name = "hybrid_analysis"
    api_key_env = "HYBRID_ANALYSIS_API_KEY"
    endpoint = "https://hybrid-analysis.com/api/v2"
    minimum_request_interval_seconds = 12.0
    query_capabilities = frozenset({"filename", "hash"})

    def request_key(self, query: str) -> str:
        digest = is_probable_hash(query)
        if digest:
            return f"hash:{digest}"
        filename = self._filename_query(query)
        return f"filename:{filename.casefold()}" if filename else ""

    def _filename_query(self, query: str) -> str:
        cleaned = query.strip()
        if len(cleaned) < 3 or not (cleaned.startswith('"') and cleaned.endswith('"')):
            return ""
        literal = unquote(cleaned[1:-1]).strip()
        lowered = literal.casefold()
        return literal if any(lowered.endswith(extension.casefold()) for extension in self.archive_extensions) else ""

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> list[SearchResult]:
        headers = {"api-key": os.environ["HYBRID_ANALYSIS_API_KEY"], "Accept": "application/json"}
        digest = is_probable_hash(query)
        if digest:
            data = await self.get_json(
                client,
                f"{self.endpoint}/search/hash",
                params={"hash": digest},
                headers=headers,
            )
            return self._hash_results(data, digest, query, limit)

        filename = self._filename_query(query)
        if not filename:
            return []
        data = await self.post_json(
            client,
            f"{self.endpoint}/search/terms",
            data={"filename": filename},
            headers=headers,
        )
        output: list[SearchResult] = []
        for group in data if isinstance(data, list) else []:
            for item in group.get("result", []):
                sha256 = item.get("sha256", "")
                if not sha256:
                    continue
                report_url = f"https://hybrid-analysis.com/sample/{sha256}"
                environment = item.get("environment_id")
                record_id = item.get("job_id") or f"{sha256}:{environment or ''}"
                output.append(SearchResult(
                    url=report_url,
                    title=item.get("submit_name", "") or f"Hybrid Analysis sample {sha256}",
                    excerpt=self._excerpt(item),
                    provider=self.name,
                    query=query,
                    published=item.get("analysis_start_time", ""),
                    source_url=report_url,
                    record_id=str(record_id),
                    reference_kind="analysis_artifact",
                    metadata=item,
                ))
                if len(output) >= limit:
                    return output
        return output

    def _hash_results(self, data: dict, digest: str, query: str, limit: int) -> list[SearchResult]:
        sha256s = data.get("sha256s", []) if isinstance(data, dict) else []
        sha256 = sha256s[0] if sha256s else digest
        report_url = f"https://hybrid-analysis.com/sample/{sha256}"
        output: list[SearchResult] = []
        for item in data.get("reports", [])[:limit] if isinstance(data, dict) else []:
            output.append(SearchResult(
                url=report_url,
                title=f"Hybrid Analysis report {sha256}",
                excerpt=self._excerpt(item),
                provider=self.name,
                query=query,
                source_url=report_url,
                record_id=str(item.get("id") or f"{sha256}:{item.get('environment_id', '')}"),
                reference_kind="analysis_artifact",
                metadata=item,
            ))
        return output

    @staticmethod
    def _excerpt(item: dict) -> str:
        details = [
            f"verdict {item['verdict']}" if item.get("verdict") else "",
            f"type {item['type']}" if item.get("type") else "",
            f"size {item['size']}" if item.get("size") is not None else "",
            f"environment {item['environment_id']}" if item.get("environment_id") is not None else "",
        ]
        return "Hybrid Analysis metadata: " + "; ".join(value for value in details if value)
