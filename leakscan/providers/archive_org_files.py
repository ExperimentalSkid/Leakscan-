"""Internet Archive item-file manifest search; file bodies are never requested."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ..models import SearchBatch, SearchResult
from .base import SearchProvider, metadata_name_matches


def _text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value or "")


class ArchiveOrgFilesProvider(SearchProvider):
    name = "archive_org_files"
    query_capabilities = frozenset({"filename", "identifier", "phrase"})
    manifest_items_per_page = 5

    async def search(self, client: httpx.AsyncClient, query: str, limit: int) -> SearchBatch:
        output: list[SearchResult] = []
        pages_fetched = 0
        rows = min(self.manifest_items_per_page, limit)
        for page in range(1, self.max_result_pages_per_query + 1):
            if not self.can_make_request():
                return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
            data = await self.get_json(
                client,
                "https://archive.org/advancedsearch.php",
                params={
                    "q": query,
                    "fl[]": ["identifier", "title", "publicdate", "date", "addeddate"],
                    "rows": rows,
                    "page": page,
                    "output": "json",
                },
            )
            pages_fetched += 1
            response = data.get("response", {})
            documents = response.get("docs", [])
            for item in documents:
                identifier = _text(item.get("identifier"))
                if not identifier:
                    continue
                if not self.can_make_request():
                    return SearchBatch(output, complete=False, pages_fetched=pages_fetched)
                metadata_url = f"https://archive.org/metadata/{quote(identifier, safe='')}"
                manifest = await self.get_json(client, metadata_url)
                for file_record in manifest.get("files", []):
                    filename = _text(file_record.get("name"))
                    if not metadata_name_matches(filename, query):
                        continue
                    file_url = (
                        f"https://archive.org/download/{quote(identifier, safe='')}/"
                        f"{quote(filename, safe='/')}"
                    )
                    hashes = {
                        name: _text(file_record.get(name))
                        for name in ("md5", "sha1", "crc32")
                        if file_record.get(name)
                    }
                    details = [
                        f"size {file_record['size']}" if file_record.get("size") else "",
                        f"format {_text(file_record.get('format'))}" if file_record.get("format") else "",
                        *(f"{name} {value}" for name, value in hashes.items()),
                    ]
                    output.append(SearchResult(
                        url=file_url,
                        title=filename,
                        excerpt="Internet Archive file manifest: " + "; ".join(part for part in details if part),
                        provider=self.name,
                        query=query,
                        published=_text(
                            item.get("publicdate") or item.get("date") or item.get("addeddate")
                        ),
                        source_url=metadata_url,
                        record_id=f"{identifier}:{filename}",
                        metadata={
                            "catalog": "internet_archive",
                            "item_identifier": identifier,
                            "item_title": _text(item.get("title")),
                            "file_name": filename,
                            "file_size": _text(file_record.get("size")),
                            "file_format": _text(file_record.get("format")),
                            "file_source": _text(file_record.get("source")),
                            "hashes": hashes,
                            "metadata_url": metadata_url,
                        },
                    ))
            total = int(response.get("numFound", 0) or 0)
            if len(documents) < rows or page * rows >= total:
                break
        return SearchBatch(output, pages_fetched=pages_fetched)
