"""Adapters for public catalog/listing pages used as fingerprint sources."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from .config import AppConfig, SeedConfig
from .models import CatalogRecord
from .parser import parse_page

ACCOUNT_LABELS = re.compile(r"(?i)^(?:uploader|uploaded by|account|user|username|author|poster|owner)$")
ID_LABELS = re.compile(r"(?i)^(?:item\s*id|file\s*id|identifier|listing\s*id|post\s*id)$")


class CatalogAdapter(ABC):
    name = "base"

    @abstractmethod
    def matches(self, seed: SeedConfig) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, body: bytes, final_url: str, content_type: str, config: AppConfig) -> CatalogRecord:
        raise NotImplementedError


def _labelled_fields(soup: BeautifulSoup) -> dict[str, str]:
    fields: dict[str, str] = {}
    for row in soup.find_all("tr"):
        cells = row.find_all(["th", "td"])
        if len(cells) >= 2:
            label = cells[0].get_text(" ", strip=True).rstrip(":")
            value = cells[1].get_text(" ", strip=True)
            if label and value:
                fields.setdefault(label, value[:1000])
    for term in soup.find_all("dt"):
        value_node = term.find_next_sibling("dd")
        if value_node:
            label = term.get_text(" ", strip=True).rstrip(":")
            value = value_node.get_text(" ", strip=True)
            if label and value:
                fields.setdefault(label, value[:1000])
    for element in soup.find_all(attrs={"data-label": True}):
        label = str(element.get("data-label", "")).strip().rstrip(":")
        value = element.get_text(" ", strip=True)
        if label and value:
            fields.setdefault(label, value[:1000])
    return fields


def _accounts_from_fields(fields: dict[str, str]) -> list[str]:
    return list(dict.fromkeys(value for label, value in fields.items() if ACCOUNT_LABELS.match(label.strip())))


def _ids_from_fields(fields: dict[str, str]) -> list[str]:
    return list(dict.fromkeys(value for label, value in fields.items() if ID_LABELS.match(label.strip())))


class GenericCatalogAdapter(CatalogAdapter):
    name = "generic"

    def matches(self, seed: SeedConfig) -> bool:
        return True

    def parse(self, body: bytes, final_url: str, content_type: str, config: AppConfig) -> CatalogRecord:
        page = parse_page(body, final_url, content_type)
        soup = BeautifulSoup(body, "html.parser")
        fields = _labelled_fields(soup)
        observed_ids = _ids_from_fields(fields)
        combined = f"{final_url}\n{page.text}"
        observed_ids.extend(item_id for item_id in config.case.item_ids if item_id in combined)
        return CatalogRecord(
            source_url=final_url,
            source_name=urlsplit(final_url).hostname or "catalog",
            adapter=self.name,
            title=page.title,
            item_ids=list(dict.fromkeys(observed_ids)),
            filenames=page.filenames,
            sizes=page.sizes,
            hashes=page.hashes,
            dates=page.dates,
            accounts=_accounts_from_fields(fields),
            links=page.links,
            fields=fields,
        )


class BiteBlobCatalogAdapter(GenericCatalogAdapter):
    """Parser for BiteBlob information-page metadata; it never follows archive bodies."""

    name = "biteblob"

    def matches(self, seed: SeedConfig) -> bool:
        return seed.adapter == self.name or (urlsplit(seed.url).hostname or "").lower().endswith("biteblob.com")

    def parse(self, body: bytes, final_url: str, content_type: str, config: AppConfig) -> CatalogRecord:
        record = super().parse(body, final_url, content_type, config)
        record.adapter = self.name
        match = re.search(r"(?i)/Information/([^/?#]+)", final_url)
        if match:
            record.item_ids.insert(0, unquote(match.group(1)))
        fragment = unquote(urlsplit(final_url).fragment)
        if fragment and any(fragment.lower().endswith(ext.lower()) for ext in config.safety.archive_extensions):
            record.filenames.insert(0, fragment)
        record.item_ids = list(dict.fromkeys(record.item_ids))
        record.filenames = list(dict.fromkeys(record.filenames))
        return record


def adapter_for(seed: SeedConfig) -> CatalogAdapter:
    adapters: list[CatalogAdapter] = [BiteBlobCatalogAdapter(), GenericCatalogAdapter()]
    if seed.adapter not in {"", "auto"}:
        for adapter in adapters:
            if adapter.name == seed.adapter:
                return adapter
    for adapter in adapters:
        if adapter.matches(seed):
            return adapter
    return GenericCatalogAdapter()
