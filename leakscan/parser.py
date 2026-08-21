"""Safe, non-executing extraction from retrieved HTML and text."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from html import unescape
from typing import Any
from urllib.parse import unquote, urljoin

from bs4 import BeautifulSoup

from .models import ParsedPage

URL_RE = re.compile(r"(?i)https?:(?:\\?/){2}[^\s<>\"'`\\]+")
HASH_PATTERNS = {
    "md5": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])"),
    "sha1": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])"),
    "sha256": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])"),
    "sha512": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])"),
}
SIZE_RE = re.compile(r"(?i)(?<![\w.])(\d+(?:[.,]\d+)?)\s*(bytes?|[kmgt]i?b)(?!\w)")
DATE_RE = re.compile(
    r"(?<!\d)(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2})(?!\d)"
)
ARCHIVE_SUFFIX_PATTERN = (
    r"(?:tar\.gz|tar\.bz2|7z\.\d{3}|part\d+\.rar|7z|zipx?|rar|tar|gz|bz2|xz|tgz|tbz2|zst|\d{3})"
)
FILENAME_RE = re.compile(
    rf"(?i)(?<![\w])([A-Za-z0-9][A-Za-z0-9 _().\[\]&+,'-]{{0,180}}\.{ARCHIVE_SUFFIX_PATTERN})\b"
)


def normalize_size(number: str, unit: str) -> int | None:
    try:
        value = float(number.replace(",", "."))
    except ValueError:
        return None
    unit = unit.lower()
    factors = {
        "byte": 1, "bytes": 1, "kb": 1000, "kib": 1024,
        "mb": 1000**2, "mib": 1024**2, "gb": 1000**3, "gib": 1024**3,
        "tb": 1000**4, "tib": 1024**4,
    }
    return round(value * factors[unit]) if unit in factors else None


def extract_hashes(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    occupied: set[tuple[int, int]] = set()
    for algorithm in ("sha512", "sha256", "sha1", "md5"):
        for match in HASH_PATTERNS[algorithm].finditer(text):
            span = match.span()
            if any(span[0] >= start and span[1] <= end for start, end in occupied):
                continue
            occupied.add(span)
            results.append({"algorithm": algorithm, "value": match.group(0).lower()})
    return results


def extract_sizes(text: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    sizes = []
    for match in SIZE_RE.finditer(text):
        original = match.group(0)
        if original.lower() in seen:
            continue
        seen.add(original.lower())
        sizes.append({"original": original, "bytes": normalize_size(match.group(1), match.group(2))})
    return sizes


def _urls_from_json(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"url", "contenturl", "downloadurl", "sameas", "embedurl"}:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, list):
                    yield from (entry for entry in item if isinstance(entry, str))
            yield from _urls_from_json(item)
    elif isinstance(value, list):
        for item in value:
            yield from _urls_from_json(item)


def _clean_raw_url(value: str) -> str:
    return unescape(value).replace("\\/", "/").rstrip(".,);]}")


def parse_page(body: bytes, base_url: str, content_type: str = "") -> ParsedPage:
    charset = "utf-8"
    match = re.search(r"charset=([\w-]+)", content_type, flags=re.IGNORECASE)
    if match:
        charset = match.group(1)
    try:
        decoded = body.decode(charset, errors="replace")
    except LookupError:
        decoded = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(decoded, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)
    links: list[str] = []
    link_contexts: dict[str, str] = {}
    canonical = ""
    for tag, attribute in (("a", "href"), ("link", "href"), ("iframe", "src"), ("script", "src"), ("img", "src")):
        for element in soup.find_all(tag):
            raw = element.get(attribute)
            if not isinstance(raw, str):
                continue
            absolute = urljoin(base_url, unquote(raw.strip()))
            links.append(absolute)
            visible = element.get_text(" ", strip=True)
            if visible:
                link_contexts.setdefault(absolute, visible[:500])
            if tag == "link" and "canonical" in [str(item).lower() for item in (element.get("rel") or [])]:
                canonical = absolute
    for element in soup.find_all("meta"):
        content = element.get("content")
        if isinstance(content, str) and ("url=" in content.lower() or content.startswith(("http://", "https://", "//"))):
            possible = content.split("url=", 1)[-1].strip(" '\"")
            links.append(urljoin(base_url, possible))
    for element in soup.find_all("script", attrs={"type": re.compile("ld\\+json", re.IGNORECASE)}):
        try:
            parsed = json.loads(element.string or element.get_text())
            links.extend(urljoin(base_url, item) for item in _urls_from_json(parsed))
        except (json.JSONDecodeError, TypeError):
            continue
    for match in URL_RE.finditer(decoded):
        links.append(_clean_raw_url(match.group(0)))
    decoded_again = unquote(decoded)
    if decoded_again != decoded:
        for match in URL_RE.finditer(decoded_again):
            links.append(_clean_raw_url(match.group(0)))
    filenames: list[str] = []
    for text_node in soup.stripped_strings:
        filenames.extend(match.group(1).strip() for match in FILENAME_RE.finditer(str(text_node)))
    filenames.extend(filename for filename in (_filename_from_link(link) for link in links) if filename)
    filenames = list(dict.fromkeys(filenames))
    dates = list(dict.fromkeys(match.group(0) for match in DATE_RE.finditer(text)))
    return ParsedPage(
        title=title[:500],
        text=text,
        links=list(dict.fromkeys(links)),
        link_contexts=link_contexts,
        canonical_url=canonical,
        hashes=extract_hashes(text),
        sizes=extract_sizes(text),
        dates=dates,
        filenames=filenames,
    )


def _filename_from_link(url: str) -> str:
    from pathlib import PurePosixPath
    from urllib.parse import urlsplit

    name = PurePosixPath(unquote(urlsplit(url).path)).name
    return name if re.search(rf"(?i)\.{ARCHIVE_SUFFIX_PATTERN}$", name) else ""


def context_excerpt(text: str, needles: list[str], width: int = 500) -> str:
    lowered = text.lower()
    positions = [lowered.find(needle.lower()) for needle in needles if needle and lowered.find(needle.lower()) >= 0]
    if not positions:
        return text[:width].strip()
    position = min(positions)
    start = max(0, position - width // 3)
    return text[start : start + width].strip()
