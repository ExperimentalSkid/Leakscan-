"""URL normalization, classification, and public-network safeguards."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

TRACKING_KEYS = {
    "fbclid", "gclid", "dclid", "mc_cid", "mc_eid", "ref", "ref_src", "source",
}
TRACKING_PREFIXES = ("utm_",)


def normalize_url(url: str, base_url: str = "") -> str:
    candidate = urljoin(base_url, url.strip()) if base_url else url.strip()
    candidate = unquote(candidate)
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower().rstrip(".")
    if not scheme or not hostname:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port else host
    path = quote(unquote(parts.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in TRACKING_KEYS
        and not any(key.lower().startswith(prefix) for prefix in TRACKING_PREFIXES)
    ]
    query = urlencode(sorted(query_pairs), doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def hostname_for(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def looks_like_archive_url(url: str, extensions: list[str] | tuple[str, ...]) -> bool:
    path = unquote(urlsplit(url).path).lower()
    suffixes = {suffix.lower() for suffix in extensions}
    return any(path.endswith(suffix) or f"{suffix}/" in path for suffix in suffixes)


def content_headers_indicate_binary(headers: dict[str, str], extensions: list[str]) -> bool:
    content_type = headers.get("content-type", "").lower().split(";", 1)[0].strip()
    disposition = headers.get("content-disposition", "").lower()
    binary_types = (
        "application/octet-stream", "application/x-7z-compressed", "application/zip",
        "application/x-rar-compressed", "application/vnd.rar", "application/x-tar",
        "application/gzip", "binary/octet-stream",
    )
    if content_type in binary_types:
        return True
    return any(extension.lower() in disposition for extension in extensions)


def bytes_look_binary(chunk: bytes) -> bool:
    if not chunk:
        return False
    signatures = (b"7z\xbc\xaf'\x1c", b"PK\x03\x04", b"Rar!\x1a\x07", b"\x1f\x8b")
    if any(chunk.startswith(signature) for signature in signatures):
        return True
    sample = chunk[:1024]
    if b"\x00" in sample:
        return True
    text_like = sum(byte in b"\t\n\r" or 32 <= byte <= 126 or byte >= 128 for byte in sample)
    return (text_like / len(sample)) < 0.70


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_public_host(hostname: str) -> list[str]:
    if not hostname or hostname == "localhost" or hostname.endswith(".local"):
        raise ValueError("local or empty hostname is not permitted")
    try:
        direct = ipaddress.ip_address(hostname)
    except ValueError:
        direct = None
    if direct is not None:
        if not is_public_ip(str(direct)):
            raise ValueError("non-public IP address is not permitted")
        return [str(direct)]
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError("hostname did not resolve")
    if any(not is_public_ip(address) for address in addresses):
        raise ValueError("hostname resolves to a non-public IP address")
    return addresses


def safe_url(url: str, allowed_schemes: list[str], reject_private: bool = True) -> tuple[bool, str]:
    parts = urlsplit(url)
    if parts.scheme.lower() not in allowed_schemes:
        return False, "scheme is not allowed"
    if not parts.hostname:
        return False, "hostname is missing"
    if parts.username or parts.password:
        return False, "credential-bearing URLs are not allowed"
    if reject_private:
        try:
            resolve_public_host(parts.hostname)
        except (OSError, ValueError) as exc:
            return False, str(exc)
    return True, ""


def filename_from_url(url: str) -> str:
    return PurePosixPath(unquote(urlsplit(url).path)).name
