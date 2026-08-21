"""Non-invasive domain metadata collection (DNS and TLS certificate only)."""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

import tldextract

from .utils.urls import resolve_public_host

_extract = tldextract.TLDExtract(suffix_list_urls=())


def parent_domain(hostname: str) -> str:
    value = _extract(hostname)
    return value.top_domain_under_public_suffix or hostname


def _tls_metadata(hostname: str, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    with (
        socket.create_connection((hostname, 443), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=hostname) as wrapped,
    ):
        certificate = wrapped.getpeercert()
    return {
        "subject": certificate.get("subject", []),
        "issuer": certificate.get("issuer", []),
        "serial_number": certificate.get("serialNumber", ""),
        "not_before": certificate.get("notBefore", ""),
        "not_after": certificate.get("notAfter", ""),
        "subject_alt_names": certificate.get("subjectAltName", [])[:100],
    }


async def inspect_domain(hostname: str, scheme: str, timeout: float) -> tuple[list[str], dict[str, Any], str]:
    try:
        addresses = await asyncio.to_thread(resolve_public_host, hostname)
    except (OSError, ValueError) as exc:
        return [], {}, f"DNS: {exc}"
    tls: dict[str, Any] = {}
    error = ""
    if scheme == "https":
        try:
            tls = await asyncio.to_thread(_tls_metadata, hostname, timeout)
        except (OSError, ssl.SSLError) as exc:
            error = f"TLS: {exc}"
    return addresses, tls, error
