"""Leakscan: catalog-first public-reference discovery and evidence preservation."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _resolve_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.is_file():
        with pyproject.open("rb") as handle:
            configured = tomllib.load(handle).get("project", {}).get("version")
        if configured:
            return str(configured)
    try:
        return version("leakscan-osint")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _resolve_version()
