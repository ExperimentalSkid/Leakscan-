"""Guided case creation for operators who do not want to author YAML by hand."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from .config import SafetyConfig

InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], object]


class WizardCancelled(Exception):
    """Raised when an operator declines to start the guided scan."""


def run_wizard(
    *,
    input_func: InputFunction = input,
    output_func: OutputFunction = print,
    home: Path | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Collect a small target definition, save it, and return normal CLI arguments."""
    output_func("")
    output_func("Leakscan guided scan")
    output_func("Search public indexes and verify candidates without downloading archive bodies.")
    output_func("Only the first answer is required. Press Enter to skip anything you do not know.")
    output_func("")

    target = _required(
        input_func,
        output_func,
        "What are you looking for? (file name, object ID, hash, phrase, or URL): ",
    )
    add_details = input_func("Add optional URLs, IDs, size, aliases, or source details? [y/N]: ").strip().casefold()
    if add_details in {"y", "yes"}:
        listing_values = _split_values(input_func(
            "Known public listing/page URL(s), if any (separate multiple with ;): "
        ))
        exact_values = _split_values(input_func(
            "Other exact object IDs or hashes, if any (separate multiple with ;): "
        ))
        reported_sizes = _split_values(input_func(
            "Known file size(s), if any, such as 6.5 GB (separate multiple with ;): "
        ))
        aliases = _split_values(input_func(
            "Other names or distinctive phrases, if any (separate multiple with ;): "
        ))
        actor_aliases = _split_values(input_func(
            "Actor/group names associated with it, if any (separate multiple with ;): "
        ))
        public_channels = _split_values(input_func(
            "Validated public Telegram preview URL(s), if any (separate multiple with ;): "
        ))
        profile = _profile(
            input_func("Coverage: focused, balanced, or broad [broad]: "),
            output_func,
        )
    else:
        listing_values = []
        exact_values = []
        reported_sizes = []
        aliases = []
        actor_aliases = []
        public_channels = []
        profile = "broad"

    fields = {
        "seeds": [],
        "item_ids": [],
        "filenames": [],
        "search_hashes": [],
        "distinctive_phrases": [],
    }
    _classify_value(target, fields)
    for value in [*listing_values, *exact_values]:
        _classify_value(value, fields)
    fields["seeds"] = _deduplicate(fields["seeds"])
    fields["item_ids"] = _deduplicate(fields["item_ids"])
    fields["filenames"] = _deduplicate(fields["filenames"])
    fields["search_hashes"] = _deduplicate(fields["search_hashes"])
    fields["distinctive_phrases"] = _deduplicate(fields["distinctive_phrases"])

    timestamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    case_name = _case_name(target)
    home_dir = (home or Path.home()).expanduser().resolve()
    case_path = _unique_path(
        home_dir / ".local" / "share" / "leakscan" / "cases" / f"{case_name}-{timestamp}.yaml"
    )
    default_output = home_dir / "leakscan-results" / f"{case_name}-{timestamp}"
    output_answer = (
        input_func(f"Results folder [{default_output}]: ").strip()
        if add_details in {"y", "yes"}
        else ""
    )
    output_dir = Path(output_answer).expanduser().resolve() if output_answer else default_output

    output_func("")
    output_func("Ready to scan")
    output_func(f"  Target: {target}")
    output_func(f"  Coverage: {profile}")
    output_func(f"  Public seed pages: {len(fields['seeds'])}")
    output_func(f"  Results: {output_dir}")
    output_func(f"  Reusable case: {case_path}")
    answer = input_func("Start now? [Y/n]: ").strip().casefold()
    if answer not in {"", "y", "yes"}:
        raise WizardCancelled("scan cancelled; no case file was created")

    if (output_dir / "state.sqlite3").exists():
        raise ValueError(
            f"the results folder already contains a scan: {output_dir}; choose a new folder"
        )
    case_path.parent.mkdir(parents=True, exist_ok=True)
    case_data = {
        "case": {
            "name": case_name,
            "seeds": [
                {"url": value, "source": "operator", "adapter": "auto"}
                for value in fields["seeds"]
            ],
            "item_ids": fields["item_ids"],
            "filenames": fields["filenames"],
            "search_hashes": fields["search_hashes"],
            "reported_sizes": reported_sizes,
            "distinctive_phrases": fields["distinctive_phrases"],
            "aliases": aliases,
            "translated_descriptors": [],
            "actor_aliases": actor_aliases,
            "incident_terms": [],
            "public_channels": public_channels,
            "exclusion_terms": [],
            "artifacts": [],
        }
    }
    case_path.write_text(
        yaml.safe_dump(case_data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    output_func(f"Case saved: {case_path}")
    output_func("Resume later with:")
    output_func(
        f'leakscan all --resume --case "{case_path}" --output "{output_dir}" '
        f"--search-profile {profile}"
    )
    output_func("Starting discovery. Press Ctrl+C safely; the printed resume command can continue later.")
    output_func("")
    return [
        "all",
        "--case", str(case_path),
        "--output", str(output_dir),
        "--search-profile", profile,
    ]


def _required(input_func: InputFunction, output_func: OutputFunction, prompt: str) -> str:
    while True:
        value = input_func(prompt).strip()
        if value:
            return value
        output_func("Please enter at least a file name, identifier, hash, phrase, or URL.")


def _split_values(value: str) -> list[str]:
    return _deduplicate(part.strip() for part in value.split(";") if part.strip())


def _profile(value: str, output_func: OutputFunction) -> str:
    selected = value.strip().casefold() or "broad"
    aliases = {"f": "focused", "b": "balanced", "max": "broad"}
    selected = aliases.get(selected, selected)
    if selected not in {"focused", "balanced", "broad"}:
        output_func("Unknown coverage choice; using broad.")
        return "broad"
    return selected


def _classify_value(value: str, fields: dict[str, list[str]]) -> None:
    cleaned = value.strip()
    if not cleaned:
        return
    if _is_url(cleaned):
        fields["seeds"].append(cleaned)
        parts = urlsplit(cleaned)
        fragment = unquote(parts.fragment).strip()
        if fragment:
            _classify_non_url(fragment, fields)
        last_segment = unquote(parts.path.rstrip("/").rsplit("/", 1)[-1]).strip()
        if last_segment and last_segment.casefold() not in {"information", "download"}:
            _classify_non_url(last_segment, fields)
        return
    _classify_non_url(cleaned, fields)


def _classify_non_url(value: str, fields: dict[str, list[str]]) -> None:
    lowered = value.casefold()
    extensions = sorted(SafetyConfig().archive_extensions, key=len, reverse=True)
    if _is_hash(value):
        fields["search_hashes"].append(lowered)
    elif any(lowered.endswith(extension.casefold()) for extension in extensions):
        fields["filenames"].append(value)
    elif " " not in value and re.fullmatch(r"[A-Za-z0-9_.:-]{6,}", value):
        fields["item_ids"].append(value)
    else:
        fields["distinctive_phrases"].append(value)


def _is_hash(value: str) -> bool:
    lowered = value.strip().casefold()
    return len(lowered) in {32, 40, 64, 128} and all(character in "0123456789abcdef" for character in lowered)


def _is_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme.casefold() in {"http", "https"} and bool(parts.hostname)


def _case_name(target: str) -> str:
    if _is_url(target):
        parts = urlsplit(target)
        target = f"{parts.hostname or 'scan'}-{parts.path.rstrip('/').rsplit('/', 1)[-1]}"
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", unquote(target)).strip("._-")
    return (value[:60] or "guided_scan").casefold()


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for number in range(2, 10_000):
        candidate = path.with_name(f"{path.stem}-{number}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not create a unique case path below {path.parent}")


def _deduplicate(values) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
