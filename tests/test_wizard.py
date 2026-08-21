from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from leakscan.config import load_config
from leakscan.wizard import WizardCancelled, run_wizard


def test_guided_scan_creates_reusable_case_from_filename(tmp_path: Path) -> None:
    search_hash = "b" * 64
    answers = iter([
        "Example Archive.7z",
        "y",
        "https://catalog.example/Information/abcDEF123/",
        f"secondaryID;{search_hash}",
        "6.5 GB",
        "Example Archive;Project Example",
        "Example Actor",
        "https://t.me/s/ExampleChannel",
        "",
        "",
        "y",
    ])
    output: list[str] = []

    arguments = run_wizard(
        input_func=lambda _prompt: next(answers),
        output_func=output.append,
        home=tmp_path,
        now=datetime(2026, 8, 21, 12, 34, 56, tzinfo=UTC),
    )

    case_path = Path(arguments[arguments.index("--case") + 1])
    result_path = Path(arguments[arguments.index("--output") + 1])
    raw_case = yaml.safe_load(case_path.read_text(encoding="utf-8"))["case"]

    assert arguments[0] == "all"
    assert arguments[-2:] == ["--search-profile", "broad"]
    assert result_path == tmp_path / "leakscan-results" / "example_archive.7z-20260821T123456Z"
    assert raw_case["filenames"] == ["Example Archive.7z"]
    assert raw_case["item_ids"] == ["abcDEF123", "secondaryID"]
    assert raw_case["search_hashes"] == [search_hash]
    assert raw_case["seeds"][0]["url"] == "https://catalog.example/Information/abcDEF123/"
    assert raw_case["actor_aliases"] == ["Example Actor"]
    assert any(line.startswith("Case saved:") for line in output)
    assert any("--search-profile broad" in line for line in output)


def test_guided_scan_can_start_without_seed_url(tmp_path: Path) -> None:
    answers = iter([
        "Unique dataset phrase",
        "",
        "yes",
    ])

    arguments = run_wizard(
        input_func=lambda _prompt: next(answers),
        output_func=lambda _line: None,
        home=tmp_path,
        now=datetime(2026, 8, 21, tzinfo=UTC),
    )
    case_path = Path(arguments[arguments.index("--case") + 1])
    settings_path = Path(__file__).resolve().parent.parent / "leakscan" / "default_settings.yaml"

    config = load_config(settings_path, case_path)

    assert config.case.seeds == []
    assert config.case.distinctive_phrases == ["Unique dataset phrase"]


def test_declining_guided_scan_does_not_create_case(tmp_path: Path) -> None:
    answers = iter([
        "Example Archive.7z",
        "",
        "n",
    ])

    with pytest.raises(WizardCancelled):
        run_wizard(
            input_func=lambda _prompt: next(answers),
            output_func=lambda _line: None,
            home=tmp_path,
            now=datetime(2026, 8, 21, tzinfo=UTC),
        )

    assert not (tmp_path / ".local" / "share" / "leakscan" / "cases").exists()
