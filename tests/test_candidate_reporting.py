import csv
import json

from leakscan.database import CaseDatabase
from leakscan.models import Finding
from leakscan.reporting import _candidate_summaries, export_reports, prepare_output


def test_latest_direct_404_overrides_repeated_index_matches() -> None:
    url = "https://files.example/u/example"
    detection = Finding(
        timestamp_utc="2026-01-01T00:00:00Z",
        discovery_method="search_result",
        source="public_index",
        source_url="https://index.example/result/record-id",
        candidate_url=url,
        normalized_url=url,
        score=160,
        classification="LIKELY",
        detection_point={
            "provider": "public_index",
            "query": '"Example Archive.7z"',
            "detected_at": "2026-01-01T00:00:00Z",
            "record_url": "https://index.example/result/record-id",
            "record_id": "record-id",
        },
    )
    duplicate = Finding.from_dict(detection.to_dict())
    direct = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="metadata_only_probe",
        source="public_index",
        candidate_url=url,
        final_url=url,
        normalized_url=url,
        status_code=404,
        classification="DEAD",
        last_checked="2026-01-02T00:00:00Z",
        evidence_path="evidence/metadata/example.json",
    )

    summaries = _candidate_summaries([detection, duplicate, direct], likely_threshold=50)

    assert len(summaries) == 1
    assert summaries[0]["current_status"] == "HISTORICAL_DEAD"
    assert summaries[0]["observation_count"] == 3
    assert summaries[0]["detection_provider"] == "public_index"
    assert summaries[0]["detection_record_id"] == "record-id"


def test_only_verified_file_metadata_is_called_live() -> None:
    url = "https://files.example/u/example"
    current_page = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="recursive_html_fetch",
        candidate_url=url,
        normalized_url=url,
        status_code=200,
        classification="LIKELY",
        score=100,
        score_reasons=[
            {"points": 90, "reason": "exact_filename", "evidence": "Example Archive.7z"},
        ],
        last_checked="2026-01-02T00:00:00Z",
    )
    verified_file = Finding.from_dict(current_page.to_dict())
    verified_file.classification = "CONFIRMED_METADATA_ONLY"

    assert _candidate_summaries([current_page], 50)[0]["current_status"] == "CURRENT_REFERENCE_ONLY"
    assert _candidate_summaries([verified_file], 50)[0]["current_status"] == "LIVE_METADATA_ONLY"


def test_listing_and_download_routes_have_precise_non_file_states() -> None:
    listing = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="recursive_html_fetch",
        candidate_url="https://catalog.example/Information/example",
        normalized_url="https://catalog.example/Information/example",
        status_code=200,
        classification="LISTING_LIVE",
        score=100,
        last_checked="2026-01-02T00:00:00Z",
    )
    download = Finding.from_dict(listing.to_dict())
    download.candidate_url = "https://catalog.example/Download/example"
    download.normalized_url = download.candidate_url
    download.classification = "DOWNLOAD_ROUTE_LIVE"

    summaries = _candidate_summaries([listing, download], 50)

    assert {item["current_status"] for item in summaries} == {"LISTING_LIVE", "DOWNLOAD_ROUTE_LIVE"}


def test_host_verification_fields_and_takedown_state_are_exported() -> None:
    finding = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="metadata_only_probe",
        candidate_url="https://files.example/u/example",
        normalized_url="https://files.example/u/example",
        status_code=200,
        classification="TAKEN_DOWN",
        score=100,
        last_checked="2026-01-02T00:00:00Z",
        verification_point={
            "method": "file_host_api",
            "endpoint": "https://files.example/api/file/example/info",
            "object_id": "example",
            "verified_at": "2026-01-02T00:00:00Z",
            "metadata": {
                "name": "Example Archive.7z",
                "size": 123,
                "hash_sha256": "a" * 64,
                "availability": "unavailable_for_legal_reasons",
            },
        },
    )

    summary = _candidate_summaries([finding], 50)[0]

    assert summary["current_status"] == "TAKEN_DOWN"
    assert summary["verification_method"] == "file_host_api"
    assert summary["host_object_id"] == "example"
    assert summary["verified_filename"] == "Example Archive.7z"
    assert summary["verified_size_bytes"] == 123
    assert summary["verified_sha256"] == "a" * 64


def test_unrelated_live_archive_is_not_a_target_candidate() -> None:
    finding = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="metadata_only_probe",
        candidate_url="https://cdn.example/openh264-runtime.zip",
        normalized_url="https://cdn.example/openh264-runtime.zip",
        status_code=200,
        classification="CONFIRMED_METADATA_ONLY",
        score=20,
        score_reasons=[{"points": 20, "reason": "archive_reference", "evidence": "zip"}],
        last_checked="2026-01-02T00:00:00Z",
    )

    assert _candidate_summaries([finding], 50) == []


def test_weak_fragment_cannot_turn_unrelated_file_metadata_into_live_target(app_config) -> None:
    url = "https://archive.org/compress/ijds-v11n12-01"
    detection = Finding(
        timestamp_utc="2026-01-01T00:00:00Z",
        discovery_method="search_result",
        source="archive_org_items",
        candidate_url=url,
        normalized_url=url,
        filename="ijds-v11n12-01.zip",
        score=55,
        score_reasons=[
            {"points": 35, "reason": "keyword_fragment", "evidence": "National Social Security Fund"},
            {"points": 20, "reason": "archive_reference", "evidence": "zip"},
        ],
        classification="UNVERIFIED",
    )
    direct = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="metadata_only_probe",
        source="archive_org_items",
        candidate_url=url,
        normalized_url=url,
        status_code=200,
        filename="ijds-v11n12-01.zip",
        score=20,
        score_reasons=[
            {"points": 20, "reason": "archive_reference", "evidence": "zip"},
        ],
        classification="CONFIRMED_METADATA_ONLY",
        last_checked="2026-01-02T00:00:00Z",
    )

    summary = _candidate_summaries([detection, direct], 50)[0]

    assert summary["current_status"] == "UNVERIFIED"
    assert summary["target_identity_confirmed"] is False
    assert summary["target_identity_basis"] == []

    prepare_output(app_config)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        database.record_finding(detection)
        database.record_finding(direct)
        export_reports(app_config, database)
    finally:
        database.close()
    overview = json.loads((app_config.output_dir / "overview.json").read_text(encoding="utf-8"))
    assert overview["counts"]["live_metadata_only"] == 0
    assert overview["counts"]["unresolved_or_blocked"] == 1
    assert overview["top_candidates"][0]["current_status"] == "UNVERIFIED"
    assert overview["top_candidates"][0]["target_identity_confirmed"] is False


def test_legacy_urlscan_observation_recovers_detection_record() -> None:
    finding = Finding(
        timestamp_utc="2026-01-01T00:00:00Z",
        discovery_method="search_result",
        source="urlscan",
        source_url="https://files.example/u/example",
        candidate_url="https://files.example/u/example",
        normalized_url="https://files.example/u/example",
        context_excerpt="urlscan result 019642f9-a46c-7157-a14e-680c7908d2e2; domain files.example",
        score=160,
        classification="LIKELY",
    )

    summary = _candidate_summaries([finding], 50)[0]

    assert summary["detection_record_id"] == "019642f9-a46c-7157-a14e-680c7908d2e2"
    assert summary["detection_record_url"].endswith("/019642f9-a46c-7157-a14e-680c7908d2e2/")


def test_exports_one_candidate_with_detection_point_and_authoritative_status(app_config) -> None:
    url = "https://files.example/u/example"
    detection = Finding(
        timestamp_utc="2026-01-01T00:00:00Z",
        discovery_method="search_result",
        source="public_index",
        candidate_url=url,
        normalized_url=url,
        score=160,
        classification="UNVERIFIED",
        detection_point={
            "provider": "public_index",
            "query": '"Example Archive.7z"',
            "detected_at": "2026-01-01T00:00:00Z",
            "record_url": "https://index.example/result/record-id",
            "record_id": "record-id",
        },
    )
    direct = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="metadata_only_probe",
        source="public_index",
        candidate_url=url,
        normalized_url=url,
        status_code=404,
        classification="DEAD",
        last_checked="2026-01-02T00:00:00Z",
    )
    prepare_output(app_config)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        database.record_finding(detection)
        database.record_finding(Finding.from_dict(detection.to_dict()))
        database.record_finding(direct)
        export_reports(app_config, database)
    finally:
        database.close()

    with (app_config.output_dir / "candidate_urls.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["current_status"] == "HISTORICAL_DEAD"
    assert rows[0]["detection_record_id"] == "record-id"
    summary = (app_config.output_dir / "reports" / "analyst_summary.md").read_text(encoding="utf-8")
    assert "historical/dead: **1**" in summary
    assert "Raw observations" not in summary
    overview = json.loads((app_config.output_dir / "overview.json").read_text(encoding="utf-8"))
    overview_markdown = (app_config.output_dir / "overview.md").read_text(encoding="utf-8")
    assert overview["counts"]["unique_candidates"] == 1
    assert overview["counts"]["dead_or_historical"] == 1
    assert overview["counts"]["raw_observations"] == 3
    assert overview["top_candidates"][0]["detection_provider"] == "public_index"
    assert "## What the scan caught" in overview_markdown
    assert "## Strongest detection points" in overview_markdown
    assert 'query `"Example Archive.7z"`' in overview_markdown
