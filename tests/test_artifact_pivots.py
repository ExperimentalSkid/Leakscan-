import csv

import pytest

from leakscan.bootstrap import CatalogBootstrapper
from leakscan.config import ArtifactReferenceConfig
from leakscan.crawler import Crawler
from leakscan.database import CaseDatabase
from leakscan.models import FetchResult, Finding
from leakscan.reporting import (
    _artifact_maps,
    _artifact_reference_summaries,
    _candidate_summaries,
    export_reports,
    prepare_output,
)
from leakscan.utils.time import utc_now
from leakscan.utils.urls import normalize_url


def test_operator_artifact_is_queued_and_exported_with_label(app_config) -> None:
    digest = "b" * 64
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="url_shortcut_artifact",
        subject_url="https://catalog.example/Download/item",
        report_url="https://analysis.example/report/item",
        observed_at="2026-01-01T00:00:00Z",
        hashes=[{"algorithm": "sha256", "value": digest}],
        notes="Not a payload hash.",
    ))
    prepare_output(app_config)
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        CatalogBootstrapper(app_config, database).register_case_fingerprints()
        export_reports(app_config, database)

        assert digest in database.pivot_map()["artifact_hash"]
        assert digest not in database.pivot_map().get("hash", set())
        assert database.queue_counts() == {"pending": 1}
    finally:
        database.close()

    with (app_config.output_dir / "hashes.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == [{
        "algorithm": "sha256",
        "hash": digest,
        "artifact_type": "url_shortcut_artifact",
        "source_url": "https://analysis.example/report/item",
        "confidence": "operator_supplied_artifact",
        "observed_at": "2026-01-01T00:00:00Z",
    }]
    with (app_config.output_dir / "artifact_references.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        artifact_rows = list(csv.DictReader(handle))
    assert artifact_rows[0]["reference_url"] == "https://analysis.example/report/item"
    assert artifact_rows[0]["current_status"] == "NOT_OBSERVED"


def test_labelled_artifact_page_is_separate_from_target_candidates(app_config) -> None:
    report_url = "https://analysis.example/report/item"
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="html_page_artifact",
        report_url=report_url,
    ))
    finding = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="recursive_html_fetch",
        source="sandbox",
        query="operator-supplied artifact report",
        candidate_url=report_url,
        normalized_url=report_url,
        final_url=report_url,
        status_code=200,
        classification="LIKELY",
        score=100,
        last_checked="2026-01-02T00:00:00Z",
    )
    report_types, hash_types = _artifact_maps(app_config)

    assert _candidate_summaries([finding], 50, report_types, hash_types) == []
    artifacts = _artifact_reference_summaries([finding], report_types, hash_types)
    assert artifacts[0]["reference_url"] == report_url
    assert artifacts[0]["current_status"] == "CURRENT_REFERENCE_ONLY"


def test_hash_indicator_lookup_is_a_derived_artifact_reference(app_config) -> None:
    digest = "d" * 64
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="html_page_artifact",
        report_url="https://analysis.example/report/item",
        hashes=[{"algorithm": "sha256", "value": digest}],
    ))
    indicator_url = f"https://indicator.example/file/{digest}"
    finding = Finding(
        timestamp_utc="2026-01-02T00:00:00Z",
        discovery_method="search_result",
        source="indicator",
        query=f'"{digest}"',
        candidate_url=indicator_url,
        normalized_url=indicator_url,
        classification="REFERENCE_ONLY",
        score=0,
    )
    report_types, hash_types = _artifact_maps(app_config)

    artifacts = _artifact_reference_summaries([finding], report_types, hash_types)
    derived = next(item for item in artifacts if item["reference_url"] == indicator_url)
    assert derived["artifact_type"] == "html_page_artifact:derived_reference"
    assert _candidate_summaries([finding], 50, report_types, hash_types) == []


@pytest.mark.asyncio
async def test_hashes_on_artifact_report_are_not_promoted_to_payload_pivots(app_config) -> None:
    known = "b" * 64
    unknown = "c" * 64
    report_url = "https://analysis.example/report/item"
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="html_page_artifact",
        report_url=report_url,
        hashes=[{"algorithm": "sha256", "value": known}],
    ))
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        crawler = Crawler(app_config, database)
        await crawler._record_page_finding(
            {
                "normalized_url": normalize_url(report_url),
                "original_url": report_url,
                "referrer_url": "",
                "source": "sandbox",
                "query_text": f'"{known}"',
                "depth": 0,
                "priority": 100,
                "created_at": utc_now(),
            },
            FetchResult(
                original_url=report_url,
                final_url=report_url,
                status_code=200,
                headers={"content-type": "text/html"},
                body=f"Example Dataset.7z SHA256 {known} related SHA256 {unknown}".encode(),
            ),
            0,
        )

        assert known not in database.pivot_map().get("hash", set())
        assert unknown not in database.pivot_map().get("hash", set())
        artifact_types = {
            item.get("artifact_type", "")
            for finding in database.iter_findings()
            for item in finding.hashes
        }
        assert "html_page_artifact" in artifact_types
        assert "html_page_artifact:unattributed_report_hash" in artifact_types
    finally:
        database.close()


@pytest.mark.asyncio
async def test_artifact_page_does_not_enqueue_unrelated_archive_dependency(app_config) -> None:
    report_url = "https://analysis.example/report/item"
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="html_page_artifact",
        report_url=report_url,
    ))
    database = CaseDatabase(app_config.output_dir / "state.sqlite3")
    try:
        crawler = Crawler(app_config, database)
        await crawler._record_page_finding(
            {
                "normalized_url": normalize_url(report_url),
                "original_url": report_url,
                "referrer_url": "",
                "source": "sandbox",
                "query_text": "operator-supplied artifact report",
                "depth": 0,
                "priority": 100,
                "created_at": utc_now(),
            },
            FetchResult(
                original_url=report_url,
                final_url=report_url,
                status_code=200,
                headers={"content-type": "text/html"},
                body=b"""
                    <html><body>Example Dataset.7z
                    <a href="https://cdn.example/openh264-runtime.zip">runtime dependency</a>
                    <a href="https://files.example/Example%20Dataset.zip">matching mirror</a>
                    </body></html>
                """,
            ),
            0,
        )

        queued = [
            row["normalized_url"]
            for row in database.connection.execute("SELECT normalized_url FROM url_queue")
        ]
        assert queued == ["https://files.example/Example%20Dataset.zip"]
    finally:
        database.close()
