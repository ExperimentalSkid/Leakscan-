import csv

import pytest

from leakscan.bootstrap import CatalogBootstrapper
from leakscan.config import ArtifactReferenceConfig
from leakscan.crawler import Crawler
from leakscan.database import CaseDatabase
from leakscan.models import FetchResult
from leakscan.reporting import export_reports, prepare_output
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
