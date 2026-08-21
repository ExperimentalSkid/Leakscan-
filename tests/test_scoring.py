from leakscan.scoring import classify, score_candidate, target_size_ranges


def test_exact_seed_scoring_is_explained(app_config):
    result = score_candidate(
        app_config,
        "https://example.com/abcDEF123/Example%20Dataset.7z",
        context="Example Dataset 549.04 MB",
        filename="Example Dataset.7z",
        size_bytes=549_040_000,
    )
    names = {reason["reason"] for reason in result.reasons}
    assert result.score >= 200
    assert "exact_item_id" in names
    assert "exact_filename" in names
    assert "approximate_size_match" in names


def test_case_exclusion_is_data_driven(app_config):
    result = score_candidate(app_config, "https://example.org/unrelated-example/news")
    assert result.score == -50


def test_likely_classification(app_config):
    assert classify(app_config.scoring.likely_threshold, app_config) == "LIKELY"


def test_legal_takedown_status_is_distinct_from_generic_block(app_config):
    assert classify(100, app_config, status_code=451, blocked=True) == "TAKEN_DOWN"


def test_target_size_accepts_decimal_and_binary_interpretations():
    ranges = target_size_ranges("549.04 MB", 0.01)
    assert any(low <= 549_040_000 <= high for low, high in ranges)
    assert any(low <= round(549.04 * 1024**2) <= high for low, high in ranges)


def test_filename_mutation_matches(app_config):
    mutated = "Example Dataset.zip"
    result = score_candidate(app_config, f"https://example.org/{mutated}", filename=mutated)
    assert any(reason["reason"] == "filename_similarity_above_threshold" for reason in result.reasons)


def test_partial_multiword_filename_plus_archive_evidence_is_likely(app_config):
    app_config.case.filenames = ["Acme International Payroll Records Archive.7z"]

    result = score_candidate(
        app_config,
        "https://files.example/International-Payroll-Records.zip",
        filename="International-Payroll-Records.zip",
    )

    reasons = {item["reason"] for item in result.reasons}
    assert "keyword_fragment" in reasons
    assert "archive_reference" in reasons
    assert result.score >= app_config.scoring.likely_threshold
