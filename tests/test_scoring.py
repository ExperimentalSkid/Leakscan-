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


def test_target_size_accepts_decimal_and_binary_interpretations():
    ranges = target_size_ranges("549.04 MB", 0.01)
    assert any(low <= 549_040_000 <= high for low, high in ranges)
    assert any(low <= round(549.04 * 1024**2) <= high for low, high in ranges)


def test_filename_mutation_matches(app_config):
    mutated = "Example Dataset.zip"
    result = score_candidate(app_config, f"https://example.org/{mutated}", filename=mutated)
    assert any(reason["reason"] == "filename_similarity_above_threshold" for reason in result.reasons)
