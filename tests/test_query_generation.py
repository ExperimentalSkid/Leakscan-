from leakscan.config import (
    ArtifactReferenceConfig,
    _render_user_agent,
    filename_variants,
    generate_queries,
    initial_fingerprints,
)


def test_exact_filename_is_first_and_all_configured_extensions_are_retained(app_config) -> None:
    filename = "Example Dataset.7z"
    extensions = app_config.safety.archive_extensions

    variants = filename_variants(filename, extensions)
    queries = generate_queries(app_config)

    assert variants[0] == filename
    for extension in extensions:
        assert f"Example Dataset{extension}" in variants
    assert queries[0] == f'"{filename}"'


def test_compound_archive_suffix_is_removed_as_one_unit(app_config) -> None:
    variants = filename_variants("Example Dataset.tar.gz", app_config.safety.archive_extensions)

    assert variants[0] == "Example Dataset.tar.gz"
    assert "Example Dataset.7z" in variants
    assert "Example Dataset.tar.7z" not in variants


def test_user_agent_renders_version_and_sanitized_contact(monkeypatch) -> None:
    monkeypatch.setenv("LEAKSCAN_CONTACT", "security@example.test\r\nInjected: no")

    rendered = _render_user_agent("Leakscan/{version} (+metadata checks)")

    assert rendered.startswith("Leakscan/1.1.0")
    assert "\r" not in rendered and "\n" not in rendered
    assert "contact=security@example.testInjected: no" in rendered


def test_first_provider_budget_contains_only_strong_queries(app_config) -> None:
    queries = generate_queries(app_config)
    first_budget = queries[: app_config.search.max_queries_per_provider]

    assert '"Example Dataset.7z"' in first_budget
    assert '"abcDEF123"' in first_budget
    assert f'"{app_config.case.primary_seed_url}"' in first_budget
    assert not any(query.rsplit(" ", 1)[-1] in app_config.search.intent_terms for query in first_budget)


def test_artifact_hash_is_separate_from_payload_hash(app_config) -> None:
    digest = "a" * 64
    app_config.case.artifacts.append(ArtifactReferenceConfig(
        source="sandbox",
        artifact_type="html_page_artifact",
        report_url="https://analysis.example/report/1",
        hashes=[{"algorithm": "sha256", "value": digest}],
    ))

    fingerprints = initial_fingerprints(app_config.case)

    assert digest in fingerprints["artifact_hash"]
    assert digest not in fingerprints["hash"]
    assert f'"{digest}"' in generate_queries(app_config)
