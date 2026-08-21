from leakscan.config import (
    ArtifactReferenceConfig,
    _render_user_agent,
    filename_variants,
    generate_queries,
    initial_fingerprints,
    keyword_variants,
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


def test_keyword_expansion_uses_bounded_multiword_fragments(app_config) -> None:
    filename = "CNSS - Moroccan National Social Security Fund.7z"
    app_config.case.filenames = [filename]

    fragments = keyword_variants(filename, app_config.safety.archive_extensions)
    queries = generate_queries(app_config)

    assert "Moroccan National Social Security Fund" in fragments
    assert "National Social Security Fund" in fragments
    assert len(fragments) <= 8
    assert all(len(fragment.split()) >= 3 for fragment in fragments)
    assert '"Moroccan National Social Security Fund"' in queries
    assert '"Moroccan"' not in queries


def test_user_agent_renders_version_and_sanitized_contact(monkeypatch) -> None:
    monkeypatch.setenv("LEAKSCAN_CONTACT", "security@example.test\r\nInjected: no")

    rendered = _render_user_agent("Leakscan/{version} (+metadata checks)")

    assert rendered.startswith("Leakscan/1.1.0")
    assert "\r" not in rendered and "\n" not in rendered
    assert "contact=security@example.testInjected: no" in rendered


def test_discovery_floor_contains_identifiers_urls_and_all_extensions(app_config) -> None:
    queries = generate_queries(app_config)
    discovery_floor = queries[: app_config.search.minimum_queries_before_plateau]

    assert '"Example Dataset.7z"' in discovery_floor
    assert '"abcDEF123"' in discovery_floor
    assert f'"{app_config.case.primary_seed_url}"' in discovery_floor
    for extension in app_config.safety.archive_extensions:
        assert f'"Example Dataset{extension}"' in discovery_floor


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


def test_unverified_search_hash_is_queried_without_becoming_payload_hash(app_config) -> None:
    digest = "b" * 64
    app_config.case.search_hashes = [digest]

    fingerprints = initial_fingerprints(app_config.case)

    assert digest in fingerprints["search_hash"]
    assert digest not in fingerprints["hash"]
    assert f'"{digest}"' in generate_queries(app_config)


def test_actor_and_incident_terms_are_case_driven_search_pivots(app_config) -> None:
    app_config.case.actor_aliases = ["Example Actor"]
    app_config.case.incident_terms = ["50,000 records"]

    fingerprints = initial_fingerprints(app_config.case)
    queries = generate_queries(app_config)

    assert "Example Actor" in fingerprints["alias"]
    assert "50,000 records" in fingerprints["phrase"]
    assert '"Example Actor" "Example Dataset"' in queries
    assert '"50,000 records"' in queries
