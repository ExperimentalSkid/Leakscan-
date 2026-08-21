from leakscan.config import _render_user_agent, filename_variants, generate_queries


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
