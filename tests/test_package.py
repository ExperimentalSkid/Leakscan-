from importlib import resources

from leakscan import __version__
from leakscan.main import _apply_overrides, _provider_availability, build_parser


def test_version_matches_release() -> None:
    assert __version__ == "1.1.0"


def test_bundled_defaults_and_example_exist() -> None:
    package_root = resources.files("leakscan")
    assert package_root.joinpath("default_settings.yaml").is_file()
    assert package_root.joinpath("examples", "example_case.yaml").is_file()


def test_cli_uses_bundled_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args(["all", "--case", "case.yaml", "--dry-run"])
    assert args.settings.endswith("default_settings.yaml")


def test_cli_exposes_guided_wizard_without_case_argument() -> None:
    args = build_parser().parse_args(["wizard"])

    assert args.command == "wizard"
    assert args.case is None


def test_cli_accepts_explicit_search_breadth(app_config) -> None:
    parser = build_parser()
    args = parser.parse_args([
        "all", "--case", "case.yaml", "--search-profile", "broad",
        "--max-provider-requests", "200", "--max-result-pages-per-query", "7",
    ])

    assert args.search_profile == "broad"
    assert args.max_provider_requests == 200
    assert args.max_result_pages_per_query == 7
    _apply_overrides(app_config, args)
    assert app_config.search.max_queries_per_provider == 200
    assert app_config.search.minimum_queries_before_plateau == 60
    assert app_config.search.stop_after_stale_queries == 20
    assert app_config.search.max_result_pages_per_query == 7


def test_provider_availability_uses_case_scoped_configuration(app_config) -> None:
    app_config.case.public_channels = ["https://t.me/s/ExampleChannel"]

    availability = _provider_availability(app_config)

    assert availability["telegram_public"] == "available"
