from importlib import resources

from leakscan import __version__
from leakscan.main import build_parser


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
