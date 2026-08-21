from pathlib import Path

import pytest

from leakscan.config import load_config


@pytest.fixture
def app_config(tmp_path: Path):
    root = Path(__file__).resolve().parent.parent
    case_path = tmp_path / "case.yaml"
    case_path.write_text(
        """case:
  name: unit_test
  seeds:
    - url: https://catalog.example/Information/abcDEF123/
      source: test_catalog
      adapter: auto
  item_ids: [abcDEF123]
  filenames: [Example Dataset.7z]
  reported_sizes: [549.04 MB]
  distinctive_phrases: [Example Dataset]
  aliases: [Example_Data]
  translated_descriptors: []
  exclusion_terms: [unrelated-example]
""",
        encoding="utf-8",
    )
    config = load_config(root / "leakscan" / "default_settings.yaml", case_path, tmp_path / "case_output")
    config.crawl.respect_robots_txt = False
    config.safety.reject_private_networks = False
    config.crawl.retry_count = 0
    config.crawl.per_host_delay_seconds = 0
    return config
