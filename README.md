# Leakscan

[![CI](https://github.com/ExperimentalSkid/Leakscan-/actions/workflows/ci.yml/badge.svg)](https://github.com/ExperimentalSkid/Leakscan-/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Leakscan is a catalog-first OSINT crawler for discovering, correlating, verifying, and preserving evidence of public references and publicly accessible locations associated with a specified file or archive.

The engine contains no organization-specific target logic. Identifiers, filenames, sizes, phrases, aliases, and seed listings come from the case YAML supplied with `--case`. Restrictions such as domain allowlists, deny lists, and exclusion terms are optional controls, not baked-in targets.

## What it does

1. Visits configured public catalog or listing pages first.
2. Extracts displayed IDs, filenames, sizes, hashes, dates, accounts, fields, and links.
3. Expands the case fingerprint with newly observed identifiers.
4. Searches independent public sources and recursively crawls relevant HTML or text pages.
5. Repeats discovery when new fingerprints or domains are found.
6. Verifies archive-like candidates from response metadata without retrieving archive bodies.
7. Exports resumable SQLite state, JSONL/CSV evidence, saved pages, and a Markdown handoff report.

## Install

Clone and install the command-line package:

```powershell
git clone https://github.com/ExperimentalSkid/Leakscan-.git
cd Leakscan-
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
Copy-Item .env.example .env
```

On macOS or Linux, activate with `source .venv/bin/activate`. API keys are optional and are read only from environment variables or `.env`.

## Quick start

Preview a case without making network requests:

```powershell
leakscan all --dry-run --case cases\example.yaml --output case_output
```

Run the catalog-first investigation:

```powershell
leakscan all --case cases\example.yaml --output case_output
```

Continue an existing investigation:

```powershell
leakscan all --resume --case cases\example.yaml --output case_output
```

`python -m leakscan` and `python leakscan.py` are equivalent entry points. Individual phases are `bootstrap`, `search`, `crawl`, `verify`, and `report`. Run `leakscan --help` for provider, depth, concurrency, timeout, rate, response-size, robots, and network-scope controls.

The repository also contains the real supplied seed job as a separate case example. Its details do not appear in the reusable crawler code or default settings.

## Case format

Copy `cases/example.yaml` and replace its values:

```yaml
case:
  name: investigation_reference
  seeds:
    - url: "https://public-catalog.example/information/item-id"
      source: public_catalog
      adapter: auto
  item_ids: ["item-id"]
  filenames: ["Example Dataset.7z"]
  reported_sizes: ["500 MB"]
  distinctive_phrases: ["Example Dataset"]
  aliases: ["Example_Dataset"]
  translated_descriptors: []
  exclusion_terms: []
```

`auto` invokes the generic structured-page adapter. Provider-specific catalog adapters can be added without changing case correlation or crawler logic.

## Discovery providers

- No key required: DuckDuckGo HTML, Common Crawl, Internet Archive CDX, urlscan public API, GitLab public search, and AlienVault OTX public indicator lookup.
- Optional credentials: Brave, Bing, Google Programmable Search, GitHub, urlscan, VirusTotal, and OTX.

A provider error or rate limit is isolated and recorded without stopping other providers. Search filtering is controlled by `search.safe_search` in the bundled defaults or a custom settings file; the default requests unfiltered results from providers that support that option.

To customize runtime behavior, copy `settings.example.yaml` and pass it with `--settings`:

```powershell
leakscan all --case cases\example.yaml --settings settings.example.yaml --output case_output
```

## Evidence and safety model

SQLite stores pending and visited URLs, provider queries, extracted pivots, relationships, domains, and observations. Relevant HTML/text pages are saved by SHA-256. Catalog metadata and archive response metadata are written under `evidence/metadata/`. The report phase regenerates CSV, JSONL, and Markdown artifacts.

Archive-like URLs use `HEAD`. If `HEAD` is unsupported, Leakscan sends a one-byte range request in streaming mode and closes it without consuming the body. Unexpected binary headers or signatures stop page retrieval immediately. Operators remain responsible for authorization, applicable law, provider terms, and handling sensitive evidence.

## Development

```powershell
python -m pip install -e ".[dev]"
ruff check .
pytest
python -m build
twine check dist\*
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/architecture.md](docs/architecture.md) for contributor, disclosure, and design guidance.

## License

Copyright (c) 2026 ExperimentalSkid. All rights reserved. See [LICENSE](LICENSE).
