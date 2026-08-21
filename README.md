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
6. Verifies recognized file-host objects through public metadata APIs and checks other archive-like candidates from response metadata without retrieving archive bodies.
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

On macOS or Linux, activate with `source .venv/bin/activate`. API keys are optional and are read only from environment variables or `.env`. `LEAKSCAN_CONTACT` adds an operator contact to the versioned HTTP User-Agent after control characters are removed.

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

The private repository also contains the real supplied seed job as a separate case example. Its details do not appear in the reusable crawler code or default settings. Do not make that case or its Git history public unless publishing those investigation details is intentional; use `cases/example.yaml` for public demonstrations.

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

- No key required: DuckDuckGo HTML, Common Crawl, Internet Archive CDX, urlscan public API, and AlienVault OTX public indicator lookup.
- Optional credentials: Brave, Bing, Google Programmable Search, GitHub, GitLab, urlscan, VirusTotal, and OTX.

A provider error or rate limit is isolated and recorded without stopping other providers. The per-host delay applies to provider APIs as well as crawling. Authentication failures open an immediate circuit breaker; rate limits honor `Retry-After` and establish a persisted cooldown; repeated connection or service failures disable that provider for the remainder of the run. Equivalent provider requests are sent once even when several filename variants map to the same API lookup.

Search filtering is controlled by `search.safe_search` in the bundled defaults or a custom settings file; the default requests unfiltered results from providers that support that option. Leakscan searches the exact supplied filename first, then every archive extension configured under `safety.archive_extensions`.

URLScan queries escape its reserved query-string characters and use the provider's remaining/reset headers to pause before another request would exceed quota. Compound and split archives such as `.tar.gz`, `.7z.001`, and `.part01.rar` are configurable alongside ordinary archive suffixes.

To customize runtime behavior, copy `settings.example.yaml` and pass it with `--settings`:

```powershell
leakscan all --case cases\example.yaml --settings settings.example.yaml --output case_output
```

## Evidence and safety model

SQLite stores pending and visited URLs, provider queries, extracted pivots, relationships, domains, and observations. Relevant HTML/text pages are saved by SHA-256. Catalog metadata and archive response metadata are written under `evidence/metadata/`. The report phase regenerates CSV, JSONL, and Markdown artifacts.

`candidate_urls.csv` contains one authoritative row per canonical candidate URL. `detection_points.csv` records where each candidate was first detected and how it was most recently verified: provider, exact query, provider record URL and ID, provider timestamp, verification method and endpoint, host object ID, verified filename/size/SHA-256, and local timestamps. Current direct observations override historical index records.

- `LIVE_METADATA_ONLY`: current file-like metadata was verified without retrieving the file body.
- `LIVE_RESTRICTED`: host-native metadata confirms the object, but access is restricted.
- `TAKEN_DOWN`: the host reports legal/abuse removal or returned HTTP 451.
- `HISTORICAL_DEAD`: an index recorded the candidate and its current direct check is 404/410.
- `CURRENT_REFERENCE_ONLY`, `UNVERIFIED`, and `BLOCKED`: never claims that a live file was confirmed.

Pixeldrain `/u/{id}` candidates are verified through the documented `/api/file/{id}/info` endpoint. Leakscan preserves stable object metadata while reading no archive bytes. Other hosts continue to use bodyless `HEAD` or one-byte range probes.

Archive-like URLs use `HEAD`. If `HEAD` is unsupported, Leakscan sends a one-byte range request in streaming mode and closes it without consuming the body. Unexpected binary headers or signatures stop page retrieval immediately. Robots rules are cached for at most 24 hours; robots server/network failures fail closed. Operators remain responsible for authorization, applicable law, provider terms, and handling sensitive evidence.

Generated SQLite state, logs, findings, reports, and evidence are ignored by the repository's standard output patterns. Keep sensitive cases and outputs outside a source checkout whenever possible, and inspect `git status` before every commit.

## Development

```powershell
python -m pip install -e ".[dev]"
ruff check .
pytest
python -m pip_audit --local
python -m build
twine check dist\*
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/architecture.md](docs/architecture.md) for contributor, disclosure, and design guidance.

## License

Copyright (c) 2026 ExperimentalSkid. All rights reserved. See [LICENSE](LICENSE).
