# Leakscan

[![CI](https://github.com/ExperimentalSkid/Leakscan-/actions/workflows/ci.yml/badge.svg)](https://github.com/ExperimentalSkid/Leakscan-/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Leakscan is a catalog-first OSINT crawler for discovering, correlating, verifying, and preserving evidence of public references and publicly accessible locations associated with a specified file or archive.

The engine contains no organization-specific target logic. Identifiers, filenames, sizes, phrases, aliases, and seed listings come from the case YAML supplied with `--case`. Restrictions such as domain allowlists, deny lists, and exclusion terms are optional controls, not baked-in targets.

## What it does

1. Visits configured public catalog or listing pages first.
2. Extracts displayed IDs, filenames, sizes, hashes, dates, accounts, fields, and links.
3. Expands the case fingerprint with newly observed identifiers.
4. Searches independent public sources and immediately verifies each newly unique candidate before continuing.
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

Use the broad discovery profile when maximum public-index coverage is more important than run time:

```powershell
leakscan all --search-profile broad --case cases\example.yaml --output case_output
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
  actor_aliases: []
  incident_terms: []
  public_channels: []
  exclusion_terms: []
  artifacts:
    - source: public_sandbox
      artifact_type: html_page_artifact
      subject_url: "https://public-catalog.example/information/item-id"
      report_url: "https://analysis.example/report/id"
      observed_at: "2026-01-01T00:00:00Z"
      hashes:
        - algorithm: sha256
          value: "page-artifact-hash"
      notes: "Hash identifies the HTML/report artifact, not the target archive."
```

`auto` invokes the generic structured-page adapter. Provider-specific catalog adapters can be added without changing case correlation or crawler logic. Optional `actor_aliases` and `incident_terms` expand event-focused searches. `public_channels` accepts only explicitly configured public Telegram preview URLs; it never selects channels on its own or downloads attachments. Optional `artifacts` entries preserve known sandbox/report provenance and keep page, URL-shortcut, and related-analysis hashes separate from archive payload hashes.

## Discovery providers

- No key required: DuckDuckGo HTML, Common Crawl, Internet Archive CDX, Internet Archive item search and file manifests, Arquivo.pt full-text history, GDELT global news, urlscan public search, explicitly configured public Telegram previews, Hugging Face Hub metadata, Kaggle public dataset metadata, GitLab public release/package metadata, and AlienVault OTX public indicator lookup.
- Optional credentials or operator endpoint: Google Programmable Search, Mojeek, SearXNG, GitHub code and release assets, authenticated GitLab search, Hybrid Analysis, LeakIX, urlscan, VirusTotal, OTX, Hugging Face, and Kaggle. A free urlscan account key enables bounded Result API request-graph metadata. Hugging Face and Kaggle can inspect public records without credentials but accept `HF_TOKEN` or `KAGGLE_USERNAME`/`KAGGLE_KEY` for authenticated quota.

The provider names are `duckduckgo`, `commoncrawl`, `archive_org`, `archive_org_items`, `archive_org_files`, `arquivo_pt`, `gdelt`, `urlscan`, `telegram_public`, `google`, `mojeek`, `searxng`, `github`, `github_releases`, `gitlab`, `gitlab_assets`, `huggingface`, `kaggle`, `hybrid_analysis`, `leakix`, `virustotal`, and `otx`. Use repeated `--provider NAME` options to run a subset. Brave is not included. The legacy `bing` adapter remains discoverable only to explain that Microsoft retired the Bing Search APIs on 11 August 2025; it is disabled and is no longer in the default provider list.

`SEARXNG_URL` must point to an instance controlled or explicitly selected by the operator; Leakscan never chooses a random public instance. `SEARXNG_BEARER_TOKEN` is optional. Mojeek uses `MOJEEK_API_KEY`, Hybrid Analysis uses `HYBRID_ANALYSIS_API_KEY`, and LeakIX uses `LEAKIX_API_KEY`. Hybrid Analysis performs only the documented filename/hash search operations, never invokes submission or sample-download endpoints, and enforces a 12-second minimum interval between searches for the restricted-key quota. LeakIX searches the `leak` scope and emits only web-service URLs that can receive the same bounded current-existence check as other candidates.

A provider error or rate limit is isolated and recorded without stopping other providers. The per-host delay applies to provider APIs as well as crawling. Authentication failures open an immediate circuit breaker; rate limits honor `Retry-After` and establish a persisted cooldown; repeated connection or service failures disable that provider for the remainder of the run. Equivalent provider requests are sent once even when several filename variants map to the same API lookup.

Discovery is broad and filtering is strict. Request budgets are enforced at the HTTP boundary: every search page, manifest lookup, repository lookup, and failed request attempt counts, rather than treating a multi-request query as one request. The balanced defaults allow up to 60 actual requests per provider across pivot rounds and resumes, guarantee a 45-request discovery floor where the provider supports that many distinct searches, and then stop a provider after 10 consecutive query groups find no new canonical URL. `--search-profile focused`, `balanced`, and `broad` select ceilings/floors/stale windows/result-page depths of `15/15/5/1`, `60/45/10/3`, and `120/60/20/5`. `--max-provider-requests` overrides the ceiling, zero disables that ceiling, and `--max-result-pages-per-query` overrides native pagination depth. A query interrupted by the hard request ceiling remains pending for a later run with additional budget. Provider rate-limit headers, cooldowns, failure circuits, per-host delays, and the global crawl bounds remain authoritative.

Search filtering is controlled by `search.safe_search` in the bundled defaults or a custom settings file; the default requests unfiltered results from providers that support that option. Leakscan starts with exact filenames, filename slugs, object IDs, and every configured archive-extension mutation, then expands through labelled hashes, known URLs, phrases, aliases, sizes, intent terms, and discovered pivots. A source-aware planner classifies those queries and sends only useful shapes to native indexes: archives receive filenames/URLs/IDs, news receives phrases and incident terms, sandboxes receive filenames/hashes, and repository catalogs receive filenames, IDs, and descriptive phrases. General web engines still receive the broad set. URLScan skips bare hash searches because its selected fields cover URLs and page titles rather than file metadata.

Catalog providers never download file bodies. Internet Archive manifests emit the item identifier, exact filename, size, format, and published MD5/SHA-1 values. Hugging Face emits repository, revision, file path, size, and LFS/blob metadata from Hub API responses. Kaggle emits public dataset and file-list metadata. GitHub and GitLab asset providers retain the repository/project, release or package identifier, filename, size, and available digest fields as the detection point. Any asset-like URL is still passed through Leakscan's normal bodyless verification boundary before it can receive a current-live classification.

URLScan queries escape its reserved query-string characters and search requested-URL metadata in addition to page/task URLs and titles. When `URLSCAN_API_KEY` is configured, Leakscan reads a bounded number of Result API HTTP-transaction records and extracts only correlated URL, status, MIME, filename, size, and response-hash metadata; it never requests stored response or file bodies. Public Telegram monitoring reads only case-configured `t.me/s/...` previews, preserves matching post provenance and outgoing links, and records attachment names/sizes without retrieving attachments. Compound, split, disk-image, and less-common archive forms such as `.tar.zst`, `.7z.001`, `.zip.001`, `.part1.rar`, `.cab`, and `.iso` are configurable alongside ordinary archive suffixes.

To customize runtime behavior, copy `settings.example.yaml` and pass it with `--settings`:

```powershell
leakscan all --case cases\example.yaml --settings settings.example.yaml --output case_output
```

## Evidence and safety model

SQLite stores pending and visited URLs, provider queries, extracted pivots, relationships, domains, and observations. Relevant HTML/text pages are saved by SHA-256. Catalog metadata and archive response metadata are written under `evidence/metadata/`. The report phase regenerates CSV, JSONL, and Markdown artifacts.

`candidate_urls.csv` contains one authoritative row per canonical, case-correlated target candidate URL. `detection_points.csv` records where each candidate was first detected and how it was most recently verified: provider, exact query, provider record URL and ID, provider timestamp, verification method and endpoint, host object ID, verified filename/size/SHA-256, and local timestamps. Current direct observations override historical index records. `artifact_references.csv` separately records operator-labelled sandbox, URL-shortcut, and analysis references. `supporting_references.csv` records provider-discovered news and analysis pages. Both reference classes can yield tightly correlated outgoing links, but neither inflates target candidate or live-file counts.

Fragments and non-root trailing slashes are removed for candidate deduplication. Console output uses `[NEW]` only for the first canonical URL; repeated provider records are retained as evidence but summarized as duplicate observations. `hashes.csv` includes an `artifact_type` column so sandbox HTML and URL-shortcut hashes cannot silently become payload hashes.

A URL ending in an archive extension is not sufficient target evidence. The crawler follows an archive or action link only when the URL/nearby context correlates with case fingerprints, or when a target-correlated non-artifact page exposes a download/mirror action. This prevents sandbox runtime dependencies and generic CDN packages from being reported as live target files.

- `LIVE_METADATA_ONLY`: current file-like metadata was verified without retrieving the file body.
- `LIVE_RESTRICTED`: host-native metadata confirms the object, but access is restricted.
- `TAKEN_DOWN`: the host reports legal/abuse removal or returned HTTP 451.
- `HISTORICAL_DEAD`: an index recorded the candidate and its current direct check is 404/410.
- `LISTING_LIVE`: a host information/listing page responds, without proving the archive is live.
- `DOWNLOAD_ROUTE_LIVE`: a download-labelled HTML route responds, but no file metadata was established.
- `CURRENT_REFERENCE_ONLY`, `UNVERIFIED`, and `BLOCKED`: never claims that a live file was confirmed.

Pixeldrain `/u/{id}` candidates are verified through the documented `/api/file/{id}/info` endpoint. Leakscan preserves stable object metadata while reading no archive bytes. BiteBlob information/download pages that explicitly say an object was reported for abuse, is unauthorized, or has no download available are classified `TAKEN_DOWN` even when the informational HTML still returns HTTP 200. Other hosts continue to use bodyless `HEAD` or one-byte range probes.

Archive-like URLs use `HEAD`. If `HEAD` is unsupported, Leakscan sends a one-byte range request in streaming mode and closes it without consuming the body. Malformed HTTP/2 protocol/body responses receive one HTTP/1.1 fallback attempt, and every candidate is isolated so one non-compliant server cannot terminate the whole run. Unexpected binary headers or signatures stop page retrieval immediately. Robots rules are cached for at most 24 hours; robots server/network failures fail closed. Operators remain responsible for authorization, applicable law, provider terms, and handling sensitive evidence.

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
