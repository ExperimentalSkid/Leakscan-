# Architecture

Leakscan separates investigation data from reusable crawling logic.

```text
case YAML
   |
   v
catalog bootstrap --> normalized observations --> fingerprint expansion
                                                |
                                                v
provider search --new canonical URL--> immediate bounded crawler/verifier
      ^                                         |
      |                                         v
      +------------------------- labelled new pivots
                                                |
                                                v
                              SQLite + JSONL/CSV/Markdown evidence
```

## Main components

- `config.py` loads and validates case and runtime settings.
- `catalogs.py` parses public listing pages into normalized observations.
- `providers/` isolates general web search, web archives, uploaded-item/file manifests, dataset hubs, release/package assets, global news, case-configured public channel previews, code search, sandbox metadata, and public-exposure indexes.
- `search.py` classifies queries by provider capability and applies native pagination, HTTP-boundary request accounting, an adaptive ceiling and plateau detector, host-level throttling, request deduplication, immediate candidate verification, persisted rate-limit cooldowns, and per-provider circuit breakers.
- `crawler.py` manages the bounded crawl queue and requires case correlation before following generic archive links.
- `parser.py` extracts reusable pivots from HTML and text.
- `scoring.py` correlates observations against the evolving fingerprint set.
- `verifier.py` records response metadata for archive-like candidates without consuming their bodies.
- `host_verifiers.py` maps recognized public file-host URLs to bounded metadata endpoints and normalizes stable object fields.
- `database.py` persists resumable state and evidence relationships.
- `reporting.py` exports analyst-facing artifacts.
- Candidate reporting merges observations by URL, retains the original detection point and latest verification point, and lets the latest direct existence check override historical index claims. Labelled artifacts and provider-discovered supporting references are exported separately from target candidates.

## Data boundary

Target identifiers live in case YAML files. Labelled sandbox/report artifacts also live in the case, and their hashes use a separate `artifact_hash` pivot type so they are never silently promoted to target payload hashes. Defaults control generic runtime behavior only. Investigation outputs, downloaded public HTML/text evidence, logs, API keys, and SQLite databases are ignored by Git.

Provider results can carry a `reference_kind`. That provenance is persisted in the resumable URL queue and copied to direct-fetch observations. Supporting news and analysis pages remain searchable evidence and may expose case-correlated links, but are excluded from target-candidate counts and exported through `supporting_references.csv`. Analysis-artifact pages cannot promote extracted hashes or generic download actions into target pivots.

Every actual provider HTTP request passes through a persistent request meter before transmission. Multi-page searches and N+1 manifest lookups therefore consume their real cost. Providers stop at the configured native page depth, return partial batches when the hard request ceiling is reached, and leave interrupted queries pending. File-catalog adapters emit compact record metadata into the detection point; they do not call resolver, dataset-download, sample-download, or package-download operations.

## Crawl boundary

The queue is depth-limited, relevance-gated, deduplicated by canonical URL, and constrained by per-host throttling and configurable concurrency. Broad provider observations are preserved, while archive/action links require case correlation before traversal. Binary responses are rejected. Recognized host objects use public metadata APIs; other correlated archive-like URLs use bodyless probes. Redirect destinations are revalidated against the public-network boundary. Robots rules use bounded retrieval and a 24-hour in-memory cache; server/network failures fail closed.

Host-native metadata can establish `LIVE_METADATA_ONLY`, `LIVE_RESTRICTED`, `TAKEN_DOWN`, or `DEAD`. Explicit host HTML notices that an object is unauthorized, abuse-reported, or unavailable for download can also establish `TAKEN_DOWN` while preserving the live reference page. Other responsive HTML routes are explicitly `LISTING_LIVE` or `DOWNLOAD_ROUTE_LIVE`; neither establishes payload availability. Search/index observations alone remain `UNVERIFIED` and never establish live availability. Malformed HTTP/2 responses receive one HTTP/1.1 fallback attempt, and unexpected per-candidate exceptions are recorded without terminating the remaining queue.
