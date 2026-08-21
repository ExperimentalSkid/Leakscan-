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
- `providers/` isolates search and public-index integrations.
- `search.py` applies a persistent strong-query budget, host-level throttling, request deduplication, immediate candidate verification, persisted rate-limit cooldowns, and per-provider circuit breakers.
- `crawler.py` manages the relevance-gated, bounded crawl queue.
- `parser.py` extracts reusable pivots from HTML and text.
- `scoring.py` correlates observations against the evolving fingerprint set.
- `verifier.py` records response metadata for archive-like candidates without consuming their bodies.
- `host_verifiers.py` maps recognized public file-host URLs to bounded metadata endpoints and normalizes stable object fields.
- `database.py` persists resumable state and evidence relationships.
- `reporting.py` exports analyst-facing artifacts.
- Candidate reporting merges observations by URL, retains the original detection point and latest verification point, and lets the latest direct existence check override historical index claims.

## Data boundary

Target identifiers live in case YAML files. Labelled sandbox/report artifacts also live in the case, and their hashes use a separate `artifact_hash` pivot type so they are never silently promoted to target payload hashes. Defaults control generic runtime behavior only. Investigation outputs, downloaded public HTML/text evidence, logs, API keys, and SQLite databases are ignored by Git.

## Crawl boundary

The queue is depth-limited, relevance-gated, deduplicated by canonical URL, and constrained by per-host throttling and configurable concurrency. Binary responses are rejected. Recognized host objects use public metadata APIs; other archive-like URLs use bodyless probes. Redirect destinations are revalidated against the public-network boundary. Robots rules use bounded retrieval and a 24-hour in-memory cache; server/network failures fail closed.

Host-native metadata can establish `LIVE_METADATA_ONLY`, `LIVE_RESTRICTED`, `TAKEN_DOWN`, or `DEAD`. Responsive HTML routes are explicitly `LISTING_LIVE` or `DOWNLOAD_ROUTE_LIVE`; neither establishes payload availability. Search/index observations alone remain `UNVERIFIED` and never establish live availability.
