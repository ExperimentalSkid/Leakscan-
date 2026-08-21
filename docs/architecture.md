# Architecture

Leakscan separates investigation data from reusable crawling logic.

```text
case YAML
   |
   v
catalog bootstrap --> normalized observations --> fingerprint expansion
                                                |
                                                v
provider searches --> candidate URLs --> bounded crawler --> new pivots
                                                |
                                                v
                                      metadata-only verifier
                                                |
                                                v
                              SQLite + JSONL/CSV/Markdown evidence
```

## Main components

- `config.py` loads and validates case and runtime settings.
- `catalogs.py` parses public listing pages into normalized observations.
- `providers/` isolates search and public-index integrations.
- `crawler.py` manages the relevance-gated, bounded crawl queue.
- `parser.py` extracts reusable pivots from HTML and text.
- `scoring.py` correlates observations against the evolving fingerprint set.
- `verifier.py` records response metadata for archive-like candidates without consuming their bodies.
- `database.py` persists resumable state and evidence relationships.
- `reporting.py` exports analyst-facing artifacts.

## Data boundary

Target identifiers live in case YAML files. Defaults control generic runtime behavior only. Investigation outputs, downloaded public HTML/text evidence, logs, API keys, and SQLite databases are ignored by Git.

## Crawl boundary

The queue is depth-limited, relevance-gated, deduplicated by canonical URL, and constrained by per-host throttling and configurable concurrency. Binary responses are rejected. Archive-like URLs are sent to the metadata-only verifier instead of the page-body fetch path.
