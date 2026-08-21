# Changelog

All notable changes to Leakscan are documented here.

## Unreleased

- Removed Brave from the provider registry, defaults, examples, and credential template.
- Added case-scoped public Telegram preview monitoring that records matching posts, attachment metadata, and outgoing links without downloading attachments.
- Added actor aliases and incident terms as generic case fingerprints and combined actor/target queries.
- Added authenticated urlscan Result API request-graph metadata with bounded free-account lookups and no stored-response retrieval.
- Classified explicit BiteBlob abuse/unauthorized/no-download notices as `TAKEN_DOWN` even when the listing HTML returns 200.
- Added HTTP/1.1 fallback for malformed HTTP/2 responses and per-candidate exception isolation.
- Treated Common Crawl 404 responses as empty capture sets and corrected Kaggle's public dataset sort parameter.
- Counted and enforced provider budgets at the actual HTTP-request boundary, including pagination and manifest lookups.
- Added bounded native pagination with focused/balanced/broad depths of one, three, and five result pages.
- Added source-aware query capabilities so archives, news, sandboxes, exposure indexes, and repository catalogs receive useful query shapes instead of every global mutation.
- Added metadata-only Internet Archive file manifests, Hugging Face repositories/files, Kaggle dataset files, GitHub release assets, and GitLab release/package files with file-level detection points.
- Disabled the retired Bing Search API adapter and removed it from default discovery.
- Replaced broad single-word archive-index fallbacks with full phrase, slug, URL, hash, or object-ID fingerprints.
- Replaced the fixed 15-request cap with adaptive broad discovery: a 60-request balanced ceiling, a 45-request floor, plateau stopping, and focused/balanced/broad CLI profiles.
- Moved every configured archive-extension mutation into the discovery floor while retaining provider-level equivalent-request deduplication.
- Added immediate verification of newly unique candidates and suppressed duplicate `[FOUND]` console noise.
- Canonicalized trailing-slash URL variants and added explicit listing/download-route states.
- Added labelled ANY.RUN/Hybrid Analysis artifact pivots that remain distinct from payload hashes.
- Separated labelled sandbox/analysis references from target candidates and rejected generic archive dependencies that have no case correlation.
- Added Arquivo.pt full-text history, Internet Archive uploaded-item metadata, and GDELT global-news discovery without requiring API keys.
- Added opt-in Mojeek, operator-configured SearXNG, Hybrid Analysis metadata-only search, and LeakIX public-exposure search providers.
- Persisted provider reference provenance across resumes and exported provider-discovered news/analysis pages separately in `supporting_references.csv` so they cannot inflate target candidate counts.

## 1.1.0 - 2026-08-21

- Applied the configured per-host delay to search-provider HTTP requests.
- Added provider circuit breakers for access denial, rate limits, and repeated failures.
- Added persisted `Retry-After` cooldowns and provider-request deduplication.
- Retained all configured archive extensions while prioritizing the supplied filename and extension.
- Added current existence states that never label index-only or HTML-only evidence as a live file.
- Consolidated candidates by URL so current direct checks override historical observations.
- Added provider, query, record, and timestamp detection points to reports and CSV exports.
- Made GitLab search require an explicit `GITLAB_TOKEN` instead of repeatedly issuing unauthorized requests.
- Added Pixeldrain host-native metadata verification for object ID, filename, exact size, MIME type, SHA-256, availability, and abuse status without reading file content.
- Added explicit `LIVE_RESTRICTED` and `TAKEN_DOWN` states and verification-point exports.
- Added URLScan query escaping and proactive quota cooldowns from its published rate-limit headers.
- Made robots.txt server/network failures fail closed, followed safe redirects, bounded parsing, and added a 24-hour cache lifetime.
- Expanded default compound and split-archive suffixes.
- Hardened CI with immutable action pins, dependency consistency checks, and dependency auditing.
- Added broader generated-evidence ignore rules and a single authoritative package version.

## 1.0.0 - 2026-08-21

- Added a reusable catalog-first public-reference crawler.
- Added generic catalog extraction and fingerprint expansion.
- Added multi-provider search, recursive HTML/text crawling, and resumable SQLite state.
- Added metadata-only verification for archive-like candidates.
- Added JSONL, CSV, saved-page, metadata, and Markdown reporting outputs.
- Added a generic example case and a separate real-job case.
- Added a packaged CLI, test suite, and GitHub Actions validation.
