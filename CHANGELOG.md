# Changelog

All notable changes to Leakscan are documented here.

## Unreleased

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
