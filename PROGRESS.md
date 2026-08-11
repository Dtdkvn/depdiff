# Project progress

Last updated: 2026-08-12

## Decisions

- Product and executable name: **Depdiff** / `depdiff`.
- npm package name: **`depdiff-audit`**. The unscoped `depdiff` name is occupied; a registry/search availability check on 2026-08-11 found no existing `depdiff-audit` package. Availability must be rechecked immediately before first publish.
- Runtime: TypeScript on Node.js 20.12+, with a pure static-analysis target model.
- Parser: Babel's JavaScript/TypeScript parser instead of native tree-sitter bindings for a portable one-command npm/Docker install. Lexical fallbacks preserve partial coverage for parser-resistant input.
- Registry security: tarball host must match configured registry host. Cross-host private-registry blobs are a documented v0.1 limitation; local tarballs are the workaround.
- Risk score: capped review-priority score, explicitly not a malware probability.
- Archive snapshots: scan all shipped tarball paths, while ergonomic default ignores remain limited to local working directories.
- CI distribution: Docker Action inputs are explicit, third-party Actions/base images are immutable, and release tags must match `package.json`.

## v0.1 status

- [x] Secure npm/local acquisition and deterministic snapshot model
- [x] Differential static detectors with evidence and stable fingerprints
- [x] Policy, baseline, CI annotations, and exit semantics
- [x] HTML, JSON, SARIF, Markdown, and public TypeScript API
- [x] Docker, Compose, GitHub Action, CI/release workflows
- [x] Offline fixtures and test suite
- [x] Launch README, architecture, security, contributor, and reference docs
- [x] MIT license and package publication metadata

## Known follow-ups

- Recheck `depdiff-audit` npm ownership immediately before publishing.
- Add private-registry blob-host allowlists based on real user demand.
- Add native binary inspection adapters without changing the no-execution invariant.
- Benchmark detector precision against curated clean/malicious npm update pairs.
