# Project progress

Last updated: 2026-08-12

## Decisions

- Product and executable name: **Depdiff** / `depdiff`.
- npm package name: **`depdiff-audit`**. The unscoped `depdiff` name is occupied; a registry/search availability check on 2026-08-11 found no existing `depdiff-audit` package. Availability must be rechecked immediately before first publish.
- Runtime: TypeScript on supported Node.js 22+, with Node 24 as the development, container, package, and release default.
- Parser: Babel's JavaScript/TypeScript parser instead of native tree-sitter bindings for a portable one-command npm/Docker install. Lexical fallbacks preserve partial coverage for parser-resistant input.
- Registry security: tarball host must match configured registry host. Cross-host private-registry blobs are a documented v0.1 limitation; local tarballs are the workaround.
- Risk score: capped review-priority score, explicitly not a malware probability.
- Archive snapshots: scan all shipped tarball paths, while ergonomic default ignores remain limited to local working directories.
- CI distribution: Docker Action inputs are explicit, third-party Actions/base images are immutable, and release tags must match `package.json`.
- Repository state: the public source repository is `https://github.com/Dtdkvn/depdiff`, and source is the current distribution. This local checkout intentionally has no configured remote. The `depdiff-audit` npm package, `v0.1.0` tag, and first reviewed Action release are not published yet.

## v0.1 status

- [x] Secure npm/local acquisition and deterministic snapshot model
- [x] Differential static detectors with evidence and stable fingerprints
- [x] Policy, baseline, CI annotations, and exit semantics
- [x] HTML, JSON, SARIF, Markdown, and public TypeScript API
- [x] Docker, Compose, GitHub Action, CI/release workflows
- [x] Offline fixtures and test suite
- [x] Launch README, architecture, security, contributor, and reference docs
- [x] MIT license, public GitHub source, and package publication metadata (npm package and release tag still pending)

## Known follow-ups

- Recheck `depdiff-audit` npm ownership immediately before publishing.
- Add private-registry blob-host allowlists based on real user demand.
- Add native binary inspection adapters without changing the no-execution invariant.
- Benchmark detector precision against curated clean/malicious npm update pairs.
