# Project progress

Last updated: 2026-08-12

## Decisions

- Product and executable name: **Depdiff** / `depdiff`.
- npm package name: **`depdiff-audit`**. The unscoped `depdiff` name is occupied; `depdiff-audit@0.1.0` is now published with npm provenance.
- Runtime: TypeScript on supported Node.js 22+, with Node 24 as the development, container, package, and release default.
- Parser: Babel's JavaScript/TypeScript parser instead of native tree-sitter bindings for a portable one-command npm/Docker install. Lexical fallbacks preserve partial coverage for parser-resistant input.
- Registry security: tarball host must match configured registry host. Cross-host private-registry blobs are a documented v0.1 limitation; local tarballs are the workaround.
- Risk score: capped review-priority score, explicitly not a malware probability.
- Archive snapshots: scan all shipped tarball paths, while ergonomic default ignores remain limited to local working directories.
- CI distribution: Docker Action inputs are explicit, third-party Actions/base images are immutable, and release tags must match `package.json`.
- Repository state: the public source repository is `https://github.com/Dtdkvn/depdiff`, `main` tracks `origin/main`, and `v0.1.0` is live as an npm package, GitHub release, and reviewed Action tag. The npm registry `dist.shasum` is `dbbe8cfd97f81f114c18fa8db670904734faa155`.
- Release authentication: the bootstrap token is revoked, the GitHub `npm` environment has no `NPM_TOKEN`, and the workflow has no token fallback. It is OIDC-only and will fail closed at `npm publish` until the npm account completes 2FA/confirmation and registers the trusted publisher.

## v0.1 status

- [x] Secure npm/local acquisition and deterministic snapshot model
- [x] Differential static detectors with evidence and stable fingerprints
- [x] Policy, baseline, CI annotations, and exit semantics
- [x] HTML, JSON, SARIF, Markdown, and public TypeScript API
- [x] Docker, Compose, GitHub Action, CI/release workflows
- [x] Offline fixtures and test suite
- [x] Launch README, architecture, security, contributor, and reference docs
- [x] MIT license, public GitHub source, npm package with provenance, GitHub release, and reviewed `v0.1.0` Action tag

## Known follow-ups

- Complete npm publisher-account 2FA/confirmation, then register `Dtdkvn/depdiff`, `release.yml`, and environment `npm` as the trusted publisher before creating the next release tag.
- Add private-registry blob-host allowlists based on real user demand.
- Add native binary inspection adapters without changing the no-execution invariant.
- Expand detector precision benchmarking beyond the current selection-biased 10-case corpus.
