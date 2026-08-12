# Changelog

All notable changes use [Keep a Changelog](https://keepachangelog.com/) conventions and semantic versioning.

## [Unreleased]

### Fixed

- flags shipped dependencies that switch from registry versions to Git, URL, archive, workspace, or local paths, and flags later changes between those external sources;
- validates every snapshot and inventory file shape in the public report schema, and preserves policy configuration warnings in SARIF execution notifications;
- marks synthetic native-Windows and Windows-backed Docker Desktop 9p bind modes unknown while preserving authoritative tar-header modes and real executable transitions;
- added a labeled detector benchmark with integrity-pinned benign releases, a human-vetted Datadog compromise sample, synthetic evasive cases, and enforced precision/recall/false-positive thresholds;
- raised non-registry runtime dependencies to a dedicated high-severity finding and warned when `maxRiskScore` is configured without an explicit severity threshold;
- made installed-tarball smoke tests exercise the actual `.bin` artifact on Windows and POSIX on every supported Node runtime;
- ran the audit when the CLI is invoked through the installed `node_modules/.bin/depdiff` symlink, which previously exited 0 without analyzing anything, and made the packaged smoke test exercise that entry point;
- failed closed when shipped code cannot be analyzed, instead of scoring it as clean: files are now classified by manifest entry point, shebang, and content rather than by extension alone, oversized and control-byte-heavy files keep a classifiable prefix, and a parse failure reports the lost coverage without discarding lexical capabilities;
- resolved module loads reached through `require` aliases, member-expression loaders such as `process.mainModule.require` and `module.constructor._load`, computed loader properties, aliased code constructors, and statically foldable module names, so the real capability and severity are reported;
- stopped capability names inside comments and string literals in the previous version from suppressing the same capability in the new one;
- recorded internationalized URL hosts so homoglyph destinations raise a domain finding and `denyDomains` can match them;
- replaced every locale-sensitive comparison with a byte-ordered one, so sort order, fingerprints, and report bytes no longer depend on the host locale;
- made the Docker Action conform to GitHub's Dockerfile/input contract and preserve policy thresholds;
- prevented archive-root/default-ignore, oversized-manifest, changed-binary, and baseline-fingerprint false negatives;
- validated redirects before requests, streamed registry metadata through its cap, and hardened strongest-digest verification;
- corrected workspace-aware SARIF/annotation paths, CLI exit codes, report sanitization, and concurrent output writes;
- pinned CI/container supply-chain inputs and added Action/distribution regression coverage;
- moved final containers to supported Node 24, upgraded Alpine packages, and removed unused global package-manager toolchains from runtime images;
- dropped Node 20, with maintained Node 22/24 CI coverage and Node 24 package/release defaults;
- made tagged releases prove main-branch ancestry, pack once, publish the verified tarball, and fail closed on registry shasum mismatches;
- shipped linked documentation, assets, and examples in the npm tarball with installed-package and local-link smoke tests.

## [0.1.0] - 2026-08-11

### Added

- npm registry, local tarball, and local directory comparisons;
- hardened same-origin acquisition, digest verification, bounded extraction, and symlink-safe traversal;
- differential capability, network destination, install script, binary, dependency, maintainer, provenance, entropy, minification, and inventory detectors;
- stable fingerprints, baseline suppression, YAML/JSON policy gates, and documented exit codes;
- standalone interactive HTML, deterministic JSON, SARIF 2.1.0, and Markdown reports;
- Docker/Compose workflow, Docker GitHub Action, CI/release workflows, fixtures, tests, and security documentation.

[Unreleased]: https://github.com/Dtdkvn/depdiff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dtdkvn/depdiff/releases/tag/v0.1.0
