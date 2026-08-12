# Changelog

All notable changes use [Keep a Changelog](https://keepachangelog.com/) conventions and semantic versioning.

## [Unreleased]

### Fixed

- ran the audit when the CLI is invoked through the installed `node_modules/.bin/depdiff` symlink, which previously exited 0 without analyzing anything, and made the packaged smoke test exercise that entry point;
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

[Unreleased]: https://github.com/yewud/depdiff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yewud/depdiff/releases/tag/v0.1.0
