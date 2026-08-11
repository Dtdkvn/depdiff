# Changelog

All notable changes use [Keep a Changelog](https://keepachangelog.com/) conventions and semantic versioning.

## [Unreleased]

### Fixed

- made the Docker Action conform to GitHub's Dockerfile/input contract and preserve policy thresholds;
- prevented archive-root/default-ignore, oversized-manifest, changed-binary, and baseline-fingerprint false negatives;
- validated redirects before requests, streamed registry metadata through its cap, and hardened strongest-digest verification;
- corrected workspace-aware SARIF/annotation paths, CLI exit codes, report sanitization, and concurrent output writes;
- pinned CI/container supply-chain inputs and added Action/distribution regression coverage.
- moved final containers to supported Node 24, upgraded Alpine packages, and removed unused global package-manager toolchains from runtime images.

## [0.1.0] - 2026-08-11

### Added

- npm registry, local tarball, and local directory comparisons;
- hardened same-origin acquisition, digest verification, bounded extraction, and symlink-safe traversal;
- differential capability, network destination, install script, binary, dependency, maintainer, provenance, entropy, minification, and inventory detectors;
- stable fingerprints, baseline suppression, YAML/JSON policy gates, and documented exit codes;
- standalone interactive HTML, deterministic JSON, SARIF 2.1.0, and Markdown reports;
- Docker/Compose workflow, Docker GitHub Action, CI/release workflows, fixtures, tests, and security documentation.

[Unreleased]: https://github.com/depdiff/depdiff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/depdiff/depdiff/releases/tag/v0.1.0
