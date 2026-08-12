# Detector precision benchmark

`npm run benchmark:precision` runs the checked-in, deterministic labeled fixtures with `--offline`. `npm run benchmark:precision:registry` also downloads the exact real npm releases and the human-vetted Datadog compromise sample named in `benchmark/precision-corpus.json`.

The registry corpus pins every version's official `dist.integrity` SHA-512 value. The runner verifies that the registry metadata still advertises the reviewed digest, and Depdiff independently verifies the downloaded tarball before analysis. The malicious sample pins the Datadog dataset commit, manifest SHA-256, sample path, and encrypted-ZIP SHA-256. A small Python standard-library helper validates archive paths/types/limits and extracts only into a temporary directory. Target package code is never installed, imported, compiled, or executed.

## Ground truth and metrics

- `alert` means the candidate intentionally adds a security-relevant capability and must produce every `expectedRules` entry.
- `clean` means a human-reviewed ordinary release pair should produce no high/critical alert. Low and medium review signals remain visible but do not count as a malicious verdict.
- Precision, recall, and false-positive rate are computed per package pair, with `high` as the alert boundary.
- The gate requires precision at least 0.80, recall 1.00, and false-positive rate at most 0.20.

The five clean registry pairs span small CommonJS and ESM utilities with code, metadata, packaging, and major-version changes. One compromised real release pair uses `jest-date-mock@1.0.10` as the registry-pinned predecessor and `1.0.11` from Datadog's Apache-2.0 dataset, whose maintainers state that every sample is manually triaged. The three local hostile transformations cover lifecycle/exfiltration, obfuscated module loading/dynamic code, and binary/executable transitions.

These are reported as three distinct evidence groups: real benign release pairs, a vetted real malicious sample paired with its clean predecessor, and synthetic regression transformations. The corpus is intentionally small and selection-biased; it is a release regression gate, not a market-wide accuracy estimate.

To refresh a pinned pair, review its source diff, update both exact versions and SHA-512 values, then run the registry benchmark through a trusted TLS connection. Never disable TLS verification to update the corpus.
