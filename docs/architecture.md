# Architecture and trust boundaries

Depdiff is a static differential analyzer. Its central invariant is simple: **the target package is untrusted data and must never become executable input to Node.js, a shell, npm, or a report renderer.**

## Data flow

```mermaid
flowchart TB
  subgraph Untrusted
    R["Registry metadata + tarball"]
    T["Local tarball"]
    F["Local directory"]
  end
  subgraph Acquisition
    V["Origin + digest validation"]
    G["Archive preflight and limits"]
    X["Disposable extraction"]
  end
  subgraph Analysis
    N["Normalized package snapshot"]
    I["Inventory + metadata diff"]
    A["AST and lexical signals"]
    H["Entropy / binary heuristics"]
  end
  subgraph Decision
    D["Evidence-backed findings"]
    B["Baseline suppression"]
    P["Policy evaluation"]
  end
  subgraph Output
    O["HTML / JSON / SARIF / Markdown"]
  end
  R --> V --> G --> X --> N
  T --> G
  F --> N
  N --> I --> D
  N --> A --> D
  N --> H --> D
  D --> B --> P --> O
```

## Acquisition

Registry specifiers resolve through one configured HTTPS origin. Depdiff strips credentials from the configured URL, rejects non-HTTPS registries, follows redirects only when the final URL remains on the same host, and requires the tarball host to match. This is intentionally strict to reduce SSRF and redirect risk. Private registries that use a separate blob host are not supported in v0.1; download the tarball separately and scan it locally instead.

Downloaded tarballs are cached by their integrity identity. When the registry supplies `dist.integrity`, Depdiff verifies the strongest supported SHA digest; otherwise it verifies `dist.shasum` when present.

Archive processing uses two passes. The first validates every path, entry type, declared size, total size, count, and decompression ratio; validation failure aborts the parser immediately. Absolute paths, drive paths, `..`, symbolic/hard links, devices, FIFOs, and other special entries are rejected. The second extracts regular files/directories into a random temporary directory with path preservation disabled. The directory is removed in a `finally` block.

Local directories are traversed with `lstat`/`realpath` containment checks. Symlinks are fingerprinted but not followed. `.git`, `node_modules`, and Depdiff output/cache directories are ignored by default.

## Snapshot and analysis

Each file has a relative path, size, mode, kind, and SHA-256. Only bounded files are kept in memory for content analysis. `package.json` is parsed as data with defensive normalization; target dependencies are never installed.

Source analyzers combine Babel AST parsing with conservative lexical fallbacks. They profile capability sets and literal network hosts for both versions, then report capabilities or hosts that occur only in the candidate version. Inventory, script, dependency, maintainer, registry provenance, entropy, minification, and binary detectors operate directly on the normalized delta.

Fingerprints hash the package name, rule, and semantic identity rather than timestamps, absolute source roots, or report ordering. They remain deterministic for the same inputs, cannot accidentally cross-suppress another package, and power baselines.

## Decision model

Findings carry an explicit score contribution. Scores sum to a capped 0–100 queue-priority number. Baseline findings remain visible but do not contribute to current risk. Policy evaluates the remaining findings plus structural limits such as added file/dependency counts.

The score is not a probability and Depdiff does not call packages malicious. Severity communicates review urgency for a newly acquired capability.

## Output safety

JSON and SARIF are generated from plain data objects. Markdown escapes syntax-bearing characters. HTML escapes all package-controlled values in markup and Unicode-escapes `<`, `>`, `&`, and script-separator characters in embedded JSON. CSS and JavaScript are inline, so the report has no third-party runtime dependency and can be archived as one file.

## Known limits

- Static analysis cannot reliably resolve destinations, modules, or commands assembled at runtime.
- Babel parse failure falls back to lexical signals; it can reduce coverage.
- Native binaries are inventoried and hashed, not disassembled.
- Minified and generated code is flagged but not automatically deobfuscated.
- Package-level comparison does not recursively download or analyze newly added dependencies.
- Registry maintainer metadata may be incomplete or differ from `package.json`.
- A clean result means no configured heuristic found a new signal; it is not proof of safety.
