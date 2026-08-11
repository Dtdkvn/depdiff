# CLI reference

## `depdiff compare <before> <after>`

Each input may be:

- an npm registry specifier (`name@1.2.3`, `@scope/name@2.0.0`, or a dist-tag);
- an existing `.tgz`, `.tar.gz`, or `.tar` file;
- an existing local directory.

Local inputs are checked before interpreting a value as a registry specifier.

| Option | Default | Description |
|---|---|---|
| `-o, --output <file>` | `depdiff-report.html` | Standalone HTML report |
| `--json <file>` | — | Stable JSON report |
| `--markdown <file>` | — | Human-readable Markdown report |
| `--sarif <file>` | — | SARIF 2.1.0 report |
| `--stdout <format>` | `summary` | `summary`, `json`, `markdown`, or `sarif` |
| `--offline` | false | Reject registry inputs and perform no network requests |
| `--deterministic` | false | Use `SOURCE_DATE_EPOCH`, or Unix epoch when unset |
| `--ci` | false | Emit GitHub annotations and default `--fail-on high` |
| `--no-fail` | false | Exit zero after any completed audit |
| `--fail-on <severity>` | policy / never | Override the severity gate |
| `--policy <file>` | — | YAML/JSON policy |
| `--baseline <file>` | — | Accepted finding fingerprints |
| `--write-baseline <file>` | — | Write current findings as a baseline |
| `--registry <url>` | npm public registry | Trusted HTTPS registry origin |
| `--cache-dir <path>` | `.depdiff-cache` | Verified tarball cache |
| `--ignore <glob>` | — | Additional local path ignore; repeatable |
| `--max-files <count>` | 25,000 | Maximum archive/directory file count |
| `--max-total-bytes <n>` | 536,870,912 | Maximum unpacked bytes |
| `--max-file-bytes <n>` | 33,554,432 | Maximum individual file bytes |
| `--max-archive-bytes <n>` | 134,217,728 | Maximum compressed archive bytes |
| `--max-compression-ratio <n>` | 100 | Maximum expanded/compressed ratio |
| `--timeout <ms>` | 30,000 | Network request timeout |
| `-q, --quiet` | false | Suppress terminal summary and paths |

Offline mode is deterministic by default. Set `SOURCE_DATE_EPOCH` (seconds) to choose the report timestamp.

## `depdiff demo`

Runs bundled safe/risky fixtures with `--offline --deterministic`. All compare output and policy options are accepted.

## `depdiff init [file]`

Writes a documented policy template to `.depdiff.yml` or the supplied path. Refuses to overwrite unless `--force` is given.

## Exit codes

- `0`: audit complete; policy passed or `--no-fail` was set.
- `1`: audit complete; policy failed.
- `2`: invalid user input, untrusted/oversized archive, bad registry response, or invalid config.
- `3`: unexpected internal error.
