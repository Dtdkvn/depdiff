# Rule catalog

Rule IDs are stable within the v1 report schema. A detector may add a suffix for the specific capability.

| Rule | Typical severity | Meaning |
|---|---|---|
| `capability.added.child_process` | critical | Candidate newly imports process spawning APIs |
| `capability.added.dynamic-code` | critical | Candidate newly uses `eval`, `Function`, `vm`, or dynamic WASM |
| `capability.added.network` | high | Candidate newly uses an HTTP/WebSocket client API |
| `capability.added.raw-network` | high | Candidate newly imports TCP/TLS/UDP APIs |
| `capability.added.filesystem` | medium | Candidate newly imports filesystem APIs |
| `capability.added.dns` | medium | Candidate newly imports DNS APIs |
| `capability.added.module-loader` | medium | Candidate newly uses a dynamic module path |
| `network.domains.added` | medium/high | New literal network hosts were found |
| `install-script.added` | high/critical | A lifecycle hook was added; suspicious downloader/shell tokens raise severity |
| `install-script.changed` | medium/critical | Existing lifecycle command changed |
| `dependencies.runtime.added` | low/medium | New shipped dependencies expand trust |
| `binary.native.added` | high | Native executable/library payload added |
| `binary.added` | medium | Other binary payload added |
| `files.executable.added` | medium | New file has executable permission bits |
| `files.symlink.added` | medium | Local input has a new symlink (never followed) |
| `inventory.size.spike` | medium | Unpacked size grew sharply |
| `obfuscation.encoded-payload` | high | Long high-entropy Base64/hex-like blob added |
| `obfuscation.entropy-spike` | medium | File entropy increased sharply |
| `payload.generated.added` | low/medium | Dense, large, or generated payload reduces reviewability |
| `metadata.maintainers.changed` | high | Effective registry/package maintainer set changed |
| `metadata.name.changed` | high | Package name changed between inputs |
| `metadata.repository.changed` | medium | Repository metadata changed |
| `provenance.attestations.removed` | high | Registry attestation advertised before, absent now |
| `provenance.signatures.removed` | high | Registry signature advertised before, absent now |
| `provenance.integrity.missing` | high | Registry version lacks `dist.integrity` |
| `analysis.new-parse-failures` | low | More files fell back from AST to lexical analysis |

Severities communicate urgency for review, not a malware verdict. Evidence and surrounding source determine whether a change is acceptable.
