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
| `dependencies.non-registry.added` | high | New Git, URL, workspace, archive, or local dependencies bypass registry integrity and provenance controls |
| `dependencies.non-registry.changed` | high | Existing dependency switched to or changed a Git, URL, workspace, archive, or local source |
| `binary.native.added` | high | Native executable/library payload added |
| `binary.added` | medium | Other binary payload added |
| `binary.native.changed` | high | Existing native executable/library payload changed |
| `binary.changed` | medium | Existing binary payload changed or text became binary |
| `files.executable.added` | medium | New file has reliable executable permission bits |
| `files.executable.changed` | medium | Existing file newly gained reliable executable permission bits |

Native Windows filesystems and Windows-backed Docker Desktop 9p bind mounts do not carry portable Unix executable metadata. Depdiff marks those modes unknown, excludes them from mode-only findings, and still uses authoritative tar-header modes for npm archives.
| `files.symlink.added` | medium | Local input has a new symlink (never followed) |
| `files.symlink.changed` | medium | Local symlink target or file kind changed |
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
| `analysis.parse-failure` | high | A shipped code file could not be parsed, so only lexical evidence was available for it |
| `analysis.unanalyzed-code` | high | A shipped file that appears to be code could not be analyzed at all, for example because it exceeds the text-analysis limit |
| `obfuscation.control-bytes` | high | A text file carries enough control bytes to defeat text detection, which hides code from analysis |

Severities communicate urgency for review, not a malware verdict. Evidence and surrounding source determine whether a change is acceptable.
