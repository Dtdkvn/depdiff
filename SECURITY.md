# Security policy

Depdiff processes software packages that may be actively malicious. Security reports about acquisition, archive handling, parser behavior, output injection, CI integration, or dependency compromise are especially welcome.

## Supported versions

Until 1.0, only the latest tagged release receives security fixes. After 1.0, the latest major release and previous major release will receive fixes for at least 90 days after a successor ships.

## Reporting a vulnerability

Please use GitHub's **Security → Report a vulnerability** private advisory flow for `depdiff/depdiff`. Do not open a public issue with exploit details.

Include:

- affected version/commit and platform;
- a minimal reproduction or hostile fixture;
- impact and the trust boundary crossed;
- suggested remediation, if known.

Maintainers aim to acknowledge reports within 72 hours, provide an initial assessment within 7 days, and coordinate disclosure after a fix is available. Please allow 90 days before public disclosure unless we agree on another timeline.

## Threat model

### Protected assets

- the operator's filesystem and credentials;
- CI runner tokens and workspace contents;
- correctness and integrity of reports/policy decisions;
- availability when processing large or malformed inputs.

### Untrusted inputs

- npm registry metadata and redirects;
- compressed archives, headers, paths, modes, and contents;
- local directories, files, and symlinks;
- package manifests, source text, binaries, and strings rendered in reports;
- policy and baseline files supplied by a repository.

### Security invariants

1. Depdiff never executes, imports, installs, compiles, or shells into target package code.
2. Registry requests require HTTPS; every redirect is validated before leaving the configured origin.
3. Registry metadata is streamed through a hard cap and the strongest supported digest is verified when present.
4. Archive paths/types, canonical root, and declared resource use are validated before analysis.
5. Extraction is disposable and contained; links and special files are rejected.
6. Local symlinks are fingerprinted but never followed.
7. Report-controlled text is escaped or normalized before entering HTML, Markdown, terminal, workflow-command, or SARIF location contexts.
8. Limits bound compressed bytes, expanded bytes, compression ratio, files, per-file bytes, parsed text, and network time.

### Explicit limitations

- Static analysis is bypassable and is not a sandbox or proof of safety.
- Native payloads are hashed/inventoried, not reverse engineered.
- Runtime-computed strings and behavior can be invisible to the detectors.
- JavaScript parser vulnerabilities in Depdiff's own dependency tree remain a risk; use a container for additional isolation when inspecting high-risk packages.
- A custom registry that serves tarballs from a different host must be scanned through a separately downloaded local tarball in v0.1.
- Local-directory access is intentionally as broad as the path the operator supplies. Do not point Depdiff at sensitive filesystem roots.

## Hardening CI

- Pin the Action to a reviewed commit SHA for high-assurance workflows. This repository's own third-party workflow Actions and base images are SHA/digest pinned.
- Use read-only `contents` permission; grant `security-events: write` only to a separate SARIF upload step.
- Run `--offline` against checked-in/downloaded artifacts where reproducibility matters.
- Keep policy and baselines under code review.
- Treat HTML/JSON/SARIF artifacts as sensitive if package paths or internal domains are sensitive.
- The provided runtime container drops capabilities, uses a read-only root filesystem in Compose, and enables `no-new-privileges`.

## Dependency installation

Project development and images use `npm ci --ignore-scripts`, so dependencies do not run lifecycle hooks during setup. Target-package dependencies are never installed under any mode.

For TLS-inspecting development networks, both Dockerfiles accept the trusted root only as an optional BuildKit secret: `docker build --secret id=depdiff_ca,src=/path/to/root.pem .`. The certificate is available only to dependency-install steps and is not copied into an image layer.
