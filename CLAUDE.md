# Depdiff contributor instructions

Read `README.md`, `docs/architecture.md`, and `SECURITY.md` before changing acquisition, extraction, analyzers, policies, or output renderers.

Non-negotiable invariants:

1. Never execute, import, install, compile, or shell into target package code.
2. Preserve archive traversal/link/device/root rejection, full shipped-path coverage, and all resource limits.
3. Registry access remains HTTPS, validates every redirect before the request, streams bounded metadata, verifies the strongest supported digest, and stays optional via `--offline`.
4. Every detector is differential, evidence-backed, stable-fingerprinted, tested, and documented.
5. Escape or normalize package-controlled data in every output context; never map package-internal paths onto unrelated repository files.
6. Offline fixture output remains deterministic.
7. Run `npm run check` and the built CLI demo before committing.

Use conventional commits. Keep code, UI copy, documentation, and commits in English.
