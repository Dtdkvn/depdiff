# Depdiff contributor instructions

Read `README.md`, `docs/architecture.md`, and `SECURITY.md` before changing acquisition, extraction, analyzers, policies, or output renderers.

Non-negotiable invariants:

1. Never execute, import, install, compile, or shell into target package code.
2. Preserve archive traversal/link/device rejection and all resource limits.
3. Registry access remains HTTPS, same-origin, digest-verified when metadata permits, and optional via `--offline`.
4. Every detector is differential, evidence-backed, stable-fingerprinted, tested, and documented.
5. Escape package-controlled data in every output context.
6. Offline fixture output remains deterministic.
7. Run `npm run check` and the built CLI demo before committing.

Use conventional commits. Keep code, UI copy, documentation, and commits in English.
