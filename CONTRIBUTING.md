# Contributing to Depdiff

Thank you for helping make npm update review more understandable and local-first.

## Development setup

Requirements: Node.js 22+ and npm 10+. Node 24 and the npm version declared by `packageManager` are the project defaults.

```bash
git clone https://github.com/yewud/depdiff.git
cd depdiff
npm ci --ignore-scripts
npm run check
```

Useful commands:

- `npm run dev -- compare <before> <after>` — run TypeScript directly;
- `npm run demo` — generate deterministic reports from hostile fixtures;
- `npm test` — run the Vitest suite;
- `npm run test:coverage` — run the enforced 80% line/statement, 85% function, and 70% branch coverage floor, including CLI behavior;
- `npm run benchmark:precision` — run the deterministic labeled detector benchmark without network access;
- `npm run benchmark:precision:registry` — add integrity-pinned real npm release pairs (network opt-in; target code is never installed or executed);
- `npm run lint` / `npm run typecheck` / `npm run build` — individual gates;
- `npm run check` — every required pre-PR gate.

## Design rules

1. Target packages are hostile data. Never execute/import/install their code or lifecycle scripts.
2. Add explicit resource bounds around new input paths.
3. Findings need a stable semantic identity, evidence, remediation, tests, and documentation.
4. Avoid a detector that only increases noise. Prefer “new capability + concrete location” over generic pattern counts.
5. Output renderers must escape all package-controlled values.
6. Archive and registry readers fail closed: never silently omit a shipped path, redirect hop, manifest, or digest.
7. Offline reports must be deterministic.
8. New dependencies need a short rationale in the pull request and must not require install scripts.

## Adding a detector

- Add or extend a differential profile in `src/analyzer.ts`.
- Prefer AST evidence; provide a conservative lexical fallback where useful.
- Compare before/after semantics so existing behavior is not re-reported.
- Assign severity based on review urgency, not presumed intent.
- Add safe/risky test fixtures and assertions for false positives.
- Document the rule in `docs/rules.md`.

## Pull requests

Keep changes focused, use conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), and explain security tradeoffs. Include generated report screenshots when changing HTML. CI must pass on every supported Node version.

Release maintainers should also read the [release integrity workflow](docs/releasing.md).

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
