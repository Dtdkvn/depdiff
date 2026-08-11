# Contributing to Depdiff

Thank you for helping make npm update review more understandable and local-first.

## Development setup

Requirements: Node.js 20.12+ and npm 10+.

```bash
git clone https://github.com/depdiff/depdiff.git
cd depdiff
npm ci --ignore-scripts
npm run check
```

Useful commands:

- `npm run dev -- compare <before> <after>` — run TypeScript directly;
- `npm run demo` — generate deterministic reports from hostile fixtures;
- `npm test` — run the Vitest suite;
- `npm run lint` / `npm run typecheck` / `npm run build` — individual gates;
- `npm run check` — every required pre-PR gate.

## Design rules

1. Target packages are hostile data. Never execute/import/install their code or lifecycle scripts.
2. Add explicit resource bounds around new input paths.
3. Findings need a stable semantic identity, evidence, remediation, tests, and documentation.
4. Avoid a detector that only increases noise. Prefer “new capability + concrete location” over generic pattern counts.
5. Output renderers must escape all package-controlled values.
6. Offline reports must be deterministic.
7. New dependencies need a short rationale in the pull request and must not require install scripts.

## Adding a detector

- Add or extend a differential profile in `src/analyzer.ts`.
- Prefer AST evidence; provide a conservative lexical fallback where useful.
- Compare before/after semantics so existing behavior is not re-reported.
- Assign severity based on review urgency, not presumed intent.
- Add safe/risky test fixtures and assertions for false positives.
- Document the rule in `docs/rules.md`.

## Pull requests

Keep changes focused, use conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), and explain security tradeoffs. Include generated report screenshots when changing HTML. CI must pass on every supported Node version.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
