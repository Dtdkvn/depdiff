# GitHub launch kit and v0.1.0 release record

This file contains launch copy and the verification record for [Depdiff](../README.md). The source repository is live at <https://github.com/Dtdkvn/depdiff>; [`depdiff-audit@0.1.0`](https://www.npmjs.com/package/depdiff-audit/v/0.1.0), the [`v0.1.0` GitHub release](https://github.com/Dtdkvn/depdiff/releases/tag/v0.1.0), and the reviewed `v0.1.0` Action tag are published.

## Repository profile

### About

> Static, local-first npm update risk diffs with file-and-line evidence, policy gates, SARIF, and standalone reports. Target packages are never executed.

Character count: **151** (GitHub limit: 160).

### Topics

`npm` · `security` · `supply-chain` · `static-analysis` · `dependency-diff` · `sarif` · `github-actions` · `software-composition-analysis`

### One-line pitch

Depdiff shows the security-relevant capabilities an npm update newly acquired, with concrete evidence and policy gates, without executing the package.

## Long launch post

### Launching Depdiff: review what an npm update learned to do

Dependency review has an awkward gap. `npm diff` can show every changed line, and advisory scanners can tell you whether installed versions match known vulnerabilities. Both are useful, but neither directly answers the question I usually have during an update: **what can this release do now that the previous release could not?**

Depdiff is an open-source, local-first tool built around that question. Give it two npm versions, tarballs, or directories. It creates normalized snapshots, compares their behavior-relevant surfaces, and returns a review queue with file-and-line evidence. The goal is not to label a package good or bad. The goal is to make the semantic delta small enough for a human to review.

The current detectors focus on changes that deserve attention during a dependency update: new network APIs and literal destinations, process execution and dynamic code, lifecycle scripts, filesystem access, binaries and executable bits, dependency sources, maintainer metadata, provenance changes, encoded payloads, and unusually dense or generated files. Each finding has a stable rule ID, severity, fingerprint, score contribution, evidence, and review guidance. Baselines let a team acknowledge reviewed findings without hiding them, while policy-as-code can reject newly introduced capabilities or domains in CI.

The safety model matters as much as the detectors. Depdiff treats target packages as hostile data. It does not install them, import their modules, invoke lifecycle scripts, compile their native code, or shell into them. Registry metadata and archives are bounded and validated, supplied integrity digests are verified, extraction is disposable, archive links and special files are rejected, and local symlinks are never followed. For reproducible reviews, `--offline` forbids network access and accepts only local directories or tarballs.

Reports are meant to travel through a real review workflow. A single run can produce a terminal summary, standalone HTML, JSON, Markdown, and SARIF 2.1.0. The HTML report has no external JavaScript or CSS dependency. The GitHub Action adds annotations and report artifacts; the CLI exposes explicit exit codes; and YAML or JSON policy controls severity, score, domains, install scripts, capabilities, dependency count, file count, and accepted fingerprints.

The fastest installation path is available now: run `npx depdiff-audit@0.1.0 demo --no-fail`. The demo is deterministic, offline, and produces HTML, JSON, Markdown, and SARIF from packaged safe/risky fixtures. Source and Docker Compose paths remain available for contributors and reproducible local review. The hosted `Dtdkvn/depdiff@v0.1.0` Action is live; production workflows should pin its reviewed full commit SHA.

Detector changes have a labeled regression gate, but I want to be precise about what it proves. The full opt-in corpus contains exactly 10 cases: six labeled clean cases and four labeled alert cases. Five clean cases are integrity-pinned ordinary npm release pairs; one is a no-op fixture. Three alert cases are synthetic evasive transformations. Exactly one case uses a human-vetted real compromised release, paired with its clean predecessor. The corpus is deliberately small and selection-biased. Its precision, recall, false-positive rate, and risk scores catch regressions in this project; they are not market-wide accuracy estimates, malware verdicts, or proof that a package is safe.

Static analysis still has hard limits. Runtime-computed module names or destinations can evade detectors. Native binaries are inventoried, not reverse engineered. Parser-resistant, minified, generated, and novel obfuscation may require deeper review. Depdiff does not recursively audit every newly added dependency, replace a source diff, or replace sandboxed malware analysis. A clean result means the configured rules found no new signal, not that the update is harmless.

If version-to-version capability review is useful in your workflow, I would value feedback on three things: which deltas consume the most review time today, which findings are noisy, and which policy controls would let you adopt the tool in CI. Start with the [source-first quickstart](../README.md#quickstart), read the [threat model](../SECURITY.md), and open an issue with a minimal package pair when a detector misses or overstates something.

## Short launch post

Depdiff is an open-source, local-first way to review the security-relevant delta between two npm package versions. It highlights newly added network destinations, process execution, install hooks, filesystem access, binaries, dependency sources, ownership changes, and other capabilities with file-and-line evidence.

Target packages are treated as hostile data: Depdiff never installs them, imports their modules, or runs lifecycle scripts. It supports offline directory/tarball comparisons, standalone HTML, JSON, Markdown, SARIF, baselines, policy-as-code, and CI exit codes.

Version `0.1.0` is live on npm with provenance, as a GitHub release, and as the reviewed `Dtdkvn/depdiff@v0.1.0` Action tag. Try it with `npx depdiff-audit@0.1.0 demo --no-fail`; source and Docker workflows remain available for local-first use.

Its full benchmark is intentionally modest: 10 labeled cases, including exactly one human-vetted real compromise. Scores prioritize review; they are not malware verdicts. Feedback on missed deltas and noisy findings is welcome.

## Hacker News title

> Show HN: Depdiff – See what capabilities an npm update added without running it

## Launch checklist

### Repository publication

- [x] Publish the reviewed source at `https://github.com/Dtdkvn/depdiff` with `main` as the default branch.
- [x] Add the 151-character About text and the topics listed above.
- [x] Push only the reviewed history and confirm no private branches, artifacts, tokens, or machine-specific files are included.
- [x] Confirm the CI badge resolves and Node 22/24 quality, container, and local Action jobs pass on GitHub-hosted runners.
- [x] Enable Issues and private vulnerability reporting; verify the [`SECURITY.md`](../SECURITY.md) advisory link resolves.
- [ ] Render the README on GitHub and check the demo GIF, report screenshot, Mermaid diagram, headings, and relative links.
- [x] Confirm the Action example pins the published `v0.1.0` commit `a14eb01108c8872b7b54849fde9fc0592777621e`.

### npm and Action publication

- [x] Publish `depdiff-audit@0.1.0` under the verified npm account.
- [x] Follow the [release integrity procedure](releasing.md): exact SemVer tag, main ancestry, one verified tarball, provenance, and post-publish shasum verification (`dbbe8cfd97f81f114c18fa8db670904734faa155`).
- [x] Revoke the temporary bootstrap token, remove the GitHub environment secret, and make the release workflow OIDC-only with no token fallback.
- [ ] Complete the npm account 2FA/confirmation and register the exact `Dtdkvn/depdiff` / `release.yml` / `npm` trusted publisher. Future release publishes intentionally fail authentication until this external registration is complete.
- [x] Install the published package in a clean directory and verify the `depdiff` binary, ESM import, types, demo, and package contents.
- [x] Verify `npx depdiff-audit@0.1.0 demo --no-fail` works before adding the npm badge and removing the pre-release notice.
- [ ] Run the hosted Action from a separate test repository, pinned to a reviewed full SHA, and verify annotations plus HTML/SARIF artifacts.
- [x] Update the README's post-publish labels only after each distribution is actually reachable.

### Launch day

- [x] Create the `v0.1.0` GitHub release with the exact published tarball and bounded release notes.
- [ ] Publish the long post where context is welcome and the short post on social channels; use the Hacker News title above for Show HN.
- [ ] Keep claims bounded: say “review-priority score,” “10 labeled cases,” and “one real compromise sample”; never present the score as a malware verdict.
- [ ] Invite reproducible false-positive and false-negative reports with exact before/after package versions or local fixtures.
- [ ] Watch CI, npm install telemetry available to maintainers, issues, and vulnerability reports during the first 24 hours.
- [ ] Thank early reviewers and record actionable detector or documentation follow-ups without silently expanding the security claims.

Contributors should start with [CONTRIBUTING.md](../CONTRIBUTING.md). The technical boundaries and known limitations are documented in [architecture.md](architecture.md) and [SECURITY.md](../SECURITY.md).
