# Policy and baselines

Policy is intentionally small enough to audit in a pull request. Unknown keys and wrong types fail closed with exit code 2.

```yaml
version: 1
failOn: high
maxRiskScore: 49
denyCapabilities: [child_process, dynamic-code]
denyDomains: ["*"]
allowDomains: ["registry.npmjs.org", "*.example.com"]
allowInstallScripts: false
maxAddedDependencies: 10
maxAddedFiles: 250
ignoreFindings: []
includeBaseline: false
```

## Fields

- `failOn`: lowest severity that fails the gate; one of `info`, `low`, `medium`, `high`, `critical`, or `never`.
- `maxRiskScore`: inclusive maximum from 0 to 100; a larger score fails.
- `denyCapabilities`: exact capability tags such as `child_process`, `dynamic-code`, `network`, `raw-network`, or `filesystem`.
- `denyDomains`: minimatch patterns. `*` denies every newly observed literal destination.
- `allowDomains`: minimatch patterns evaluated first; an allow wins over a deny.
- `allowInstallScripts`: when false, added or changed lifecycle scripts fail.
- `maxAddedDependencies`: maximum new shipped runtime/optional/peer dependencies.
- `maxAddedFiles`: maximum added files.
- `ignoreFindings`: exact or globbed rule IDs/fingerprints excluded only from policy.
- `includeBaseline`: when true, accepted baseline findings are evaluated again.

## Baselines

A baseline contains stable finding fingerprints and minimal human labels. It does not hide findings: accepted findings remain visible with `status: baseline`, but they do not contribute to current risk or default policy evaluation.

Write one only after review:

```bash
depdiff compare old.tgz candidate.tgz --offline \
  --write-baseline .depdiff-baseline.json --no-fail
```

Commit the baseline. On a later comparison, pass `--baseline .depdiff-baseline.json`. Changed semantic evidence produces a different fingerprint and re-enters the review queue; capability fingerprints include hashes of the candidate files that produced their signals.

Never baseline an unexplained critical finding merely to make CI green.
