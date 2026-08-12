import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { applyBaseline, DEFAULT_POLICY, evaluatePolicy, loadPolicy, validatePolicy } from '../src/policy.js';
import type { Baseline, Policy } from '../src/types.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');

describe('policy', () => {
  it('rejects unknown keys and malformed fields', () => {
    expect(() => validatePolicy({ version: 1, surprise: true })).toThrow(/Unknown policy field/);
    expect(() => validatePolicy({ version: 1, failOn: 'severe' })).toThrow(/failOn/);
    expect(() => validatePolicy({ version: 1, maxRiskScore: 101 })).toThrow(/maxRiskScore/);
    expect(() => validatePolicy({ version: 2 })).toThrow(/version/);
  });

  it('turns malformed YAML into a clear policy error', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-policy-test-'));
    const file = path.join(root, 'policy.yml');
    try {
      await writeFile(file, 'version: [unterminated', 'utf8');
      await expect(loadPolicy(file, { ci: false })).rejects.toThrow(/Cannot parse policy/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('preserves a policy threshold in CI unless the caller explicitly overrides it', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-policy-threshold-'));
    const file = path.join(root, 'policy.yml');
    try {
      await writeFile(file, 'version: 1\nfailOn: medium\n');
      expect((await loadPolicy(file, { ci: true })).policy.failOn).toBe('medium');
      expect((await loadPolicy(file, { ci: true, failOn: 'high' })).policy.failOn).toBe('high');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('warns when maxRiskScore is the only configured failure threshold', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-policy-warning-'));
    const scoreOnly = path.join(root, 'score-only.yml');
    const explicitSeverity = path.join(root, 'severity.yml');
    try {
      await writeFile(scoreOnly, 'version: 1\nmaxRiskScore: 49\n');
      await writeFile(explicitSeverity, 'version: 1\nmaxRiskScore: 49\nfailOn: high\n');
      expect((await loadPolicy(scoreOnly, { ci: false })).warnings).toEqual([
        expect.objectContaining({ rule: 'maxRiskScore-without-failOn' }),
      ]);
      expect((await loadPolicy(explicitSeverity, { ci: false })).warnings).toEqual([]);
      expect((await loadPolicy(scoreOnly, { ci: false, failOn: 'high' })).warnings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('enforces severity, capabilities, domains, scripts, and inventory limits', async () => {
    const report = await audit(safe, risky, { offline: true });
    const policy: Policy = {
      ...DEFAULT_POLICY,
      failOn: 'high',
      maxRiskScore: 40,
      denyCapabilities: ['child_process'],
      denyDomains: ['*.invalid'],
      allowInstallScripts: false,
      maxAddedDependencies: 0,
      maxAddedFiles: 1,
    };
    const result = evaluatePolicy(report, policy, '.depdiff.yml');
    expect(result.passed).toBe(false);
    expect(new Set(result.violations.map((violation) => violation.rule))).toEqual(expect.objectContaining(new Set([
      'failOn',
      'maxRiskScore',
      'denyCapabilities:child_process',
      'denyDomains:collector.example.invalid',
      'allowInstallScripts',
      'maxAddedDependencies',
      'maxAddedFiles',
    ])));
  });

  it('lets an allow-domain rule override a broad deny', async () => {
    const report = await audit(safe, risky, { offline: true });
    const result = evaluatePolicy(report, {
      ...DEFAULT_POLICY,
      denyDomains: ['*'],
      allowDomains: ['*.example.invalid'],
    });
    expect(result.violations.filter((violation) => violation.rule.startsWith('denyDomains:'))).toEqual([]);
  });

  it('suppresses accepted fingerprints from risk and policy by default', async () => {
    const report = await audit(safe, risky, { offline: true });
    const baseline: Baseline = {
      schemaVersion: 1,
      generatedAt: report.generatedAt,
      findings: report.findings.map(({ fingerprint, id, title }) => ({ fingerprint, id, title })),
    };
    applyBaseline(report, baseline);
    expect(report.risk.score).toBe(0);
    expect(report.risk.baselineFindings).toBe(report.findings.length);
    expect(evaluatePolicy(report, { ...DEFAULT_POLICY, failOn: 'info' }).passed).toBe(true);
    expect(evaluatePolicy(report, { ...DEFAULT_POLICY, failOn: 'info', includeBaseline: true }).passed).toBe(false);
  });
});
