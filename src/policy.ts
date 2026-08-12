import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { minimatch } from 'minimatch';
import { parse as parseYaml } from 'yaml';
import { summarizeRisk } from './analyzer.js';
import type { Baseline, DiffReport, Finding, Policy, PolicyResult, PolicyViolation, Severity } from './types.js';
import { compareStrings, isRecord, severityRank, stableStringify, stringArray, UserError, writeTextFile } from './util.js';

export const DEFAULT_POLICY: Policy = {
  version: 1,
  failOn: 'never',
  maxRiskScore: 100,
  denyCapabilities: [],
  denyDomains: [],
  allowDomains: [],
  allowInstallScripts: true,
  maxAddedDependencies: 1_000_000,
  maxAddedFiles: 1_000_000,
  ignoreFindings: [],
  includeBaseline: false,
};

export const POLICY_TEMPLATE = `# Depdiff policy — commit this file as .depdiff.yml
version: 1

# Fail CI when a new finding reaches this severity.
failOn: high
maxRiskScore: 49

# Capability names appear in report finding IDs/tags.
denyCapabilities:
  - child_process
  - dynamic-code

# Minimatch patterns are supported. Allow rules win over deny rules.
denyDomains:
  - "*"
allowDomains:
  - "registry.npmjs.org"
  - "*.example.com"

allowInstallScripts: false
maxAddedDependencies: 10
maxAddedFiles: 250

# IDs, fingerprints, and glob patterns are accepted.
ignoreFindings: []
includeBaseline: false
`;

export async function loadPolicy(
  policyPath: string | undefined,
  overrides: { failOn?: Severity | 'never'; ci: boolean },
): Promise<{ policy: Policy; path?: string; warnings: Array<{ rule: string; message: string }> }> {
  let policy = { ...DEFAULT_POLICY };
  const warnings: Array<{ rule: string; message: string }> = [];
  let resolvedPath: string | undefined;
  if (policyPath) {
    resolvedPath = path.resolve(policyPath);
    const raw = await readFile(resolvedPath, 'utf8').catch((error: unknown) => {
      throw new UserError(`Cannot read policy ${policyPath}: ${error instanceof Error ? error.message : String(error)}`);
    });
    let parsed: unknown;
    try {
      parsed = /\.json$/i.test(policyPath) ? JSON.parse(raw) : parseYaml(raw);
    } catch (error) {
      throw new UserError(`Cannot parse policy ${policyPath}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (isRecord(parsed) && Object.hasOwn(parsed, 'maxRiskScore') && !Object.hasOwn(parsed, 'failOn') && overrides.failOn === undefined) {
      warnings.push({
        rule: 'maxRiskScore-without-failOn',
        message: 'maxRiskScore is configured without failOn. Scores prioritize review, so one high or critical finding can remain below an aggregate score threshold; add an explicit failOn severity unless that is intentional.',
      });
    }
    policy = validatePolicy(parsed);
  } else if (overrides.ci) {
    policy.failOn = 'high';
  }
  if (overrides.failOn !== undefined) policy.failOn = overrides.failOn;
  return { policy, ...(resolvedPath ? { path: resolvedPath } : {}), warnings };
}

export function validatePolicy(value: unknown): Policy {
  if (!isRecord(value)) throw new UserError('Policy must be a YAML/JSON object.');
  const allowed = new Set([
    'version', 'failOn', 'maxRiskScore', 'denyCapabilities', 'denyDomains', 'allowDomains',
    'allowInstallScripts', 'maxAddedDependencies', 'maxAddedFiles', 'ignoreFindings', 'includeBaseline',
  ]);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new UserError(`Unknown policy field${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}`);
  if (value.version !== 1) throw new UserError('Policy version must be 1.');
  const failOn = value.failOn ?? DEFAULT_POLICY.failOn;
  if (typeof failOn !== 'string' || !['info', 'low', 'medium', 'high', 'critical', 'never'].includes(failOn)) {
    throw new UserError('Policy failOn must be info, low, medium, high, critical, or never.');
  }
  return {
    version: 1,
    failOn: failOn as Policy['failOn'],
    maxRiskScore: boundedNumber(value.maxRiskScore, 'maxRiskScore', 0, 100, DEFAULT_POLICY.maxRiskScore),
    denyCapabilities: checkedStrings(value.denyCapabilities, 'denyCapabilities'),
    denyDomains: checkedStrings(value.denyDomains, 'denyDomains'),
    allowDomains: checkedStrings(value.allowDomains, 'allowDomains'),
    allowInstallScripts: checkedBoolean(value.allowInstallScripts, 'allowInstallScripts', DEFAULT_POLICY.allowInstallScripts),
    maxAddedDependencies: boundedNumber(value.maxAddedDependencies, 'maxAddedDependencies', 0, 1_000_000, DEFAULT_POLICY.maxAddedDependencies),
    maxAddedFiles: boundedNumber(value.maxAddedFiles, 'maxAddedFiles', 0, 1_000_000, DEFAULT_POLICY.maxAddedFiles),
    ignoreFindings: checkedStrings(value.ignoreFindings, 'ignoreFindings'),
    includeBaseline: checkedBoolean(value.includeBaseline, 'includeBaseline', DEFAULT_POLICY.includeBaseline),
  };
}

export async function loadBaseline(baselinePath: string | undefined): Promise<Baseline | undefined> {
  if (!baselinePath) return undefined;
  const raw = await readFile(path.resolve(baselinePath), 'utf8').catch((error: unknown) => {
    throw new UserError(`Cannot read baseline ${baselinePath}: ${error instanceof Error ? error.message : String(error)}`);
  });
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    throw new UserError(`Invalid baseline JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isRecord(value) || value.schemaVersion !== 1 || !Array.isArray(value.findings)) {
    throw new UserError('Baseline must use schemaVersion 1 and contain a findings array.');
  }
  const findings = value.findings.map((entry, index) => {
    if (!isRecord(entry) || typeof entry.fingerprint !== 'string' || typeof entry.id !== 'string' || typeof entry.title !== 'string') {
      throw new UserError(`Invalid baseline finding at index ${index}.`);
    }
    return { fingerprint: entry.fingerprint, id: entry.id, title: entry.title };
  });
  return {
    schemaVersion: 1,
    generatedAt: typeof value.generatedAt === 'string' ? value.generatedAt : new Date(0).toISOString(),
    findings,
  };
}

export function applyBaseline(report: DiffReport, baseline: Baseline | undefined): void {
  if (!baseline) return;
  const accepted = new Set(baseline.findings.map((finding) => finding.fingerprint));
  report.findings = report.findings.map((finding) => accepted.has(finding.fingerprint) ? { ...finding, status: 'baseline' } : finding);
  report.risk = summarizeRisk(report.findings);
}

export function evaluatePolicy(
  report: DiffReport,
  policy: Policy,
  policyPath?: string,
  warnings: Array<{ rule: string; message: string }> = [],
): PolicyResult {
  const findings = report.findings.filter((finding) => {
    if (!policy.includeBaseline && finding.status === 'baseline') return false;
    return !matchesIgnore(finding, policy.ignoreFindings);
  });
  const violations: PolicyViolation[] = [];
  const severityMatches = findings.filter((finding) => severityRank(finding.severity) >= severityRank(policy.failOn));
  if (severityMatches.length > 0 && policy.failOn !== 'never') {
    violations.push({
      rule: 'failOn',
      message: `${severityMatches.length} finding(s) meet or exceed ${policy.failOn} severity.`,
      findingFingerprints: severityMatches.map((finding) => finding.fingerprint),
    });
  }
  const policyScore = Math.min(100, findings.reduce((total, finding) => total + finding.score, 0));
  if (policyScore > policy.maxRiskScore) {
    violations.push({
      rule: 'maxRiskScore',
      message: `Risk score ${policyScore} exceeds maximum ${policy.maxRiskScore}.`,
      findingFingerprints: findings.map((finding) => finding.fingerprint),
    });
  }
  for (const capability of policy.denyCapabilities) {
    const matching = findings.filter((finding) => finding.tags.includes(capability) || finding.id.endsWith(`.${capability}`));
    if (matching.length > 0) violations.push({
      rule: `denyCapabilities:${capability}`,
      message: `Denied capability detected: ${capability}.`,
      findingFingerprints: matching.map((finding) => finding.fingerprint),
    });
  }
  const domains = new Set(findings.flatMap((finding) => finding.tags.filter((tag) => tag.startsWith('domain:')).map((tag) => tag.slice(7))));
  for (const domain of domains) {
    if (matchesAny(domain, policy.allowDomains)) continue;
    if (matchesAny(domain, policy.denyDomains)) {
      const matching = findings.filter((finding) => finding.tags.includes(`domain:${domain}`));
      violations.push({
        rule: `denyDomains:${domain}`,
        message: `Network destination is denied: ${domain}.`,
        findingFingerprints: matching.map((finding) => finding.fingerprint),
      });
    }
  }
  if (!policy.allowInstallScripts) {
    const matching = findings.filter((finding) => finding.id.startsWith('install-script.'));
    if (matching.length > 0) violations.push({
      rule: 'allowInstallScripts', message: 'New or changed install scripts are not allowed.',
      findingFingerprints: matching.map((finding) => finding.fingerprint),
    });
  }
  const addedDependencies = report.metadata.dependencies.filter((change) => change.change === 'added' && change.scope !== 'development').length;
  if (addedDependencies > policy.maxAddedDependencies) violations.push({
    rule: 'maxAddedDependencies', message: `${addedDependencies} shipped dependencies were added; maximum is ${policy.maxAddedDependencies}.`,
    findingFingerprints: findings.filter((finding) => finding.id === 'dependencies.runtime.added').map((finding) => finding.fingerprint),
  });
  if (report.inventory.added.length > policy.maxAddedFiles) violations.push({
    rule: 'maxAddedFiles', message: `${report.inventory.added.length} files were added; maximum is ${policy.maxAddedFiles}.`,
    findingFingerprints: findings.filter((finding) => finding.category === 'inventory' || finding.category === 'binary').map((finding) => finding.fingerprint),
  });
  return { passed: violations.length === 0, ...(policyPath ? { policyPath } : {}), violations, warnings };
}

export async function writeBaseline(filePath: string, report: DiffReport): Promise<void> {
  const baseline: Baseline = {
    schemaVersion: 1,
    generatedAt: report.generatedAt,
    findings: report.findings.map(({ fingerprint, id, title }) => ({ fingerprint, id, title })).sort((a, b) => compareStrings(a.fingerprint, b.fingerprint)),
  };
  await writeTextFile(filePath, `${stableStringify(baseline)}\n`);
}

function matchesIgnore(finding: Finding, patterns: string[]): boolean {
  return patterns.some((pattern) => minimatch(finding.id, pattern) || minimatch(finding.fingerprint, pattern));
}

function matchesAny(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => minimatch(value, pattern, { nocase: true }));
}

function checkedStrings(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || stringArray(value).length !== value.length) throw new UserError(`Policy ${field} must be an array of strings.`);
  return stringArray(value);
}

function checkedBoolean(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new UserError(`Policy ${field} must be true or false.`);
  return value;
}

function boundedNumber(value: unknown, field: string, minimum: number, maximum: number, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < minimum || value > maximum) {
    throw new UserError(`Policy ${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return value;
}
