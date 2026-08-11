import path from 'node:path';
import { analyzeDiff } from './analyzer.js';
import { DEFAULT_IGNORES, DEFAULT_LIMITS } from './constants.js';
import { applyBaseline, evaluatePolicy, loadBaseline, loadPolicy } from './policy.js';
import { resolvePackageSource } from './source.js';
import type { DiffReport, ScanLimits, Severity } from './types.js';

export interface AuditOptions {
  offline?: boolean;
  deterministic?: boolean;
  registry?: string;
  cacheDir?: string;
  ignore?: string[];
  limits?: Partial<ScanLimits>;
  policyPath?: string;
  baselinePath?: string;
  failOn?: Severity | 'never';
  ci?: boolean;
}

export async function audit(beforeInput: string, afterInput: string, options: AuditOptions = {}): Promise<DiffReport> {
  const offline = options.offline ?? false;
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const resolveOptions = {
    offline,
    registry: options.registry ?? 'https://registry.npmjs.org/',
    cacheDir: path.resolve(options.cacheDir ?? '.depdiff-cache'),
    limits,
    localIgnore: DEFAULT_IGNORES,
    ignore: options.ignore ?? [],
  };
  const [{ policy, path: policyPath }, baseline, before, after] = await Promise.all([
    loadPolicy(options.policyPath, { ...(options.failOn !== undefined ? { failOn: options.failOn } : {}), ci: options.ci ?? false }),
    loadBaseline(options.baselinePath),
    resolvePackageSource(beforeInput, resolveOptions),
    resolvePackageSource(afterInput, resolveOptions),
  ]);
  const generatedAt = options.deterministic || offline
    ? new Date(Number(process.env.SOURCE_DATE_EPOCH ?? 0) * 1000).toISOString()
    : new Date().toISOString();
  const report = analyzeDiff(before, after, { generatedAt, offline, resolveOptions });
  applyBaseline(report, baseline);
  report.policy = evaluatePolicy(report, policy, policyPath);
  return report;
}
