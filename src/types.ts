export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = [
  'network',
  'execution',
  'filesystem',
  'obfuscation',
  'install',
  'dependency',
  'binary',
  'metadata',
  'provenance',
  'inventory',
] as const;
export type Category = (typeof CATEGORIES)[number];

export interface Evidence {
  file?: string;
  line?: number;
  message: string;
  snippet?: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  category: Category;
  severity: Severity;
  score: number;
  evidence: Evidence[];
  remediation: string;
  status: 'new' | 'baseline';
  tags: string[];
}

export interface SourceDescriptor {
  input: string;
  kind: 'directory' | 'tarball' | 'registry';
  resolved: string;
  packageName?: string;
  version?: string;
  integrity?: string;
  shasum?: string;
  publishedAt?: string;
  maintainers?: string[];
  provenance?: {
    attestations: boolean;
    signatures: boolean;
    npmUser?: string;
    gitHead?: string;
  };
}

export interface PackageMetadata {
  name: string;
  version: string;
  description?: string;
  license?: string;
  repository?: string;
  engines: Record<string, string>;
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  bundledDependencies: string[];
  maintainers: string[];
  files?: string[];
}

export interface FileSummary {
  path: string;
  size: number;
  sha256: string;
  mode: number;
  kind: 'text' | 'binary' | 'symlink';
}

export interface PackageSnapshot {
  source: SourceDescriptor;
  package: PackageMetadata;
  files: FileSummary[];
  totalBytes: number;
}

export interface LoadedFile extends FileSummary {
  content?: Buffer;
}

export interface LoadedPackage {
  snapshot: PackageSnapshot;
  files: Map<string, LoadedFile>;
}

export interface CapabilitySignal {
  capability: string;
  category: Category;
  file: string;
  line?: number;
  message: string;
  snippet?: string;
}

export interface InventoryDiff {
  added: FileSummary[];
  removed: FileSummary[];
  modified: Array<{ before: FileSummary; after: FileSummary }>;
  unchanged: number;
}

export interface DependencyChange {
  name: string;
  scope: 'runtime' | 'optional' | 'peer' | 'development';
  before?: string;
  after?: string;
  change: 'added' | 'removed' | 'changed';
}

export interface MetadataDiff {
  scripts: Array<{ name: string; before?: string; after?: string }>;
  maintainersAdded: string[];
  maintainersRemoved: string[];
  dependencies: DependencyChange[];
  packageFields: Array<{ field: string; before?: string; after?: string }>;
}

export interface RiskSummary {
  score: number;
  level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  counts: Record<Severity, number>;
  newFindings: number;
  baselineFindings: number;
}

export interface PolicyViolation {
  rule: string;
  message: string;
  findingFingerprints: string[];
}

export interface PolicyResult {
  passed: boolean;
  policyPath?: string;
  violations: PolicyViolation[];
}

export interface DiffReport {
  schemaVersion: '1.0.0';
  tool: { name: 'depdiff'; version: string };
  generatedAt: string;
  before: PackageSnapshot;
  after: PackageSnapshot;
  inventory: InventoryDiff;
  metadata: MetadataDiff;
  findings: Finding[];
  risk: RiskSummary;
  policy: PolicyResult;
  analysis: {
    offline: boolean;
    packageCodeExecuted: false;
    limits: ScanLimits;
    notes: string[];
  };
}

export interface ScanLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
  maxArchiveBytes: number;
  maxTextBytes: number;
  maxCompressionRatio: number;
  timeoutMs: number;
}

export interface ResolveOptions {
  offline: boolean;
  registry: string;
  cacheDir: string;
  limits: ScanLimits;
  ignore: string[];
}

export interface Policy {
  version: 1;
  failOn: Severity | 'never';
  maxRiskScore: number;
  denyCapabilities: string[];
  denyDomains: string[];
  allowDomains: string[];
  allowInstallScripts: boolean;
  maxAddedDependencies: number;
  maxAddedFiles: number;
  ignoreFindings: string[];
  includeBaseline: boolean;
}

export interface Baseline {
  schemaVersion: 1;
  generatedAt: string;
  findings: Array<{
    fingerprint: string;
    id: string;
    title: string;
  }>;
}
