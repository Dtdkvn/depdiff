import {
  BINARY_EXTENSIONS,
  CODE_EXTENSIONS,
  codeExtension,
  classifyCodeFile,
  collectAliases,
  DYNAMIC_CODE_PROPERTIES,
  foldStaticString,
  inertRegionsFromAst,
  LineIndex,
  memberPropertyName,
  MODULE_LOAD_PROPERTIES,
  parseSource,
  resolveEntryReasons,
  scanInertRegions,
  scriptEntryTokens,
  walkAst,
} from './codeprofile.js';
import type { AliasTables, CodeReason, InertRegions } from './codeprofile.js';
import { LIFECYCLE_SCRIPTS } from './constants.js';
import type {
  CapabilitySignal,
  Category,
  DependencyChange,
  DiffReport,
  Evidence,
  FileSummary,
  Finding,
  InventoryDiff,
  LoadedFile,
  LoadedPackage,
  MetadataDiff,
  ResolveOptions,
  RiskSummary,
  ScanLimits,
  Severity,
} from './types.js';
import { compareStrings, isRecord, sha256, truncate } from './util.js';

interface AnalyzeOptions {
  generatedAt: string;
  offline: boolean;
  resolveOptions: ResolveOptions;
}

interface FindingDraft extends Omit<Finding, 'fingerprint' | 'status'> {
  identity: string;
}

/**
 * A shipped file that plausibly contains code but was not fully analyzed. Every
 * gap becomes a visible finding: "not understood" must never look like "safe".
 */
interface CoverageGap {
  file: string;
  reason: 'size-limit' | 'unreadable' | 'parse-failure' | 'partial-parse';
  detail: string;
}

interface StaticProfile {
  signals: CapabilitySignal[];
  domains: Map<string, Evidence[]>;
  gaps: CoverageGap[];
  controlBytes: Evidence[];
}

const MODULE_CAPABILITIES: Record<string, { capability: string; category: Category; message: string }> = {
  child_process: { capability: 'child_process', category: 'execution', message: 'Imports the child process API.' },
  cluster: { capability: 'child_process', category: 'execution', message: 'Imports the cluster process API.' },
  fs: { capability: 'filesystem', category: 'filesystem', message: 'Imports filesystem access.' },
  'fs/promises': { capability: 'filesystem', category: 'filesystem', message: 'Imports asynchronous filesystem access.' },
  http: { capability: 'network', category: 'network', message: 'Imports the HTTP client/server API.' },
  https: { capability: 'network', category: 'network', message: 'Imports the HTTPS client/server API.' },
  net: { capability: 'raw-network', category: 'network', message: 'Imports raw TCP networking.' },
  tls: { capability: 'raw-network', category: 'network', message: 'Imports raw TLS networking.' },
  dgram: { capability: 'raw-network', category: 'network', message: 'Imports UDP networking.' },
  dns: { capability: 'dns', category: 'network', message: 'Imports DNS lookup APIs.' },
  vm: { capability: 'dynamic-code', category: 'execution', message: 'Imports the VM dynamic-code API.' },
  module: { capability: 'module-loader', category: 'execution', message: 'Imports the module loader API.' },
  worker_threads: { capability: 'worker-threads', category: 'execution', message: 'Imports worker threads.' },
  inspector: { capability: 'inspector', category: 'execution', message: 'Imports the Node inspector API.' },
  axios: { capability: 'network', category: 'network', message: 'Imports the Axios HTTP client.' },
  got: { capability: 'network', category: 'network', message: 'Imports the Got HTTP client.' },
  undici: { capability: 'network', category: 'network', message: 'Imports the Undici HTTP client.' },
  'node-fetch': { capability: 'network', category: 'network', message: 'Imports the node-fetch HTTP client.' },
  superagent: { capability: 'network', category: 'network', message: 'Imports the SuperAgent HTTP client.' },
  request: { capability: 'network', category: 'network', message: 'Imports the request HTTP client.' },
  execa: { capability: 'child_process', category: 'execution', message: 'Imports the Execa process execution API.' },
  'cross-spawn': { capability: 'child_process', category: 'execution', message: 'Imports a process spawning API.' },
  shelljs: { capability: 'child_process', category: 'execution', message: 'Imports the ShellJS command execution API.' },
  'fs-extra': { capability: 'filesystem', category: 'filesystem', message: 'Imports extended filesystem access.' },
};

const CAPABILITY_RISK: Record<string, { severity: Severity; score: number; title: string; remediation: string }> = {
  child_process: {
    severity: 'critical', score: 34, title: 'New child process capability',
    remediation: 'Confirm every spawn/exec path and ensure no untrusted value can reach a shell or executable name.',
  },
  'dynamic-code': {
    severity: 'critical', score: 32, title: 'New dynamic code execution',
    remediation: 'Remove eval/Function/vm usage or pin and manually review the exact generated input.',
  },
  'raw-network': {
    severity: 'high', score: 22, title: 'New raw network capability',
    remediation: 'Verify destinations, TLS handling, and why lower-level socket access is required.',
  },
  network: {
    severity: 'high', score: 20, title: 'New network capability',
    remediation: 'Verify every destination and ensure network access is expected during runtime and installation.',
  },
  filesystem: {
    severity: 'medium', score: 10, title: 'New filesystem capability',
    remediation: 'Review paths, write operations, permissions, and all values derived from external input.',
  },
  dns: {
    severity: 'medium', score: 10, title: 'New DNS capability',
    remediation: 'Confirm DNS access is expected and cannot be used to exfiltrate sensitive data.',
  },
  'module-loader': {
    severity: 'medium', score: 9, title: 'New module-loader capability',
    remediation: 'Review dynamic resolution paths and prevent loading attacker-controlled modules.',
  },
  'worker-threads': {
    severity: 'low', score: 4, title: 'New worker thread capability',
    remediation: 'Confirm worker entry points are fixed and bundled with the package.',
  },
  inspector: {
    severity: 'high', score: 18, title: 'New inspector capability',
    remediation: 'Confirm the inspector is never exposed or activated in production installs.',
  },
  environment: {
    severity: 'low', score: 4, title: 'New environment-variable access',
    remediation: 'Verify secrets read from the environment are never logged or transmitted.',
  },
};

const GENERATED_EXTENSIONS = new Set(['.map', '.min.js', '.bundle.js']);
const NATIVE_BINARY_EXTENSIONS = new Set(['.node', '.dll', '.so', '.dylib', '.exe']);

export function analyzeDiff(before: LoadedPackage, after: LoadedPackage, options: AnalyzeOptions): DiffReport {
  const inventory = diffInventory(before, after);
  const metadata = diffMetadata(before, after);
  const limits = options.resolveOptions.limits;
  const beforeProfile = profilePackage(before, limits);
  const afterProfile = profilePackage(after, limits);
  const drafts: FindingDraft[] = [];

  drafts.push(...capabilityFindings(beforeProfile, afterProfile, after));
  drafts.push(...domainFindings(beforeProfile, afterProfile));
  drafts.push(...installScriptFindings(metadata));
  drafts.push(...dependencyFindings(metadata));
  drafts.push(...inventoryFindings(before, after, inventory));
  drafts.push(...obfuscationFindings(before, after, inventory));
  drafts.push(...metadataFindings(before, after, metadata));
  drafts.push(...provenanceFindings(before, after));
  drafts.push(...coverageFindings(afterProfile, after, inventory, limits));

  const findings = deduplicateFindings(drafts, after.snapshot.package.name).sort(compareFinding);
  const risk = summarizeRisk(findings);
  return {
    schemaVersion: '1.0.0',
    tool: { name: 'depdiff', version: '0.1.0' },
    generatedAt: options.generatedAt,
    before: before.snapshot,
    after: after.snapshot,
    inventory,
    metadata,
    findings,
    risk,
    policy: { passed: true, violations: [] },
    analysis: {
      offline: options.offline,
      packageCodeExecuted: false,
      limits: options.resolveOptions.limits,
      notes: [
        'Depdiff performs static analysis only and never executes package code or lifecycle scripts.',
        'Heuristics are review signals, not proof that code is malicious or safe.',
      ],
    },
  };
}

function diffInventory(before: LoadedPackage, after: LoadedPackage): InventoryDiff {
  const added: FileSummary[] = [];
  const removed: FileSummary[] = [];
  const modified: Array<{ before: FileSummary; after: FileSummary }> = [];
  let unchanged = 0;
  for (const [filePath, next] of after.files) {
    const previous = before.files.get(filePath);
    if (!previous) added.push(stripContent(next));
    else if (previous.sha256 !== next.sha256 || previous.mode !== next.mode) {
      modified.push({ before: stripContent(previous), after: stripContent(next) });
    } else unchanged += 1;
  }
  for (const [filePath, previous] of before.files) {
    if (!after.files.has(filePath)) removed.push(stripContent(previous));
  }
  added.sort((a, b) => compareStrings(a.path, b.path));
  removed.sort((a, b) => compareStrings(a.path, b.path));
  modified.sort((a, b) => compareStrings(a.after.path, b.after.path));
  return { added, removed, modified, unchanged };
}

function stripContent(file: LoadedFile): FileSummary {
  return { path: file.path, size: file.size, sha256: file.sha256, mode: file.mode, kind: file.kind };
}

function diffMetadata(before: LoadedPackage, after: LoadedPackage): MetadataDiff {
  const previous = before.snapshot.package;
  const next = after.snapshot.package;
  const scriptNames = new Set([...Object.keys(previous.scripts), ...Object.keys(next.scripts)]);
  const scripts = [...scriptNames].filter((name) => previous.scripts[name] !== next.scripts[name]).sort().map((name) => ({
    name,
    ...(previous.scripts[name] !== undefined ? { before: previous.scripts[name] } : {}),
    ...(next.scripts[name] !== undefined ? { after: next.scripts[name] } : {}),
  }));
  const beforeMaintainers = effectiveMaintainers(before);
  const afterMaintainers = effectiveMaintainers(after);
  const maintainersAdded = afterMaintainers.filter((value) => !beforeMaintainers.includes(value));
  const maintainersRemoved = beforeMaintainers.filter((value) => !afterMaintainers.includes(value));
  const dependencies = [
    ...diffDependencySet(previous.dependencies, next.dependencies, 'runtime'),
    ...diffDependencySet(previous.optionalDependencies, next.optionalDependencies, 'optional'),
    ...diffDependencySet(previous.peerDependencies, next.peerDependencies, 'peer'),
    ...diffDependencySet(previous.devDependencies, next.devDependencies, 'development'),
  ].sort((a, b) => compareStrings(`${a.scope}:${a.name}`, `${b.scope}:${b.name}`));
  const packageFields: MetadataDiff['packageFields'] = [];
  for (const [field, a, b] of [
    ['name', previous.name, next.name],
    ['license', previous.license, next.license],
    ['repository', previous.repository, next.repository],
    ['node engine', previous.engines.node, next.engines.node],
  ] as Array<[string, string | undefined, string | undefined]>) {
    if (a !== b) packageFields.push({ field, ...(a !== undefined ? { before: a } : {}), ...(b !== undefined ? { after: b } : {}) });
  }
  return { scripts, maintainersAdded, maintainersRemoved, dependencies, packageFields };
}

function diffDependencySet(
  before: Record<string, string>,
  after: Record<string, string>,
  scope: DependencyChange['scope'],
): DependencyChange[] {
  const changes: DependencyChange[] = [];
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) {
    if (before[name] === after[name]) continue;
    changes.push({
      name,
      scope,
      ...(before[name] !== undefined ? { before: before[name] } : {}),
      ...(after[name] !== undefined ? { after: after[name] } : {}),
      change: before[name] === undefined ? 'added' : after[name] === undefined ? 'removed' : 'changed',
    });
  }
  return changes;
}

function effectiveMaintainers(pkg: LoadedPackage): string[] {
  return [...new Set(pkg.snapshot.source.maintainers ?? pkg.snapshot.package.maintainers)].sort();
}

/**
 * Profiles every shipped file that plausibly contains code.
 *
 * Coverage is fail-closed: a file is selected by content and manifest metadata
 * rather than an extension allowlist, its bytes are analyzed whatever the
 * text/binary classification said, and any file that could not be analyzed for
 * any reason is recorded as a coverage gap instead of silently contributing
 * nothing.
 */
function profilePackage(pkg: LoadedPackage, limits: ScanLimits): StaticProfile {
  const signals: CapabilitySignal[] = [];
  const domains = new Map<string, Evidence[]>();
  const gaps: CoverageGap[] = [];
  const controlBytes: Evidence[] = [];
  const entryReasons = resolveEntryReasons(
    pkg.snapshot.package.entryPoints,
    scriptEntryTokens(pkg.snapshot.package.scripts),
    new Set(pkg.files.keys()),
  );
  for (const file of pkg.files.values()) {
    const verdict = classifyCodeFile({
      filePath: file.path,
      kind: file.kind,
      probe: file.content ?? file.probe,
      entryReason: entryReasons.get(file.path),
    });
    if (!verdict.code) continue;
    profileCodeFile(file, verdict.reason ?? 'content', { signals, domains, gaps, controlBytes }, limits);
  }
  return { signals: uniqueSignals(signals), domains, gaps, controlBytes };
}

function profileCodeFile(
  file: LoadedFile,
  reason: CodeReason,
  out: { signals: CapabilitySignal[]; domains: Map<string, Evidence[]>; gaps: CoverageGap[]; controlBytes: Evidence[] },
  limits: ScanLimits,
): void {
  if (!file.content) {
    out.gaps.push({
      file: file.path,
      reason: 'size-limit',
      detail: `${file.size.toLocaleString('en-US')} bytes exceeds the ${limits.maxTextBytes.toLocaleString('en-US')}-byte analyzed-text limit (--max-text-bytes); selected as code by ${reason}`,
    });
    return;
  }
  const source = file.content.toString('utf8');
  const lines = new LineIndex(source);
  const parsed = parseSource(source, codeExtension(file.path));
  const inert = parsed.ast === undefined ? scanInertRegions(source) : inertRegionsFromAst(parsed.ast);
  profileUrls(source, file.path, lines, inert, out.domains);
  profileLexicalCapabilities(source, file.path, lines, inert, out.signals, parsed.ast === undefined || parsed.degraded);
  if (parsed.ast !== undefined) {
    const aliases = collectAliases(parsed.ast);
    walkAst(parsed.ast, (node) => profileNode(node, lines, file.path, aliases, out.signals));
  }
  if (parsed.error !== undefined) {
    out.gaps.push({
      file: file.path,
      reason: parsed.ast === undefined ? 'parse-failure' : 'partial-parse',
      detail: truncate(parsed.error, 200),
    });
  }
  const control = countControlBytes(file.content);
  if (control.count >= CONTROL_BYTE_THRESHOLD || control.nul) {
    out.controlBytes.push({
      file: file.path,
      message: `${control.count.toLocaleString('en-US')} raw control byte(s)${control.nul ? ' including NUL' : ''} inside a file shipped as code (selected by ${reason}).`,
    });
  }
}

const CONTROL_BYTE_THRESHOLD = 16;

function countControlBytes(buffer: Buffer): { count: number; nul: boolean } {
  let count = 0;
  let nul = false;
  for (const byte of buffer) {
    if (byte === 0) nul = true;
    if (byte < 7 || (byte > 14 && byte < 32)) count += 1;
  }
  return { count, nul };
}

function profileUrls(
  source: string,
  file: string,
  lines: LineIndex,
  inert: InertRegions,
  domains: Map<string, Evidence[]>,
): void {
  // Hosts may be internationalized, so the character class must accept any
  // Unicode letter or digit. An ASCII-only class silently ignored homoglyph
  // destinations such as "еvil-corp.com", which also meant no domain tag was
  // produced and a denyDomains policy could not match them.
  const pattern = /\bhttps?:\\?\/\\?\/((?:[\p{L}\p{N}][\p{L}\p{N}.-]*)|\[[a-f0-9:]+\])(?::\d+)?(?:[/?#]|\b)/giu;
  for (const match of source.matchAll(pattern)) {
    const host = match[1]?.toLowerCase();
    if (!host) continue;
    const index = match.index ?? 0;
    // A URL inside a string literal is a real destination; one inside a comment
    // is prose and must neither raise nor pre-suppress a finding.
    if (inert.comments.contains(index)) continue;
    const evidence = {
      file,
      line: lines.lineNumber(index),
      message: `References ${host}.`,
      snippet: truncate(lines.lineText(index)),
    };
    const current = domains.get(host) ?? [];
    if (current.length < 5) current.push(evidence);
    domains.set(host, current);
  }
}

/**
 * Lexical capability checks. Matches inside comments and string literals are
 * discarded: `// never use eval()` is not a call, and a v1 that merely mentions
 * a capability must not suppress the v2 that actually gains it.
 */
function profileLexicalCapabilities(
  source: string,
  file: string,
  lines: LineIndex,
  inert: InertRegions,
  signals: CapabilitySignal[],
  includeModuleFallback: boolean,
): void {
  const checks: Array<[RegExp, string, Category, string]> = [
    [/\b(?:eval|Function)\s*\(/g, 'dynamic-code', 'execution', 'Calls a dynamic code constructor.'],
    [/\bprocess\s*\.\s*env\b/g, 'environment', 'execution', 'Reads environment variables.'],
    [/\b(?:fetch|XMLHttpRequest|WebSocket)\s*(?:\(|\b)/g, 'network', 'network', 'Uses a network client API.'],
    [/\b(?:axios|got|superagent|request|undici)\s*\.\s*(?:get|post|put|patch|delete|request|fetch|stream)\s*\(/g, 'network', 'network', 'Calls a network client API.'],
    [/\b(?:Bun\s*\.\s*spawn|Deno\s*\.\s*Command)\b/g, 'child_process', 'execution', 'Uses a runtime process execution API.'],
    [/\bWebAssembly\s*\.\s*(?:compile|instantiate)\s*\(/g, 'dynamic-code', 'execution', 'Compiles or instantiates WebAssembly dynamically.'],
  ];
  for (const [pattern, capability, category, message] of checks) {
    for (const match of source.matchAll(pattern)) {
      const index = match.index ?? 0;
      if (inert.comments.contains(index) || inert.literals.contains(index)) continue;
      signals.push({ capability, category, file, line: lines.lineNumber(index), message, snippet: truncate(lines.lineText(index)) });
    }
  }
  if (!includeModuleFallback) return;
  // The AST is missing or incomplete. Recover module capabilities lexically so a
  // parse failure degrades coverage instead of erasing the capability set.
  const moduleReferences = [
    /\b(?:require|_load|_compile)\s*\(\s*['"]([^'"\n]{1,120})['"]/g,
    /\bimport\s*\(\s*['"]([^'"\n]{1,120})['"]/g,
    /\bfrom\s*['"]([^'"\n]{1,120})['"]/g,
  ];
  for (const pattern of moduleReferences) {
    for (const match of source.matchAll(pattern)) {
      const index = match.index ?? 0;
      if (inert.comments.contains(index) || inert.literals.contains(index)) continue;
      const mapping = moduleCapability(match[1] ?? '');
      if (!mapping) continue;
      signals.push({
        capability: mapping.capability,
        category: mapping.category,
        file,
        line: lines.lineNumber(index),
        message: `${mapping.message} (recovered lexically after a parse failure)`,
        snippet: truncate(lines.lineText(index)),
      });
    }
  }
}

function profileNode(
  node: Record<string, unknown>,
  lines: LineIndex,
  file: string,
  aliases: AliasTables,
  signals: CapabilitySignal[],
): void {
  const nodeType = typeof node.type === 'string' ? node.type : '';
  if (nodeType === 'ImportDeclaration' || nodeType === 'ExportNamedDeclaration' || nodeType === 'ExportAllDeclaration') {
    const moduleName = foldStaticString(node.source);
    if (moduleName) addModuleSignal(moduleName.value, moduleName.literal, node, lines, file, signals);
  }
  if (nodeType === 'ImportExpression') {
    resolveModuleArgument(node.source, node, lines, file, signals);
  }
  if (nodeType === 'CallExpression') {
    const callee = isRecord(node.callee) ? node.callee : undefined;
    const argument = firstArrayItem(node.arguments);
    if (callee?.type === 'Import') {
      resolveModuleArgument(argument, node, lines, file, signals);
      return;
    }
    if (callee?.type === 'Identifier' && typeof callee.name === 'string' && (callee.name === 'require' || aliases.requireLike.has(callee.name))) {
      resolveModuleArgument(argument, node, lines, file, signals);
      return;
    }
    if (!callee) return;
    if (callee.type === 'Identifier' && typeof callee.name === 'string' && aliases.dynamicLike.has(callee.name)) {
      // const F = (() => {}).constructor; F("return require('child_process')")
      // reaches the Function constructor without ever naming Function or eval.
      addSignal('dynamic-code', 'execution', 'Builds executable code through an aliased code constructor.', node, lines, file, signals);
      return;
    }
    const property = memberPropertyName(callee);
    if (property && MODULE_LOAD_PROPERTIES.has(property)) {
      // process.mainModule.require(x), module.constructor._load(x), and the
      // computed forms of both reach the module loader just as a bare require
      // does, so the loaded module decides the capability.
      resolveModuleArgument(argument, node, lines, file, signals);
      return;
    }
    if (property && DYNAMIC_CODE_PROPERTIES.has(property) && foldStaticString(argument)) {
      addSignal('dynamic-code', 'execution', 'Builds executable code from a string through a member reference.', node, lines, file, signals);
    }
  }
}

function resolveModuleArgument(
  argument: unknown,
  node: Record<string, unknown>,
  lines: LineIndex,
  file: string,
  signals: CapabilitySignal[],
): void {
  const folded = foldStaticString(argument);
  if (folded) addModuleSignal(folded.value, folded.literal, node, lines, file, signals);
  else addSignal('module-loader', 'execution', 'Loads a module from a dynamic path.', node, lines, file, signals);
}

function moduleCapability(rawModule: string): { capability: string; category: Category; message: string } | undefined {
  return MODULE_CAPABILITIES[rawModule.replace(/^node:/, '')];
}

function addModuleSignal(
  rawModule: string,
  literal: boolean,
  node: Record<string, unknown>,
  lines: LineIndex,
  file: string,
  signals: CapabilitySignal[],
): void {
  const mapping = moduleCapability(rawModule);
  if (mapping) addSignal(mapping.capability, mapping.category, mapping.message, node, lines, file, signals);
  else if (!literal) addSignal('module-loader', 'execution', 'Loads a module from a dynamic path.', node, lines, file, signals);
}

function addSignal(
  capability: string,
  category: Category,
  message: string,
  node: Record<string, unknown>,
  lines: LineIndex,
  file: string,
  signals: CapabilitySignal[],
): void {
  const start = typeof node.start === 'number' ? node.start : 0;
  signals.push({ capability, category, file, line: lines.lineNumber(start), message, snippet: truncate(lines.lineText(start)) });
}

function firstArrayItem(value: unknown): unknown {
  if (!Array.isArray(value)) return undefined;
  return (value as unknown[])[0];
}

/**
 * Turns unanalyzed content into visible findings. A reviewer must always be able
 * to tell "Depdiff did not understand this content" from "this content is safe".
 */
function coverageFindings(
  profile: StaticProfile,
  candidate: LoadedPackage,
  inventory: InventoryDiff,
  limits: ScanLimits,
): FindingDraft[] {
  const changed = new Set([...inventory.added.map((file) => file.path), ...inventory.modified.map((change) => change.after.path)]);
  const drafts: FindingDraft[] = [];
  const relevant = profile.gaps.filter((gap) => changed.has(gap.file)).sort((a, b) => compareStrings(`${a.file}\0${a.reason}`, `${b.file}\0${b.reason}`));
  const unanalyzed = relevant.filter((gap) => gap.reason === 'size-limit' || gap.reason === 'unreadable');
  const parseGaps = relevant.filter((gap) => gap.reason === 'parse-failure' || gap.reason === 'partial-parse');
  if (unanalyzed.length > 0) {
    drafts.push({
      id: 'analysis.unanalyzed-code',
      identity: `unanalyzed:${gapIdentity(unanalyzed, candidate)}`,
      title: `${unanalyzed.length} new or changed code file${unanalyzed.length === 1 ? '' : 's'} was not analyzed`,
      description: `Depdiff ships these paths as code but never read their bytes, so no capability, destination, or obfuscation check ran on them. The analyzed-text limit is ${limits.maxTextBytes.toLocaleString('en-US')} bytes.`,
      category: 'obfuscation',
      severity: 'high',
      score: 25,
      evidence: unanalyzed.slice(0, 8).map((gap) => ({ file: gap.file, message: gap.detail })),
      remediation: 'Raise --max-text-bytes above these files and re-run, or review them by hand. An unanalyzed shipped file can contain anything.',
      tags: ['coverage', 'review-gap', 'unanalyzed'],
    });
  }
  if (parseGaps.length > 0) {
    const partial = parseGaps.some((gap) => gap.reason === 'partial-parse');
    drafts.push({
      id: 'analysis.parse-failure',
      identity: `parse-failure:${gapIdentity(parseGaps, candidate)}`,
      title: `${parseGaps.length} new or changed code file${parseGaps.length === 1 ? '' : 's'} could not be parsed`,
      description: `Syntax analysis ${partial ? 'recovered only part of' : 'failed on'} these files, so capability coverage fell back to lexical checks and is incomplete.`,
      category: 'obfuscation',
      severity: 'high',
      score: 25,
      evidence: parseGaps.slice(0, 8).map((gap) => ({ file: gap.file, message: gap.detail })),
      remediation: 'Confirm the file is expected generated syntax rather than parser evasion, and review it by hand before approving the update.',
      tags: ['coverage', 'review-gap', 'parser'],
    });
  }
  const control = profile.controlBytes.filter((evidence) => evidence.file !== undefined && changed.has(evidence.file));
  if (control.length > 0) {
    drafts.push({
      id: 'obfuscation.control-bytes',
      identity: `control-bytes:${evidenceFileIdentity(control, candidate)}`,
      title: `${control.length} code file${control.length === 1 ? '' : 's'} contains raw control bytes`,
      description: 'Files shipped and loaded as code contain raw control or NUL bytes, which normal source does not and which defeats text/binary heuristics.',
      category: 'obfuscation',
      severity: 'high',
      score: 20,
      evidence: control.slice(0, 8),
      remediation: 'Inspect the raw bytes. Legitimate source has no reason to embed control characters outside string escapes.',
      tags: ['obfuscation', 'control-bytes'],
    });
  }
  return drafts;
}

function gapIdentity(gaps: CoverageGap[], pkg: LoadedPackage): string {
  return [...new Set(gaps.map((gap) => `${gap.file}:${gap.reason}:${pkg.files.get(gap.file)?.sha256 ?? sha256(gap.detail)}`))].sort(compareStrings).join(',');
}

function capabilityFindings(before: StaticProfile, after: StaticProfile, candidate: LoadedPackage): FindingDraft[] {
  const previous = new Set(before.signals.map((signal) => signal.capability));
  const additions = [...new Set(after.signals.map((signal) => signal.capability))].filter((capability) => !previous.has(capability));
  return additions.map((capability) => {
    const risk = CAPABILITY_RISK[capability] ?? {
      severity: 'medium' as const, score: 8, title: `New ${capability} capability`, remediation: 'Review this newly introduced capability.',
    };
    const matching = after.signals.filter((signal) => signal.capability === capability);
    const semanticFiles = [...new Set(matching.map((signal) => {
      const digest = candidate.files.get(signal.file)?.sha256 ?? sha256(`${signal.message}\0${signal.snippet ?? ''}`);
      return `${signal.file}:${digest}`;
    }))].sort();
    return {
      id: `capability.added.${capability}`,
      identity: `capability:${capability}:${semanticFiles.join(',')}`,
      title: risk.title,
      description: `The updated package introduces the ${capability} capability, which was not detected in the previous version.`,
      category: matching[0]?.category ?? 'execution',
      severity: risk.severity,
      score: risk.score,
      evidence: matching.slice(0, 8).map(({ file, line, message, snippet }) => ({ file, ...(line ? { line } : {}), message, ...(snippet ? { snippet } : {}) })),
      remediation: risk.remediation,
      tags: ['capability', capability],
    };
  });
}

function domainFindings(before: StaticProfile, after: StaticProfile): FindingDraft[] {
  const additions = [...after.domains.keys()].filter((domain) => !before.domains.has(domain)).sort();
  if (additions.length === 0) return [];
  const suspicious = additions.some((domain) => isPrivateOrLiteralHost(domain) || looksDisposable(domain));
  return [{
    id: 'network.domains.added',
    identity: `domains:${additions.join(',')}`,
    title: `${additions.length} new network destination${additions.length === 1 ? '' : 's'}`,
    description: `The update adds URL literals for: ${additions.join(', ')}.`,
    category: 'network',
    severity: suspicious ? 'high' : 'medium',
    score: suspicious ? 20 : Math.min(16, 8 + additions.length),
    evidence: additions.flatMap((domain) => after.domains.get(domain) ?? []).slice(0, 12),
    remediation: 'Confirm every destination is owned or expected, and trace which data can be sent to it.',
    tags: ['network', 'domain', ...additions.map((domain) => `domain:${domain}`)],
  }];
}

function isPrivateOrLiteralHost(host: string): boolean {
  return host === 'localhost' || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host);
}

function looksDisposable(host: string): boolean {
  return /(?:ngrok|requestbin|webhook\.site|pastebin|discord(?:app)?\.com)$/i.test(host);
}

function installScriptFindings(metadata: MetadataDiff): FindingDraft[] {
  return metadata.scripts.filter((script) => LIFECYCLE_SCRIPTS.includes(script.name as (typeof LIFECYCLE_SCRIPTS)[number]) && script.after !== undefined && script.after !== script.before).map((script) => {
    const command = script.after ?? '';
    const dangerous = /(?:curl|wget|powershell|certutil|base64|node\s+-e|\/dev\/tcp|child_process|https?:\/\/)/i.test(command);
    const newlyAdded = script.before === undefined;
    return {
      id: newlyAdded ? 'install-script.added' : 'install-script.changed',
      identity: `install-script:${script.name}:${command}`,
      title: `${newlyAdded ? 'New' : 'Changed'} ${script.name} lifecycle script`,
      description: 'npm may execute this lifecycle hook during installation or package preparation.',
      category: 'install',
      severity: dangerous ? 'critical' : newlyAdded ? 'high' : 'medium',
      score: dangerous ? 34 : newlyAdded ? 22 : 10,
      evidence: [{ file: 'package.json', message: `${script.name}: ${truncate(command, 240)}` }],
      remediation: 'Inspect the command and every referenced file. Install with --ignore-scripts until the change is approved.',
      tags: ['lifecycle', script.name],
    };
  });
}

function dependencyFindings(metadata: MetadataDiff): FindingDraft[] {
  const runtimeAdded = metadata.dependencies.filter((change) => change.change === 'added' && change.scope !== 'development');
  if (runtimeAdded.length === 0) return [];
  return [{
    id: 'dependencies.runtime.added',
    identity: `dependencies:${runtimeAdded.map((change) => `${change.scope}:${change.name}@${change.after}`).join(',')}`,
    title: `${runtimeAdded.length} new shipped dependenc${runtimeAdded.length === 1 ? 'y' : 'ies'}`,
    description: 'New runtime, optional, or peer dependencies expand the package supply-chain and install surface.',
    category: 'dependency',
    severity: runtimeAdded.length > 10 ? 'medium' : 'low',
    score: Math.min(14, 3 + runtimeAdded.length),
    evidence: runtimeAdded.slice(0, 20).map((change) => ({ file: 'package.json', message: `${change.scope}: ${change.name}@${change.after ?? '(unknown)'}` })),
    remediation: 'Review the ownership, release age, lifecycle scripts, and transitive tree of each added dependency.',
    tags: ['dependency'],
  }];
}

function inventoryFindings(
  before: LoadedPackage,
  after: LoadedPackage,
  inventory: InventoryDiff,
): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const binaries = inventory.added.filter((file) => file.kind === 'binary' || BINARY_EXTENSIONS.has(codeExtension(file.path)));
  if (binaries.length > 0) {
    const native = binaries.some((file) => NATIVE_BINARY_EXTENSIONS.has(codeExtension(file.path)));
    drafts.push({
      id: native ? 'binary.native.added' : 'binary.added',
      identity: `binaries:${binaries.map((file) => `${file.path}:${file.sha256}`).join(',')}`,
      title: `${binaries.length} new ${native ? 'native ' : ''}binary file${binaries.length === 1 ? '' : 's'}`,
      description: 'Binary payloads are difficult to review with ordinary source diffs and may execute outside JavaScript controls.',
      category: 'binary',
      severity: native ? 'high' : 'medium',
      score: native ? 22 : 10,
      evidence: binaries.slice(0, 12).map((file) => ({ file: file.path, message: `${file.size} bytes · sha256 ${file.sha256.slice(0, 16)}…` })),
      remediation: 'Rebuild binaries from source, verify checksums and signatures, and inspect platform-specific loading paths.',
      tags: ['binary', ...(native ? ['native'] : [])],
    });
  }
  const changedBinaries = inventory.modified.filter(({ after: file }) => file.kind === 'binary' || BINARY_EXTENSIONS.has(codeExtension(file.path)));
  if (changedBinaries.length > 0) {
    const native = changedBinaries.some(({ after: file }) => NATIVE_BINARY_EXTENSIONS.has(codeExtension(file.path)));
    drafts.push({
      id: native ? 'binary.native.changed' : 'binary.changed',
      identity: `changed-binaries:${changedBinaries.map(({ before: previous, after: next }) => `${next.path}:${previous.sha256}:${next.sha256}`).join(',')}`,
      title: `${changedBinaries.length} ${native ? 'native ' : ''}binary file${changedBinaries.length === 1 ? '' : 's'} changed`,
      description: 'Previously shipped binary payloads changed bytes or changed from reviewable text into binary data.',
      category: 'binary',
      severity: native ? 'high' : 'medium',
      score: native ? 22 : 10,
      evidence: changedBinaries.slice(0, 12).map(({ before: previous, after: next }) => ({
        file: next.path,
        message: `sha256 ${previous.sha256.slice(0, 16)}… → ${next.sha256.slice(0, 16)}…`,
      })),
      remediation: 'Rebuild the changed binaries from reviewed source and verify their checksums, signatures, and loading paths.',
      tags: ['binary', 'changed', ...(native ? ['native'] : [])],
    });
  }
  const executables = inventory.added.filter((file) => file.kind !== 'binary' && (file.mode & 0o111) !== 0);
  if (executables.length > 0) {
    drafts.push({
      id: 'files.executable.added',
      identity: `executables:${executables.map((file) => `${file.path}:${file.sha256}:${file.mode}`).join(',')}`,
      title: `${executables.length} new executable file${executables.length === 1 ? '' : 's'}`,
      description: 'The update ships new files marked executable.',
      category: 'execution',
      severity: 'medium',
      score: Math.min(15, 8 + executables.length),
      evidence: executables.slice(0, 12).map((file) => ({ file: file.path, message: `Mode ${(file.mode & 0o777).toString(8)}` })),
      remediation: 'Review each executable entry point and verify it is expected to ship in the npm tarball.',
      tags: ['executable', 'inventory'],
    });
  }
  const executableTransitions = inventory.modified.filter(({ before: previous, after: next }) =>
    next.kind !== 'binary' && (previous.mode & 0o111) === 0 && (next.mode & 0o111) !== 0,
  );
  if (executableTransitions.length > 0) {
    drafts.push({
      id: 'files.executable.changed',
      identity: `changed-executables:${executableTransitions.map(({ before: previous, after: next }) => `${next.path}:${previous.mode}:${next.mode}:${next.sha256}`).join(',')}`,
      title: `${executableTransitions.length} existing file${executableTransitions.length === 1 ? '' : 's'} became executable`,
      description: 'The update added executable permission bits to files that were previously non-executable.',
      category: 'execution', severity: 'medium', score: Math.min(15, 8 + executableTransitions.length),
      evidence: executableTransitions.slice(0, 12).map(({ before: previous, after: next }) => ({
        file: next.path,
        message: `Mode ${(previous.mode & 0o777).toString(8)} → ${(next.mode & 0o777).toString(8)}`,
      })),
      remediation: 'Confirm why each existing file became executable and inspect every invocation path.',
      tags: ['executable', 'inventory', 'changed'],
    });
  }
  const links = inventory.added.filter((file) => file.kind === 'symlink');
  if (links.length > 0) {
    drafts.push({
      id: 'files.symlink.added', identity: `symlinks:${links.map((file) => `${file.path}:${file.sha256}`).join(',')}`,
      title: `${links.length} new symbolic link${links.length === 1 ? '' : 's'}`,
      description: 'Local directory input contains new symlinks. Depdiff records but never follows them.',
      category: 'inventory', severity: 'medium', score: 8,
      evidence: links.map((file) => ({ file: file.path, message: `Link fingerprint ${file.sha256.slice(0, 16)}…` })).slice(0, 12),
      remediation: 'Verify every link target and ensure packaging does not redirect consumers outside the package root.', tags: ['symlink'],
    });
  }
  const changedLinks = inventory.modified.filter(({ before: previous, after: next }) =>
    next.kind === 'symlink' && (previous.kind !== 'symlink' || previous.sha256 !== next.sha256),
  );
  if (changedLinks.length > 0) {
    drafts.push({
      id: 'files.symlink.changed', identity: `changed-symlinks:${changedLinks.map(({ before: previous, after: next }) => `${next.path}:${previous.sha256}:${next.sha256}`).join(',')}`,
      title: `${changedLinks.length} symbolic link${changedLinks.length === 1 ? '' : 's'} changed`,
      description: 'Local directory input contains symlinks whose targets or file kind changed.',
      category: 'inventory', severity: 'medium', score: 8,
      evidence: changedLinks.slice(0, 12).map(({ before: previous, after: next }) => ({
        file: next.path,
        message: `Link fingerprint ${previous.sha256.slice(0, 16)}… → ${next.sha256.slice(0, 16)}…`,
      })),
      remediation: 'Verify each changed link target and ensure packaging cannot redirect consumers outside the package root.',
      tags: ['symlink', 'changed'],
    });
  }
  const delta = after.snapshot.totalBytes - before.snapshot.totalBytes;
  if (delta > Math.max(1_000_000, before.snapshot.totalBytes * 1.5)) {
    drafts.push({
      id: 'inventory.size.spike', identity: `size-spike:${before.snapshot.totalBytes}:${after.snapshot.totalBytes}`,
      title: 'Package size increased sharply',
      description: `The unpacked package grew by ${delta.toLocaleString('en-US')} bytes.`,
      category: 'inventory', severity: 'medium', score: 8,
      evidence: [{ message: `${before.snapshot.totalBytes.toLocaleString('en-US')} → ${after.snapshot.totalBytes.toLocaleString('en-US')} unpacked bytes` }],
      remediation: 'Confirm the growth is explained by intended source, assets, or platform artifacts.', tags: ['size', 'inventory'],
    });
  }
  return drafts;
}

function obfuscationFindings(before: LoadedPackage, after: LoadedPackage, inventory: InventoryDiff): FindingDraft[] {
  const changedPaths = new Set([...inventory.added.map((file) => file.path), ...inventory.modified.map((file) => file.after.path)]);
  const encoded: Evidence[] = [];
  const minified: Evidence[] = [];
  const entropySpikes: Evidence[] = [];
  const generated: Evidence[] = [];
  for (const filePath of changedPaths) {
    const next = after.files.get(filePath);
    if (!next || next.kind !== 'text') continue;
    const extension = codeExtension(filePath);
    if (next.size > 1_000_000 || (next.size > 100_000 && [...GENERATED_EXTENSIONS].some((suffix) => filePath.endsWith(suffix)))) {
      generated.push({ file: filePath, message: `${next.size.toLocaleString('en-US')} byte generated/minified payload.` });
    }
    if (!next.content) continue;
    const text = next.content.toString('utf8');
    if (CODE_EXTENSIONS.has(extension)) {
      const lines = text.split(/\r?\n/);
      const longest = lines.reduce((max, line) => Math.max(max, line.length), 0);
      const average = text.length / Math.max(1, lines.length);
      if ((longest > 500 && average > 250) || (text.length > 40_000 && lines.length < 12)) {
        minified.push({ file: filePath, message: `${text.length.toLocaleString('en-US')} characters across ${lines.length} lines; longest line ${longest.toLocaleString('en-US')}.` });
      }
    }
    const token = findEncodedToken(text);
    if (token) encoded.push({ file: filePath, line: lineNumberAt(text, token.index), message: `${token.kind} blob (${token.length.toLocaleString('en-US')} characters, entropy ${token.entropy.toFixed(2)} bits/byte).`, snippet: truncate(lineAt(text, token.index)) });
    const previous = before.files.get(filePath);
    if (previous?.content && previous.kind === 'text' && next.content.length >= 1_024) {
      const oldEntropy = shannonEntropy(previous.content);
      const newEntropy = shannonEntropy(next.content);
      if (newEntropy > 5.2 && newEntropy - oldEntropy > 0.8) {
        entropySpikes.push({ file: filePath, message: `Entropy increased from ${oldEntropy.toFixed(2)} to ${newEntropy.toFixed(2)} bits/byte.` });
      }
    }
  }
  const drafts: FindingDraft[] = [];
  if (encoded.length > 0) drafts.push({
    id: 'obfuscation.encoded-payload', identity: `encoded:${evidenceFileIdentity(encoded, after)}`,
    title: 'High-entropy encoded payload added', description: 'New or changed files contain unusually long Base64/hex-like blobs.',
    category: 'obfuscation', severity: 'high', score: 20, evidence: encoded.slice(0, 10),
    remediation: 'Decode the payload in an isolated review environment, identify its generator, and compare it with reproducible source.', tags: ['entropy', 'encoded'],
  });
  if (entropySpikes.length > 0) drafts.push({
    id: 'obfuscation.entropy-spike', identity: `entropy:${evidenceFileIdentity(entropySpikes, after)}`,
    title: 'File entropy increased sharply', description: 'Changed files became substantially less human-readable.', category: 'obfuscation',
    severity: 'medium', score: 10, evidence: entropySpikes.slice(0, 10),
    remediation: 'Compare generated artifacts with their source and reproduce the build before trusting the update.', tags: ['entropy'],
  });
  if (minified.length > 0 || generated.length > 0) drafts.push({
    id: 'payload.generated.added', identity: `generated:${evidenceFileIdentity([...minified, ...generated], after)}`,
    title: 'New or changed generated payload', description: 'Dense, generated, or unusually large code reduces the usefulness of normal human review.', category: 'obfuscation',
    severity: generated.length > 0 ? 'medium' : 'low', score: generated.length > 0 ? 10 : 4, evidence: [...minified, ...generated].slice(0, 12),
    remediation: 'Prefer source distributions, validate source maps, and reproduce the published bundle from the tagged source.', tags: ['minified', 'generated'],
  });
  return drafts;
}

function findEncodedToken(text: string): { index: number; length: number; entropy: number; kind: string } | undefined {
  const patterns: Array<[RegExp, string]> = [
    [/[A-Za-z0-9+/]{240,}={0,2}/g, 'Base64-like'],
    [/(?:[a-fA-F0-9]{2}){180,}/g, 'hex-like'],
  ];
  for (const [pattern, kind] of patterns) {
    const match = pattern.exec(text);
    if (!match?.[0]) continue;
    const entropy = shannonEntropy(Buffer.from(match[0]));
    if (entropy >= 3.5) return { index: match.index, length: match[0].length, entropy, kind };
  }
  return undefined;
}

export function shannonEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] = (counts[byte] ?? 0) + 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function metadataFindings(before: LoadedPackage, after: LoadedPackage, metadata: MetadataDiff): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (metadata.maintainersAdded.length > 0 || metadata.maintainersRemoved.length > 0) {
    drafts.push({
      id: 'metadata.maintainers.changed',
      identity: `maintainers:${metadata.maintainersAdded.join(',')}:${metadata.maintainersRemoved.join(',')}`,
      title: 'Maintainer set changed',
      description: 'A publisher or maintainer transition can be legitimate, but it is a high-value supply-chain review point.',
      category: 'metadata', severity: 'high', score: 20,
      evidence: [
        ...metadata.maintainersAdded.map((name) => ({ message: `Added: ${name}` })),
        ...metadata.maintainersRemoved.map((name) => ({ message: `Removed: ${name}` })),
      ],
      remediation: 'Verify the change through the project repository and established maintainer channels before updating.', tags: ['maintainer', 'ownership'],
    });
  }
  for (const change of metadata.packageFields) {
    if (!['name', 'repository'].includes(change.field)) continue;
    drafts.push({
      id: `metadata.${change.field.replace(' ', '-')}.changed`,
      identity: `metadata:${change.field}:${change.before ?? ''}:${change.after ?? ''}`,
      title: `Package ${change.field} changed`,
      description: `The published ${change.field} metadata changed between versions.`, category: 'metadata',
      severity: change.field === 'name' ? 'high' : 'medium', score: change.field === 'name' ? 20 : 8,
      evidence: [{ file: 'package.json', message: `${change.before ?? '(missing)'} → ${change.after ?? '(missing)'}` }],
      remediation: 'Verify the change against the canonical repository and release notes.', tags: ['metadata', change.field],
    });
  }
  if (before.snapshot.package.name !== '(unknown package)' && after.snapshot.package.name !== before.snapshot.package.name) {
    // Covered above; this branch makes the package-name invariant explicit for readers and future extensions.
  }
  return drafts;
}

function provenanceFindings(before: LoadedPackage, after: LoadedPackage): FindingDraft[] {
  const previous = before.snapshot.source;
  const next = after.snapshot.source;
  if (previous.kind !== 'registry' || next.kind !== 'registry') return [];
  const drafts: FindingDraft[] = [];
  if (previous.provenance?.attestations && !next.provenance?.attestations) {
    drafts.push({
      id: 'provenance.attestations.removed', identity: 'provenance:attestations-removed', title: 'Registry attestation disappeared',
      description: 'The previous package version advertised attestations but the updated version does not.', category: 'provenance',
      severity: 'high', score: 20, evidence: [{ message: 'attestations: present → absent' }],
      remediation: 'Confirm the release workflow change with maintainers and inspect the npm provenance record.', tags: ['provenance', 'attestation'],
    });
  }
  if (previous.provenance?.signatures && !next.provenance?.signatures) {
    drafts.push({
      id: 'provenance.signatures.removed', identity: 'provenance:signatures-removed', title: 'Registry signatures disappeared',
      description: 'The previous package version advertised registry signatures but the update does not.', category: 'provenance',
      severity: 'high', score: 18, evidence: [{ message: 'signatures: present → absent' }],
      remediation: 'Verify the registry metadata and release provenance before approving the update.', tags: ['provenance', 'signature'],
    });
  }
  if (!next.integrity) {
    drafts.push({
      id: 'provenance.integrity.missing', identity: 'provenance:integrity-missing', title: 'Registry integrity metadata is missing',
      description: 'The updated tarball has no Subresource Integrity value in registry metadata.', category: 'provenance', severity: 'high', score: 20,
      evidence: [{ message: `${next.resolved} has no dist.integrity value.` }],
      remediation: 'Do not approve the package until its tarball digest can be authenticated independently.', tags: ['provenance', 'integrity'],
    });
  }
  return drafts;
}

function deduplicateFindings(drafts: FindingDraft[], packageName: string): Finding[] {
  const unique = new Map<string, Finding>();
  for (const { identity, ...draft } of drafts) {
    const fingerprint = sha256(`${packageName}\0${draft.id}\0${identity}`).slice(0, 32);
    if (!unique.has(fingerprint)) unique.set(fingerprint, { ...draft, fingerprint, status: 'new' });
  }
  return [...unique.values()];
}

function evidenceFileIdentity(evidence: Evidence[], pkg: LoadedPackage): string {
  return [...new Set(evidence.map((entry) => {
    const digest = entry.file ? pkg.files.get(entry.file)?.sha256 : undefined;
    return `${entry.file ?? '(global)'}:${digest ?? sha256(`${entry.message}\0${entry.snippet ?? ''}`)}`;
  }))].sort().join(',');
}

function compareFinding(a: Finding, b: Finding): number {
  const ranks: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return ranks[b.severity] - ranks[a.severity] || b.score - a.score || compareStrings(a.id, b.id);
}

export function summarizeRisk(findings: Finding[]): RiskSummary {
  const active = findings.filter((finding) => finding.status === 'new');
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of active) counts[finding.severity] += 1;
  const rawScore = active.reduce((sum, finding) => sum + finding.score, 0);
  const score = Math.min(100, rawScore);
  const level: RiskSummary['level'] = score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'none';
  return {
    score,
    level,
    counts,
    newFindings: active.length,
    baselineFindings: findings.length - active.length,
  };
}

function uniqueSignals(signals: CapabilitySignal[]): CapabilitySignal[] {
  const seen = new Set<string>();
  const unique = signals.filter((signal) => {
    const key = `${signal.capability}:${signal.file}:${signal.line ?? 0}:${signal.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  // Sorted so evidence order never depends on traversal or filesystem order.
  return unique.sort((a, b) => compareStrings(
    `${a.file}\0${String(a.line ?? 0).padStart(9, '0')}\0${a.capability}\0${a.message}`,
    `${b.file}\0${String(b.line ?? 0).padStart(9, '0')}\0${b.capability}\0${b.message}`,
  ));
}

function lineNumberAt(source: string, index: number): number {
  return source.slice(0, index).split('\n').length;
}

function lineAt(source: string, index: number): string {
  const start = source.lastIndexOf('\n', index - 1) + 1;
  const end = source.indexOf('\n', index);
  return source.slice(start, end === -1 ? source.length : end);
}

export const __test = { diffInventory, diffMetadata, profilePackage, findEncodedToken, lineNumberAt };
