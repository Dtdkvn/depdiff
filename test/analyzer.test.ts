import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { shannonEntropy } from '../src/analyzer.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');
const temporaryPaths: string[] = [];

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
