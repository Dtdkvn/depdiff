import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli } from '../src/cli.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(projectRoot, 'src', 'cli.ts');
const tsx = path.join(projectRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');
const temporaryPaths: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe('CLI contract', () => {
  it('maps Commander syntax failures to invalid-input exit code 2', async () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(await runCli(['node', 'depdiff', '--definitely-bad'])).toBe(2);
    process.exitCode = undefined;
    expect(await runCli(['node', 'depdiff', 'compare'])).toBe(2);
    expect((await runProcess(['--definitely-bad'])).code).toBe(2);
    expect((await runProcess(['compare'])).code).toBe(2);
  });

  it('rejects colliding report destinations before writing', async () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-cli-collision-'));
    temporaryPaths.push(root);
    const output = path.join(root, 'same-output');
    expect(await runCli([
      'node', 'depdiff', 'compare', safe, risky, '--offline', '--output', output, '--json', output,
    ])).toBe(2);
    await expect(readFile(output, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('creates init policy files exclusively under concurrent processes', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-cli-init-'));
    temporaryPaths.push(root);
    const policy = path.join(root, '.depdiff.yml');
    const results = await Promise.all([runProcess(['init', policy]), runProcess(['init', policy])]);
    expect(results.map((result) => result.code).sort()).toEqual([0, 2]);
    expect(await readFile(policy, 'utf8')).toContain('version: 1');
    await writeFile(policy, 'sentinel', 'utf8');
    expect((await runProcess(['init', policy, '--force'])).code).toBe(0);
    expect(await readFile(policy, 'utf8')).toContain('version: 1');
  });

  it('keeps package-controlled newlines and ANSI controls on one safe terminal line', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-cli-terminal-'));
    temporaryPaths.push(root);
    const before = path.join(root, 'before');
    const after = path.join(root, 'after');
    await mkdir(before);
    await mkdir(after);
    const name = 'safe\n::warning::forged\u001b[31m';
    await writeFile(path.join(before, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
    await writeFile(path.join(after, 'package.json'), JSON.stringify({ name, version: '1.1.0' }));
    const result = await runProcess([
      'compare', before, after, '--offline', '--no-fail', '--output', path.join(root, 'report.html'),
    ], root);
    expect(result.code).toBe(0);
    expect(result.stdout).not.toMatch(/(?:^|\n)::warning::forged/);
    expect(result.stdout).not.toContain('\u001b');
  });
});

async function runProcess(arguments_: string[], cwd = projectRoot): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [tsx, cli, ...arguments_], {
      cwd,
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) reject(new Error(`CLI terminated by ${signal}`));
      else resolve({ code: code ?? 3, stdout, stderr });
    });
  });
}
