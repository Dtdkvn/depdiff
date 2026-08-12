import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const projectRoot = path.resolve(import.meta.dirname, '..');
const npmProcessUrl = pathToFileURL(path.join(projectRoot, 'scripts', 'npm-process.mjs')).href;

describe('spawnNpm', () => {
  it('ignores a hostile npm_execpath and runs the trusted npm CLI', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'depdiff-npm-process-'));
    const marker = path.join(temporaryRoot, 'executed');
    const hostileCli = path.join(temporaryRoot, 'hostile-npm.mjs');

    await writeFile(hostileCli, [
      "import { writeFileSync } from 'node:fs';",
      `writeFileSync(${JSON.stringify(marker)}, 'executed');`,
    ].join('\n'));

    try {
      const environment = Object.fromEntries(
        Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'npm_execpath'),
      );
      const probe = [
        `import { spawnNpm } from ${JSON.stringify(npmProcessUrl)};`,
        "const result = spawnNpm(['--version'], { encoding: 'utf8', env: process.env, windowsHide: true });",
        'if (result.error) throw result.error;',
        'process.stdout.write(JSON.stringify({ status: result.status, stdout: result.stdout, stderr: result.stderr }));',
      ].join('\n');
      const child = spawnSync(process.execPath, ['--input-type=module', '--eval', probe], {
        encoding: 'utf8',
        env: { ...environment, npm_execpath: hostileCli },
        windowsHide: true,
      });

      expect(child.status, child.stderr).toBe(0);
      expect(existsSync(marker)).toBe(false);
      const result = JSON.parse(child.stdout) as { status: number | null; stdout: string; stderr: string };
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+(?:-.+)?$/);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
});
