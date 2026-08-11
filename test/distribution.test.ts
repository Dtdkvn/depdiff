import { spawnSync } from 'node:child_process';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('distribution contracts', () => {
  it('ships a valid Docker Action metadata layout with explicit input arguments', async () => {
    const action = parseYaml(await readFile(path.join(projectRoot, 'action.yml'), 'utf8')) as {
      inputs: Record<string, { default?: string }>;
      runs: { using: string; image: string; args: string[] };
    };
    expect(action.runs.using).toBe('docker');
    expect(path.basename(action.runs.image)).toBe('Dockerfile');
    await expect(access(path.join(projectRoot, action.runs.image))).resolves.toBeUndefined();
    expect(action.runs.args).toHaveLength(8);
    expect(action.runs.args.join('\n')).toContain('inputs.before');
    expect(action.runs.args[4]).toContain("inputs['fail-on']");
    expect(action.inputs['fail-on']?.default).toBeUndefined();
    const entrypoint = await readFile(path.join(projectRoot, 'scripts', 'action-entrypoint.mjs'), 'utf8');
    expect(entrypoint).not.toContain('INPUT_FAIL_ON');
    expect(entrypoint).toContain("addOptional(args, '--fail-on', failOn)");
    const missingInput = spawnSync(process.execPath, [path.join(projectRoot, 'scripts', 'action-entrypoint.mjs')], { encoding: 'utf8' });
    expect(missingInput.status).toBe(2);
    expect(missingInput.stderr).toContain('Missing required Action input: before');
  });

  it('pins CI Actions and container bases and guards release tag versions', async () => {
    const workflows = await Promise.all(['ci.yml', 'release.yml'].map((file) => readFile(path.join(projectRoot, '.github', 'workflows', file), 'utf8')));
    const consumerExamples = await Promise.all([
      readFile(path.join(projectRoot, 'examples', 'github-action.yml'), 'utf8'),
      readFile(path.join(projectRoot, 'README.md'), 'utf8'),
    ]);
    for (const document of [...workflows, ...consumerExamples]) {
      for (const match of document.matchAll(/^\s*(?:-\s*)?uses:\s+([^./\s][^@\s]*)@([^\s#]+)/gm)) {
        expect(match[2], `${match[1]} must use a full commit SHA`).toMatch(/^[a-f0-9]{40}$/);
      }
    }
    expect(workflows[0]).toContain('uses: ./');
    expect(workflows[1]).toContain('GITHUB_REF_NAME');
    for (const file of ['Dockerfile', path.join('action', 'Dockerfile')]) {
      const dockerfile = await readFile(path.join(projectRoot, file), 'utf8');
      expect(dockerfile.match(/^FROM .+@sha256:[a-f0-9]{64}/gm)?.length).toBe(2);
      expect(dockerfile).toContain('sharing=locked');
      expect(dockerfile).toContain('test -x node_modules/.bin/tsc');
      expect(dockerfile).toContain("require.resolve(name)");
      expect(dockerfile).toContain('id=depdiff_ca,required=false');
      expect(dockerfile).toContain('node:24-alpine@sha256:');
      expect(dockerfile).toContain('apk upgrade --no-cache');
      expect(dockerfile).toContain('cat /etc/ssl/certs/ca-certificates.crt /run/secrets/depdiff_ca');
      expect(dockerfile).toContain('rm -f /tmp/depdiff-ca-bundle.pem');
      expect(dockerfile).toContain('rm -rf /usr/local/lib/node_modules/npm');
      expect(dockerfile).toContain('rm -f /usr/local/bin/npm');
    }
  });

  it('does not publish an orphaned Action manifest in the npm package', async () => {
    const packageDocument = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8')) as { files: string[] };
    expect(packageDocument.files).not.toContain('action.yml');
  });
});
