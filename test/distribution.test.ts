import { spawnSync } from 'node:child_process';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const canonicalRepository = 'https://github.com/yewud/depdiff';

describe('distribution contracts', () => {
  it('ships a valid Docker Action metadata layout with explicit input arguments', async () => {
    const action = parseYaml(await projectFile('action.yml')) as {
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
    const entrypoint = await projectFile('scripts/action-entrypoint.mjs');
    expect(entrypoint).not.toContain('INPUT_FAIL_ON');
    expect(entrypoint).toContain("addOptional(args, '--fail-on', failOn)");
    const missingInput = spawnSync(process.execPath, [path.join(projectRoot, 'scripts', 'action-entrypoint.mjs')], { encoding: 'utf8' });
    expect(missingInput.status).toBe(2);
    expect(missingInput.stderr).toContain('Missing required Action input: before');
  });

  it('supports only maintained Node releases and gates packages and artifacts on Node 24', async () => {
    const packageDocument = JSON.parse(await projectFile('package.json')) as {
      engines: { node: string };
      packageManager: string;
    };
    expect(packageDocument.engines.node).toBe('>=22');
    expect(packageDocument.packageManager).toBe('npm@11.17.0');
    const lockDocument = JSON.parse(await projectFile('package-lock.json')) as {
      packages: Record<string, { engines?: { node?: string } }>;
    };
    expect(lockDocument.packages['']?.engines?.node).toBe('>=22');
    expect((await projectFile('.nvmrc')).trim()).toBe('24');

    const ci = parseYaml(await projectFile('.github/workflows/ci.yml')) as {
      jobs: {
        quality: {
          strategy: { matrix: { node: number[] } };
          steps: Array<{ uses?: string; run?: string; if?: string }>;
        };
      };
    };
    expect(ci.jobs.quality.strategy.matrix.node).toEqual([22, 24]);
    expect(ci.jobs.quality.steps.find((step) => step.run === 'npm run test:package')?.if).toBe('matrix.node == 24');
    expect(ci.jobs.quality.steps.find((step) => step.uses?.startsWith('actions/upload-artifact@'))?.if).toBe('matrix.node == 24');

    for (const file of ['Dockerfile', path.join('action', 'Dockerfile')]) {
      const dockerfile = await projectFile(file);
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

  it('uses the canonical repository in package, report, schema, and contributor metadata', async () => {
    const packageDocument = JSON.parse(await projectFile('package.json')) as {
      repository: { url: string };
      bugs: { url: string };
      homepage: string;
    };
    expect(packageDocument.repository.url).toBe(`git+${canonicalRepository}.git`);
    expect(packageDocument.bugs.url).toBe(`${canonicalRepository}/issues`);
    expect(packageDocument.homepage).toBe(`${canonicalRepository}#readme`);
    expect(await projectFile('src/reports.ts')).toContain(`informationUri: '${canonicalRepository}'`);
    const policySchema = JSON.parse(await projectFile('schemas/policy.schema.json')) as { $id: string };
    const reportSchema = JSON.parse(await projectFile('schemas/report.schema.json')) as { $id: string };
    expect(policySchema.$id).toBe('https://raw.githubusercontent.com/yewud/depdiff/main/schemas/policy.schema.json');
    expect(reportSchema.$id).toBe('https://raw.githubusercontent.com/yewud/depdiff/main/schemas/report.schema.json');
    for (const file of ['README.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'SECURITY.md', 'PROGRESS.md']) {
      expect(await projectFile(file), file).toContain(canonicalRepository);
    }
    expect(await projectFile('examples/github-action.yml')).toContain('uses: yewud/depdiff@');
    const progress = await projectFile('PROGRESS.md');
    expect(progress).toContain('no remote configured');
    expect(progress).toContain('not been pushed or published to npm');
  });

  it('pins dependencies and enforces the fail-closed release contract', async () => {
    const ci = await projectFile('.github/workflows/ci.yml');
    const release = await projectFile('.github/workflows/release.yml');
    const consumerExamples = await Promise.all([
      projectFile('examples/github-action.yml'),
      projectFile('README.md'),
    ]);
    for (const document of [ci, release, ...consumerExamples]) {
      for (const match of document.matchAll(/^\s*(?:-\s*)?uses:\s+([^./\s][^@\s]*)@([^\s#]+)/gm)) {
        expect(match[2], `${match[1]} must use a full commit SHA`).toMatch(/^[a-f0-9]{40}$/);
      }
    }
    expect(ci).toContain('uses: ./');

    const parsed = parseYaml(release) as {
      permissions: Record<string, string>;
      jobs: { npm: { steps: Array<{ uses?: string; with?: Record<string, unknown> }> } };
    };
    expect(parsed.permissions).toEqual({ contents: 'read', 'id-token': 'write' });
    const checkout = parsed.jobs.npm.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
    expect(checkout?.with).toMatchObject({ 'fetch-depth': 0, 'persist-credentials': false });
    const setupNode = parsed.jobs.npm.steps.find((step) => step.uses?.startsWith('actions/setup-node@'));
    expect(setupNode?.with?.['node-version']).toBe(24);
    expect(release.match(/NODE_AUTH_TOKEN/g)).toHaveLength(1);
    const verifyIndex = release.indexOf('scripts/verify-release.mjs');
    const installIndex = release.indexOf('npm ci --ignore-scripts');
    const packIndex = release.indexOf('scripts/pack-release.mjs');
    const smokeIndex = release.indexOf('scripts/package-smoke.mjs');
    const uploadIndex = release.indexOf('actions/upload-artifact@');
    const tokenIndex = release.indexOf('NODE_AUTH_TOKEN');
    expect(verifyIndex).toBeLessThan(installIndex);
    expect(installIndex).toBeLessThan(packIndex);
    expect(packIndex).toBeLessThan(smokeIndex);
    expect(smokeIndex).toBeLessThan(uploadIndex);
    expect(uploadIndex).toBeLessThan(tokenIndex);
    expect(release).toContain('scripts/pack-release.mjs');
    expect(release).toContain('scripts/package-smoke.mjs "${{ steps.pack.outputs.tarball }}"');
    expect(release).toContain('scripts/publish-release.mjs');
    expect(release).not.toMatch(/\bnpm publish\b/);

    const verifier = await projectFile('scripts/verify-release.mjs');
    expect(verifier).toContain('strictSemVer');
    expect(verifier).toContain('refs/remotes/origin/main^{commit}');
    expect(verifier).toContain("['merge-base', '--is-ancestor'");
    expect(verifier).toContain('tag !== `v${version}`');
    expect(verifier).toContain('taggedCommit !== eventCommit');

    const packer = await projectFile('scripts/pack-release.mjs');
    expect(packer.match(/['"]pack['"]/g)).toHaveLength(1);
    expect(packer).toContain("hashFile(tarball, 'sha1'");
    expect(packer).toContain("hashFile(tarball, 'sha512'");
    expect(packer).toContain("'docs/releasing.md'");
    expect(packer).toContain("'examples/github-action.yml'");

    const publisher = await projectFile('scripts/publish-release.mjs');
    expect(publisher).toContain("'dist.shasum'");
    expect(publisher).toContain('existing.shasum !== localShasum');
    expect(publisher).toContain("'publish', tarball");
    expect(publisher).toContain("'--provenance'");
    expect(publisher).toContain('Release tarball changed after the pack step.');
  });

  it('packs all user-facing documentation and validates local Markdown targets', async () => {
    const packageDocument = JSON.parse(await projectFile('package.json')) as { files: string[]; scripts: Record<string, string> };
    expect(packageDocument.files).toEqual(expect.arrayContaining([
      'docs', 'examples', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md',
    ]));
    expect(packageDocument.files).not.toContain('action.yml');
    expect(packageDocument.scripts['test:package']).toBe('node scripts/package-smoke.mjs');
    const smoke = await projectFile('scripts/package-smoke.mjs');
    expect(smoke).toContain('collectMarkdownFiles(packageRoot)');
    expect(smoke).toContain('Supplied package smoke tarball must be a .tgz inside the project.');
    expect(smoke).toContain('Packed Markdown target escapes the package');
    expect(smoke).toContain("'docs/assets/demo.gif'");
    expect(smoke).toContain("'docs/assets/report-preview.png'");
  });
});

async function projectFile(relative: string): Promise<string> {
  return readFile(path.join(projectRoot, relative), 'utf8');
}
