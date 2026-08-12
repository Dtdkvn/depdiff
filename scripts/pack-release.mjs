import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnNpm } from './npm-process.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageDocument = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8'));
const outputDirectory = path.join(projectRoot, 'release-artifacts');
await mkdir(outputDirectory);

const packed = spawnNpm([
  'pack', '--ignore-scripts', '--json', '--loglevel=error', '--pack-destination', outputDirectory,
], { cwd: projectRoot, encoding: 'utf8', env: process.env, windowsHide: true });
if (packed.error) throw packed.error;
if (packed.status !== 0) throw new Error(`npm pack failed: ${packed.stderr || packed.stdout}`);
const records = JSON.parse(packed.stdout);
if (!Array.isArray(records) || records.length !== 1 || typeof records[0]?.filename !== 'string') {
  throw new Error('npm pack did not produce exactly one release tarball.');
}
const record = records[0];
const filename = path.basename(record.filename);
if (filename !== record.filename) throw new Error(`npm pack returned an unsafe filename: ${record.filename}`);
const tarball = path.join(outputDirectory, filename);
const details = await stat(tarball);
if (!details.isFile() || details.size === 0) throw new Error('Release tarball is missing or empty.');

const requiredFiles = [
  'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md',
  'docs/architecture.md', 'docs/cli.md', 'docs/LAUNCH.md', 'docs/policy.md', 'docs/rules.md', 'docs/releasing.md',
  'docs/assets/demo.gif', 'docs/assets/report-preview.png', 'examples/github-action.yml',
];
const packedFiles = new Set(record.files?.map((entry) => entry.path));
for (const required of requiredFiles) {
  if (!packedFiles.has(required)) throw new Error(`Release tarball is missing required file ${required}.`);
}

const shasum = await hashFile(tarball, 'sha1', 'hex');
const integrity = `sha512-${await hashFile(tarball, 'sha512', 'base64')}`;
if (record.shasum !== shasum || record.integrity !== integrity) {
  throw new Error('Independent tarball digests do not match npm pack output.');
}
const relativeTarball = path.relative(projectRoot, tarball).split(path.sep).join('/');
const manifest = {
  name: packageDocument.name,
  version: packageDocument.version,
  tarball: relativeTarball,
  size: details.size,
  shasum,
  integrity,
};
await writeFile(path.join(outputDirectory, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
await writeOutput({
  tarball: relativeTarball,
  artifact_name: `${packageDocument.name}-${packageDocument.version}`.replace('@', '').replace('/', '-'),
  shasum,
  integrity,
});
process.stdout.write(`Packed once: ${relativeTarball} (${details.size} bytes, sha1 ${shasum}).\n`);

async function hashFile(file, algorithm, encoding) {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest(encoding);
}

async function writeOutput(values) {
  if (!process.env.GITHUB_OUTPUT) return;
  await appendFile(process.env.GITHUB_OUTPUT, `${Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n')}\n`, 'utf8');
}
