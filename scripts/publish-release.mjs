import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnNpm } from './npm-process.mjs';

const [tarballInput, expectedName, expectedVersion, expectedShasum] = process.argv.slice(2);
if (!tarballInput || !expectedName || !expectedVersion || !/^[a-f0-9]{40}$/i.test(expectedShasum ?? '')) {
  throw new Error('Usage: publish-release.mjs <tarball> <name> <version> <sha1>.');
}
const projectRoot = process.cwd();
const releaseRoot = path.resolve(projectRoot, 'release-artifacts');
const tarball = path.resolve(projectRoot, tarballInput);
const relative = path.relative(releaseRoot, tarball);
if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Release tarball must be inside release-artifacts/.');
if (!(await lstat(tarball)).isFile()) throw new Error('Release tarball is not a regular file.');
const packageDocument = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8'));
if (packageDocument.name !== expectedName || packageDocument.version !== expectedVersion) {
  throw new Error('Release arguments do not match package.json.');
}
const localShasum = await hashFile(tarball);
if (localShasum !== expectedShasum.toLowerCase()) throw new Error('Release tarball changed after the pack step.');

const existing = queryPublishedShasum();
if (existing.state === 'present') {
  if (existing.shasum !== localShasum) {
    throw new Error(`${expectedName}@${expectedVersion} already exists with shasum ${existing.shasum}, not ${localShasum}.`);
  }
  await writeOutput('already-present');
  process.stdout.write(`Registry already contains the identical tarball ${localShasum}; publication skipped.\n`);
  process.exit(0);
}
const published = spawnNpm([
  'publish', tarball, '--provenance', '--access', 'public', '--registry=https://registry.npmjs.org/', '--ignore-scripts',
], { cwd: projectRoot, encoding: 'utf8', env: process.env, stdio: 'inherit', windowsHide: true });
if (published.error) throw published.error;
if (published.status !== 0) {
  const raced = queryPublishedShasum();
  if (raced.state === 'present' && raced.shasum === localShasum) {
    await writeOutput('already-present-after-race');
    process.stdout.write('A concurrent publisher installed the identical tarball; treating the release as complete.\n');
    process.exit(0);
  }
  throw new Error(`npm publish failed with exit code ${published.status}.`);
}

for (let attempt = 0; attempt < 6; attempt += 1) {
  const verified = queryPublishedShasum();
  if (verified.state === 'present') {
    if (verified.shasum !== localShasum) throw new Error('Published registry shasum does not match the verified tarball.');
    await writeOutput('published');
    process.stdout.write(`Published and verified registry shasum ${localShasum}.\n`);
    process.exit(0);
  }
  await new Promise((resolve) => setTimeout(resolve, 1_000));
}
throw new Error('Published version did not become visible for shasum verification.');

function queryPublishedShasum() {
  const specifier = `${expectedName}@${expectedVersion}`;
  const result = spawnNpm([
    'view', specifier, 'dist.shasum', '--json', '--registry=https://registry.npmjs.org/', '--ignore-scripts',
  ], { cwd: projectRoot, encoding: 'utf8', env: process.env, windowsHide: true });
  if (result.error) throw result.error;
  if (result.status === 0) {
    const value = JSON.parse(result.stdout);
    if (typeof value !== 'string' || !/^[a-f0-9]{40}$/i.test(value)) {
      throw new Error(`Registry returned an invalid dist.shasum for ${specifier}.`);
    }
    return { state: 'present', shasum: value.toLowerCase() };
  }
  if (/\bE404\b|404 Not Found|is not in this registry/i.test(`${result.stderr}\n${result.stdout}`)) {
    return { state: 'absent' };
  }
  throw new Error(`Cannot query registry state for ${specifier}: ${result.stderr || result.stdout}`);
}

async function hashFile(file) {
  const hash = createHash('sha1');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function writeOutput(result) {
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `result=${result}\n`, 'utf8');
}
