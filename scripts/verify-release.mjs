import { appendFile, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

const packageDocument = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const version = packageDocument.version;
const packageName = packageDocument.name;
const tag = process.env.GITHUB_REF_NAME;
const eventRef = process.env.GITHUB_REF;
const eventSha = process.env.GITHUB_SHA;

const numeric = '(?:0|[1-9]\\d*)';
const prereleaseIdentifier = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const strictSemVer = new RegExp(`^${numeric}\\.${numeric}\\.${numeric}(?:-${prereleaseIdentifier}(?:\\.${prereleaseIdentifier})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`);

if (typeof packageName !== 'string' || !/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(packageName)) {
  throw new Error('package.json contains an invalid npm package name.');
}
if (typeof version !== 'string' || !strictSemVer.test(version)) {
  throw new Error(`package.json version is not strict SemVer: ${String(version)}`);
}
if (!tag || eventRef !== `refs/tags/${tag}` || tag !== `v${version}`) {
  throw new Error(`Release ref ${eventRef ?? '(missing)'} must be the exact tag v${version}.`);
}
if (!eventSha || !/^[a-f0-9]{40}$/i.test(eventSha)) throw new Error('GITHUB_SHA must be a full commit SHA.');

const taggedCommit = git(['rev-parse', '--verify', `refs/tags/${tag}^{commit}`]);
const eventCommit = git(['rev-parse', '--verify', `${eventSha}^{commit}`]);
const mainCommit = git(['rev-parse', '--verify', 'refs/remotes/origin/main^{commit}']);
if (taggedCommit !== eventCommit) {
  throw new Error(`Tag ${tag} resolves to ${taggedCommit}, not event commit ${eventCommit}.`);
}
const ancestry = spawnSync('git', ['merge-base', '--is-ancestor', taggedCommit, mainCommit], { encoding: 'utf8', windowsHide: true });
if (ancestry.error) throw ancestry.error;
if (ancestry.status !== 0) {
  throw new Error(`Tagged commit ${taggedCommit} is not an ancestor of origin/main ${mainCommit}.`);
}

await writeOutput({ name: packageName, version, tag, tagged_sha: taggedCommit });
process.stdout.write(`Verified ${tag} at ${taggedCommit}: strict SemVer and ancestor of origin/main.\n`);

function git(args) {
  const result = spawnSync('git', args, { encoding: 'utf8', windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

async function writeOutput(values) {
  if (!process.env.GITHUB_OUTPUT) return;
  const lines = Object.entries(values).map(([key, value]) => {
    if (/\r|\n/.test(value)) throw new Error(`Release output ${key} contains a line break.`);
    return `${key}=${value}`;
  });
  await appendFile(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, 'utf8');
}
