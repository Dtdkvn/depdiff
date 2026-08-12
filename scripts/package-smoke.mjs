import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, lstat, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as tar from 'tar';
import { spawnNpm } from './npm-process.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp(path.join(tmpdir(), 'depdiff-package-smoke-'));

try {
  const suppliedTarball = process.argv[2];
  let tarball;
  let filename;
  if (suppliedTarball) {
    tarball = path.resolve(projectRoot, suppliedTarball);
    const relative = path.relative(projectRoot, tarball);
    if (relative.startsWith('..') || path.isAbsolute(relative) || !tarball.endsWith('.tgz')) {
      throw new Error('Supplied package smoke tarball must be a .tgz inside the project.');
    }
    const details = await lstat(tarball);
    if (!details.isFile()) throw new Error('Supplied package smoke tarball is not a regular file.');
    filename = path.basename(tarball);
  } else {
    const packOutput = runNpm([
      'pack', '--ignore-scripts', '--json', '--loglevel=error', '--pack-destination', temporary,
    ], projectRoot);
    const records = JSON.parse(packOutput);
    if (!Array.isArray(records) || records.length !== 1 || typeof records[0]?.filename !== 'string') {
      throw new Error('npm pack did not return exactly one package record.');
    }
    filename = path.basename(records[0].filename);
    tarball = path.join(temporary, filename);
  }
  const unpacked = path.join(temporary, 'unpacked');
  await mkdir(unpacked);
  await tar.extract({ file: tarball, cwd: unpacked, strict: true });
  const packageRoot = path.join(unpacked, 'package');
  const validatedLinks = await validatePackedDocumentation(packageRoot);

  const installRoot = path.join(temporary, 'installed');
  runNpm([
    'install', '--prefix', installRoot, tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--offline',
  ], projectRoot);
  const installedPackage = path.join(installRoot, 'node_modules', 'depdiff-audit');
  const packageDocument = JSON.parse(await readFile(path.join(installedPackage, 'package.json'), 'utf8'));
  const cli = path.join(installedPackage, 'dist', 'cli.js');
  const version = run(process.execPath, [cli, '--version'], installRoot).trim();
  if (version !== packageDocument.version) {
    throw new Error(`Packed CLI version ${version} does not match package version ${packageDocument.version}.`);
  }

  const safeFixture = path.join(installedPackage, 'fixtures', 'safe-v1');
  const riskyFixture = path.join(installedPackage, 'fixtures', 'risky-v2');
  await verifyBinEntryPoint({ installRoot, temporary, packageDocument, safeFixture, riskyFixture });

  const reportPath = path.join(temporary, 'smoke.json');
  run(process.execPath, [
    cli,
    'compare',
    safeFixture,
    riskyFixture,
    '--offline', '--json', reportPath, '--output', path.join(temporary, 'smoke.html'), '--no-fail', '--quiet',
  ], installRoot);
  const report = JSON.parse(await readFile(reportPath, 'utf8'));
  const findingIds = new Set(report.findings?.map((finding) => finding.id));
  for (const required of ['capability.added.child_process', 'install-script.added', 'binary.native.added']) {
    if (!findingIds.has(required)) throw new Error(`Packed CLI missed core finding ${required}.`);
  }

  const api = await import(pathToFileURL(path.join(installedPackage, 'dist', 'index.js')).href);
  if (typeof api.audit !== 'function') throw new Error('Packed public API does not export audit().');
  process.stdout.write(`Packed ${filename}: CLI ${version}, ${report.findings.length} findings, ${validatedLinks} local documentation targets verified.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

/**
 * Consumers reach the CLI through `node_modules/.bin/depdiff`, which npm creates
 * as a symlink on POSIX. Invoking only the real `dist/cli.js` path cannot catch
 * an entry-point guard that fails for symlinks, and asserting a zero exit code
 * cannot catch it either, because a silent no-op also exits 0. So this checks
 * real stdout through the link and a non-zero exit on a failing policy.
 */
async function verifyBinEntryPoint({ installRoot, temporary, packageDocument, safeFixture, riskyFixture }) {
  const binEntry = path.join(installRoot, 'node_modules', '.bin', 'depdiff');
  const entry = process.platform === 'win32' ? `${binEntry}.cmd` : binEntry;
  const binDetails = await lstat(entry).catch(() => undefined);
  if (!binDetails) throw new Error(`npm install did not create ${path.relative(installRoot, entry)}.`);
  if (process.platform !== 'win32' && !binDetails.isSymbolicLink()) {
    throw new Error('npm install did not create node_modules/.bin/depdiff as a symlink.');
  }

  const versionResult = runBin(entry, ['--version'], installRoot);
  if (versionResult.status !== 0) {
    throw new Error(`Installed .bin entry failed --version with ${versionResult.status}:\n${versionResult.stderr || versionResult.stdout}`);
  }
  const version = versionResult.stdout.trim();
  if (version !== packageDocument.version) {
    throw new Error(
      `CLI invoked through ${entry} printed ${JSON.stringify(version)} instead of ${packageDocument.version}; the .bin entry point is not executing the CLI.`,
    );
  }
  const failing = runBin(entry, [
    'compare', safeFixture, riskyFixture,
    '--offline', '--fail-on', 'high', '--quiet', '--output', path.join(temporary, 'binlink.html'),
  ], installRoot);
  if (failing.status !== 1) {
    throw new Error(
      `CLI invoked through ${entry} exited ${failing.status} on a failing policy; expected 1. A silent no-op also exits 0.\n${failing.stderr || failing.stdout}`,
    );
  }
}

function runBin(entry, args, cwd) {
  // npm creates a JavaScript symlink on POSIX and a cmd.exe shim on Windows.
  // Execute the artifact consumers actually receive on each platform.
  if (process.platform === 'win32') {
    return spawnSync(entry, args, {
      cwd, encoding: 'utf8', env: process.env, windowsHide: true, shell: true,
    });
  }
  return spawnSync(process.execPath, [entry, ...args], {
    cwd, encoding: 'utf8', env: process.env, windowsHide: true,
  });
}

async function validatePackedDocumentation(packageRoot) {
  const required = [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md',
    'docs/architecture.md', 'docs/cli.md', 'docs/policy.md', 'docs/precision-benchmark.md', 'docs/rules.md', 'docs/releasing.md',
    'docs/assets/demo.gif', 'docs/assets/report-preview.png', 'examples/github-action.yml',
  ];
  for (const relative of required) await requirePackedTarget(packageRoot, relative, 'package manifest');

  const markdownFiles = await collectMarkdownFiles(packageRoot);
  let validated = 0;
  for (const markdownFile of markdownFiles) {
    const source = await readFile(markdownFile, 'utf8');
    const targets = [
      ...source.matchAll(/!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\s*\)/g),
      ...source.matchAll(/<(?:a|img)\b[^>]*\b(?:href|src)=["']([^"']+)["'][^>]*>/gi),
      ...source.matchAll(/^[ \t]{0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|([^\s]+))/gm),
    ].map((match) => match[1] ?? match[2]).filter((value) => typeof value === 'string');
    for (const target of targets) {
      if (isExternalOrAnchor(target)) continue;
      const pathOnly = decodeURIComponent(target.split('#', 1)[0].split('?', 1)[0]);
      if (!pathOnly) continue;
      const candidate = pathOnly.startsWith('/')
        ? path.resolve(packageRoot, `.${pathOnly}`)
        : path.resolve(path.dirname(markdownFile), pathOnly);
      const relative = path.relative(packageRoot, candidate);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new Error(`Packed Markdown target escapes the package: ${path.relative(packageRoot, markdownFile)} -> ${target}`);
      }
      await requirePackedTarget(packageRoot, relative, path.relative(packageRoot, markdownFile));
      validated += 1;
    }
  }
  if (validated === 0) throw new Error('No local Markdown targets were validated in the packed package.');
  return validated;
}

async function collectMarkdownFiles(root) {
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) files.push(absolute);
    }
  }
  await visit(root);
  return files;
}

async function requirePackedTarget(packageRoot, relative, source) {
  try {
    await lstat(path.resolve(packageRoot, relative));
  } catch {
    throw new Error(`Packed documentation target is missing: ${source} -> ${relative}`);
  }
}

function isExternalOrAnchor(target) {
  return target.startsWith('#') || target.startsWith('//') || /^[a-z][a-z\d+.-]*:/i.test(target);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', env: process.env, windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with ${result.status}:\n${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function runNpm(args, cwd) {
  const result = spawnNpm(args, { cwd, encoding: 'utf8', env: process.env, windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`npm ${args.join(' ')} failed with ${result.status}:\n${result.stderr || result.stdout}`);
  }
  return result.stdout;
}
