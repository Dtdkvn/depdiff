import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchBounded } from '../dist/bounded-fetch.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(projectRoot, 'benchmark', 'precision-corpus.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const registryMode = process.argv.includes('--registry');

if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.cases) || manifest.cases.length === 0) {
  throw new Error('Precision corpus must use schemaVersion 1 and contain cases.');
}

const selected = manifest.cases.filter((entry) => entry.kind === 'fixture' || registryMode);
if (selected.length === 0) throw new Error('Precision benchmark selected no cases.');

const temporary = await mkdtemp(path.join(tmpdir(), 'depdiff-precision-'));
const cacheDir = path.join(temporary, 'cache');
const results = [];

try {
  const { audit } = await import('../dist/index.js').catch(() => {
    throw new Error('Precision benchmark requires a built package. Run npm run build first.');
  });
  for (const entry of selected) {
    validateCase(entry);
    let before;
    let after;
    if (entry.kind === 'fixture') {
      before = path.resolve(projectRoot, entry.before);
      after = path.resolve(projectRoot, entry.after);
    } else if (entry.kind === 'registry') {
      await verifyPinnedRegistryMetadata(entry);
      before = entry.before;
      after = entry.after;
    } else {
      await verifyRegistryIntegrity(entry.id, entry.before, entry.integrity.before);
      before = entry.before;
      after = await prepareDatasetSample(entry, temporary);
    }
    const report = await audit(before, after, {
      offline: entry.kind === 'fixture',
      deterministic: true,
      cacheDir,
    });
    const findingIds = new Set(report.findings.map((finding) => finding.id));
    const missingRules = (entry.expectedRules ?? []).filter((rule) => !findingIds.has(rule));
    const predictedAlert = report.findings.some((finding) => finding.status === 'new'
      && (finding.severity === 'high' || finding.severity === 'critical'));
    results.push({
      id: entry.id,
      label: entry.label,
      predictedAlert,
      risk: report.risk.score,
      findings: report.findings.length,
      missingRules,
    });
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}

const counts = results.reduce((totals, result) => {
  if (result.label === 'alert' && result.predictedAlert) totals.truePositive += 1;
  else if (result.label === 'alert') totals.falseNegative += 1;
  else if (result.predictedAlert) totals.falsePositive += 1;
  else totals.trueNegative += 1;
  return totals;
}, { truePositive: 0, falsePositive: 0, trueNegative: 0, falseNegative: 0 });
const metrics = {
  precision: divide(counts.truePositive, counts.truePositive + counts.falsePositive),
  recall: divide(counts.truePositive, counts.truePositive + counts.falseNegative),
  falsePositiveRate: divide(counts.falsePositive, counts.falsePositive + counts.trueNegative),
};
const missingRules = results.flatMap((result) => result.missingRules.map((rule) => `${result.id}:${rule}`));
const failures = [
  ...(metrics.precision < manifest.thresholds.precision ? [`precision ${format(metrics.precision)} < ${format(manifest.thresholds.precision)}`] : []),
  ...(metrics.recall < manifest.thresholds.recall ? [`recall ${format(metrics.recall)} < ${format(manifest.thresholds.recall)}`] : []),
  ...(metrics.falsePositiveRate > manifest.thresholds.falsePositiveRate
    ? [`false-positive rate ${format(metrics.falsePositiveRate)} > ${format(manifest.thresholds.falsePositiveRate)}`] : []),
  ...missingRules.map((rule) => `missing expected rule ${rule}`),
];

for (const result of results) {
  const verdict = result.predictedAlert ? 'ALERT' : 'clean';
  process.stdout.write(`${result.id.padEnd(30)} label=${result.label.padEnd(5)} predicted=${verdict.padEnd(5)} risk=${String(result.risk).padStart(3)} findings=${result.findings}\n`);
}
process.stdout.write(`\nPrecision ${format(metrics.precision)} · Recall ${format(metrics.recall)} · FPR ${format(metrics.falsePositiveRate)} · TP ${counts.truePositive} FP ${counts.falsePositive} TN ${counts.trueNegative} FN ${counts.falseNegative}\n`);
process.stdout.write(`Corpus ${results.length}/${manifest.cases.length} cases (${registryMode ? 'fixtures + integrity-pinned registry releases + vetted dataset sample' : 'offline fixtures'}). Package code executed: no.\n`);
if (failures.length > 0) {
  throw new Error(`Precision benchmark failed: ${failures.join('; ')}`);
}

function validateCase(entry) {
  if (!entry || typeof entry.id !== 'string' || !['fixture', 'registry', 'dataset'].includes(entry.kind)
    || !['alert', 'clean'].includes(entry.label) || typeof entry.before !== 'string' || typeof entry.after !== 'string') {
    throw new Error('Precision corpus contains a malformed case.');
  }
  if (entry.label === 'alert' && (!Array.isArray(entry.expectedRules) || entry.expectedRules.length === 0)) {
    throw new Error(`Alert case ${entry.id} must name expectedRules.`);
  }
  if (entry.kind === 'registry' && (!entry.integrity?.before || !entry.integrity?.after)) {
    throw new Error(`Registry case ${entry.id} must pin both integrity values.`);
  }
  if (entry.kind === 'dataset' && (!entry.integrity?.before || !entry.dataset?.commit
    || !entry.dataset?.manifestSha256 || !entry.dataset?.sampleSha256)) {
    throw new Error(`Dataset case ${entry.id} must pin predecessor integrity, commit, manifest, and sample digests.`);
  }
}

async function verifyPinnedRegistryMetadata(entry) {
  const [beforeName, beforeVersion] = splitSpecifier(entry.before);
  const [afterName, afterVersion] = splitSpecifier(entry.after);
  if (beforeName !== afterName) throw new Error(`Registry case ${entry.id} changes package identity.`);
  for (const [version, expected] of [[beforeVersion, entry.integrity.before], [afterVersion, entry.integrity.after]]) {
    await verifyRegistryVersion(`${beforeName}@${version}`, expected, entry.id);
  }
}

async function verifyRegistryIntegrity(id, specifier, expected) {
  await verifyRegistryVersion(specifier, expected, id);
}

async function verifyRegistryVersion(specifier, expected, id) {
  const [name, version] = splitSpecifier(specifier);
  const url = new URL(`${encodeURIComponent(name)}/${encodeURIComponent(version)}`, 'https://registry.npmjs.org/');
  const bytes = await fetchBounded(url, {
    expectedHost: 'registry.npmjs.org',
    label: `registry metadata for ${specifier}`,
    maximumBytes: 1024 * 1024,
    mediaTypes: ['application/json'],
    accept: 'application/json',
  });
  const metadata = JSON.parse(bytes.toString('utf8'));
  if (metadata?.name !== name || metadata?.version !== version) {
    throw new Error(`Registry metadata identity mismatch for ${specifier}.`);
  }
  const actual = metadata?.dist?.integrity;
  if (actual !== expected) {
    throw new Error(`Pinned integrity mismatch for ${id}/${specifier}: expected ${digestLabel(expected)}, got ${digestLabel(actual)}.`);
  }
}

async function prepareDatasetSample(entry, root) {
  const dataset = entry.dataset;
  if (dataset.repository !== 'https://github.com/DataDog/malicious-software-packages-dataset'
    || dataset.license !== 'Apache-2.0' || !/^[a-f0-9]{40}$/u.test(dataset.commit)) {
    throw new Error(`Dataset case ${entry.id} has untrusted provenance metadata.`);
  }
  const rawRoot = `https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/${dataset.commit}/`;
  const [manifestBytes, sampleBytes] = await Promise.all([
    fetchPinnedFile(new URL(dataset.manifestPath, rawRoot), 4 * 1024 * 1024),
    fetchPinnedFile(new URL(dataset.samplePath, rawRoot), 20 * 1024 * 1024),
  ]);
  assertSha256(`${entry.id} manifest`, manifestBytes, dataset.manifestSha256);
  assertSha256(`${entry.id} sample`, sampleBytes, dataset.sampleSha256);
  const labels = JSON.parse(manifestBytes.toString('utf8'))?.[dataset.packageName];
  if (!Array.isArray(labels) || !labels.includes(dataset.version)) {
    throw new Error(`Datadog manifest at ${dataset.commit} does not label ${dataset.packageName}@${dataset.version} compromised.`);
  }

  const caseRoot = path.join(root, entry.id);
  const extracted = path.join(caseRoot, 'extracted');
  await mkdir(extracted, { recursive: true });
  const archive = path.join(caseRoot, 'sample.zip');
  await writeFile(archive, sampleBytes, { flag: 'wx' });
  const python = findPython();
  const helper = path.join(projectRoot, 'scripts', 'extract-dataset-zip.py');
  const result = spawnSync(python, [helper, archive, extracted], {
    cwd: projectRoot, encoding: 'utf8', windowsHide: true, env: process.env,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Dataset extraction failed with ${result.status}:\n${result.stderr || result.stdout}`);
  const roots = await findPackageRoots(extracted);
  if (roots.length !== 1) throw new Error(`Dataset sample must contain exactly one package root; found ${roots.length}.`);
  const document = JSON.parse(await readFile(path.join(roots[0], 'package.json'), 'utf8'));
  if (document.name !== dataset.packageName || document.version !== dataset.version) {
    throw new Error(`Dataset sample identity mismatch: expected ${dataset.packageName}@${dataset.version}.`);
  }
  return roots[0];
}

async function fetchPinnedFile(url, maximumBytes) {
  const manifest = url.pathname.endsWith('.json');
  return fetchBounded(url, {
    expectedHost: 'raw.githubusercontent.com',
    label: `dataset download ${url.pathname}`,
    maximumBytes,
    mediaTypes: manifest ? ['application/json', 'text/plain'] : ['application/zip', 'application/octet-stream'],
    accept: manifest ? 'application/json,text/plain' : 'application/zip,application/octet-stream',
  });
}

function assertSha256(label, bytes, expected) {
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) throw new Error(`${label} SHA-256 mismatch: expected ${expected}, got ${actual}.`);
}

function findPython() {
  const candidates = process.platform === 'win32' ? ['python', 'python3'] : ['python3', 'python'];
  for (const command of candidates) {
    const result = spawnSync(command, ['--version'], { encoding: 'utf8', windowsHide: true });
    if (!result.error && result.status === 0) return command;
  }
  throw new Error('The vetted-dataset benchmark requires Python 3 for safe encrypted-ZIP extraction.');
}

async function findPackageRoots(root) {
  const roots = [];
  let visited = 0;
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      visited += 1;
      if (visited > 1_000) throw new Error('Extracted dataset sample contains more than 1,000 entries.');
      const absolute = path.join(directory, entry.name);
      const details = await lstat(absolute);
      if (details.isSymbolicLink()) throw new Error(`Extracted dataset contains a symbolic link: ${absolute}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile() && entry.name === 'package.json' && path.basename(directory) === 'package') roots.push(directory);
    }
  }
  await visit(root);
  return roots;
}

function splitSpecifier(specifier) {
  const separator = specifier.lastIndexOf('@');
  if (separator <= 0 || separator === specifier.length - 1) throw new Error(`Registry benchmark requires an exact package@version: ${specifier}`);
  return [specifier.slice(0, separator), specifier.slice(separator + 1)];
}

function digestLabel(value) {
  return typeof value === 'string' ? `${value.slice(0, 18)}…/${createHash('sha256').update(value).digest('hex').slice(0, 12)}` : String(value);
}

function divide(numerator, denominator) {
  return denominator === 0 ? 0 : numerator / denominator;
}

function format(value) {
  return value.toFixed(3);
}
