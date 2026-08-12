import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable, Transform } from 'node:stream';
import * as tar from 'tar';
import { minimatch } from 'minimatch';
import { manifestEntryPaths } from './codeprofile.js';
import type {
  FileSummary,
  LoadedFile,
  LoadedPackage,
  PackageMetadata,
  ResolveOptions,
  SourceDescriptor,
} from './types.js';
import { asStringRecord, compareStrings, isRecord, sha256, stringArray, UserError } from './util.js';

/** Bytes retained from every file so oversized content can still be classified. */
const PROBE_BYTES = 4_096;

interface RegistryDocument {
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, RegistryVersion>;
  time?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
}

interface RegistryVersion extends Record<string, unknown> {
  name?: string;
  version?: string;
  maintainers?: Array<{ name?: string; email?: string }>;
  _npmUser?: { name?: string; email?: string };
  gitHead?: string;
  dist?: {
    tarball?: string;
    integrity?: string;
    shasum?: string;
    signatures?: unknown[];
    attestations?: { url?: string };
  };
}

export async function resolvePackageSource(input: string, options: ResolveOptions): Promise<LoadedPackage> {
  const local = path.resolve(input);
  try {
    const details = await lstat(local);
    if (details.isDirectory()) {
      return scanDirectory(local, {
        input,
        kind: 'directory',
        resolved: local,
      }, options);
    }
    if (details.isFile()) {
      if (!/\.(?:tgz|tar\.gz|tar)$/i.test(local)) {
        throw new UserError(`Local input is not a supported tar archive: ${input}`);
      }
      return loadTarball(local, {
        input,
        kind: 'tarball',
        resolved: local,
      }, options);
    }
    throw new UserError(`Input is neither a directory nor a regular file: ${input}`);
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
  }

  if (options.offline) {
    throw new UserError(`Offline mode only accepts existing directories or tarballs: ${input}`);
  }
  return loadRegistryPackage(input, options);
}

async function loadRegistryPackage(input: string, options: ResolveOptions): Promise<LoadedPackage> {
  const { name, requestedVersion } = parseRegistrySpecifier(input);
  const registry = normalizeRegistry(options.registry);
  const metadataUrl = new URL(encodeURIComponent(name), registry);
  const registryHost = new URL(registry).host;
  const response = await fetchWithTimeout(metadataUrl, registryHost, options.limits.timeoutMs, 'registry metadata');
  if (!response.ok) {
    throw new UserError(`npm registry returned ${response.status} for ${name}`);
  }
  const document = await readRegistryDocument(response);
  const resolvedVersion = document['dist-tags']?.[requestedVersion] ?? requestedVersion;
  const manifestValue: unknown = document.versions?.[resolvedVersion];
  if (!isRecord(manifestValue)) {
    throw new UserError(
      `Version or dist-tag ${requestedVersion} was not found for ${name}. Use an exact version or a published dist-tag.`,
    );
  }
  const manifest = manifestValue as RegistryVersion;
  const distributionValue: unknown = manifestValue.dist;
  if (!isRecord(distributionValue)) throw new UserError(`Registry metadata for ${name}@${resolvedVersion} has no distribution object.`);
  const tarballUrl = distributionValue.tarball;
  if (typeof tarballUrl !== 'string' || !tarballUrl) throw new UserError(`Registry metadata for ${name}@${resolvedVersion} has no tarball URL.`);
  const integrity = optionalRegistryString(distributionValue.integrity, 'dist.integrity');
  const shasum = optionalRegistryString(distributionValue.shasum, 'dist.shasum');
  let parsedTarball: URL;
  try {
    parsedTarball = new URL(tarballUrl);
  } catch {
    throw new UserError('Registry metadata contains an invalid tarball URL.');
  }
  if (parsedTarball.protocol !== 'https:') throw new UserError('Registry tarballs must use HTTPS.');
  if (parsedTarball.host !== registryHost) {
    throw new UserError(
      `Registry returned a tarball on a different host (${parsedTarball.host}). Configure that registry as the trusted --registry origin explicitly.`,
    );
  }

  await mkdir(options.cacheDir, { recursive: true });
  const digestIdentity = integrity ?? shasum;
  const tarballFile = digestIdentity
    ? path.join(options.cacheDir, `${sha256(digestIdentity)}.tgz`)
    : path.join(options.cacheDir, `.unverified.${process.pid}.${randomUUID()}.tgz`);
  if (!digestIdentity || !(await isAccessible(tarballFile))) {
    await downloadTarball(parsedTarball, tarballFile, registryHost, options);
  }
  if (digestIdentity) {
    try {
      await verifyArchiveDigest(tarballFile, integrity, shasum);
    } catch (error) {
      await rm(tarballFile, { force: true });
      throw error;
    }
  }

  const maintainers = normalizeMaintainers(manifest.maintainers ?? document.maintainers);
  const npmUser = normalizeMaintainers(manifest._npmUser)[0];
  const source: SourceDescriptor = {
    input,
    kind: 'registry',
    resolved: `${name}@${resolvedVersion}`,
    packageName: name,
    version: resolvedVersion,
    ...(integrity ? { integrity } : {}),
    ...(shasum ? { shasum } : {}),
    ...(document.time?.[resolvedVersion] ? { publishedAt: document.time[resolvedVersion] } : {}),
    ...(maintainers.length > 0 ? { maintainers } : {}),
    provenance: {
      attestations: isRecord(distributionValue.attestations) && typeof distributionValue.attestations.url === 'string' && distributionValue.attestations.url.length > 0,
      signatures: Array.isArray(distributionValue.signatures) && distributionValue.signatures.length > 0,
      ...(npmUser ? { npmUser } : {}),
      ...(typeof manifest.gitHead === 'string' && manifest.gitHead ? { gitHead: manifest.gitHead } : {}),
    },
  };
  try {
    return await loadTarball(tarballFile, source, options);
  } finally {
    if (!digestIdentity) await rm(tarballFile, { force: true });
  }
}

function optionalRegistryString(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new UserError(`Registry metadata ${field} must be a string.`);
  return value;
}

function parseRegistrySpecifier(input: string): { name: string; requestedVersion: string } {
  const trimmed = input.trim();
  if (!trimmed) throw new UserError('Package specifier cannot be empty.');
  let separator = trimmed.lastIndexOf('@');
  if (trimmed.startsWith('@')) {
    const slash = trimmed.indexOf('/');
    if (slash < 2) throw new UserError(`Invalid scoped npm package specifier: ${input}`);
    if (separator < slash) separator = -1;
  }
  const name = separator > 0 ? trimmed.slice(0, separator) : trimmed;
  const requestedVersion = separator > 0 ? trimmed.slice(separator + 1) || 'latest' : 'latest';
  if (!/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(name)) {
    throw new UserError(`Invalid npm package name: ${name}`);
  }
  return { name, requestedVersion };
}

function normalizeRegistry(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value.endsWith('/') ? value : `${value}/`);
  } catch {
    throw new UserError(`Invalid registry URL: ${value}`);
  }
  if (parsed.protocol !== 'https:') throw new UserError('The npm registry must use HTTPS.');
  parsed.username = '';
  parsed.password = '';
  return parsed.toString();
}

async function fetchWithTimeout(
  initialUrl: URL,
  expectedHost: string,
  timeoutMs: number,
  label: string,
): Promise<Response> {
  const signal = AbortSignal.timeout(timeoutMs);
  let currentUrl = initialUrl;
  const maximumRedirects = 5;
  for (let redirects = 0; redirects <= maximumRedirects; redirects += 1) {
    assertTrustedUrl(currentUrl, expectedHost, label);
    let response: Response;
    try {
      response = await fetch(currentUrl, {
        signal,
        headers: { accept: 'application/json', 'user-agent': 'depdiff/0.1.0' },
        redirect: 'manual',
      });
    } catch (error) {
      throw new UserError(`Network request failed for ${currentUrl.host}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    if (redirects === maximumRedirects) throw new UserError(`Too many redirects while fetching ${label}.`);
    const location = response.headers.get('location');
    if (!location) throw new UserError(`Redirect while fetching ${label} did not include a Location header.`);
    let nextUrl: URL;
    try {
      nextUrl = new URL(location, currentUrl);
    } catch {
      throw new UserError(`Invalid redirect while fetching ${label}: ${location}`);
    }
    assertTrustedUrl(nextUrl, expectedHost, label);
    await response.body?.cancel();
    currentUrl = nextUrl;
  }
  throw new UserError(`Too many redirects while fetching ${label}.`);
}

async function readRegistryDocument(response: Response): Promise<RegistryDocument> {
  const maximum = 16 * 1024 * 1024;
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared > maximum) throw new UserError('Registry metadata exceeds the 16 MiB limit.');
  try {
    if (!response.body) throw new UserError('Registry metadata response has no body.');
    const reader = response.body.getReader();
    const chunks: Buffer[] = [];
    let received = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maximum) {
          await reader.cancel('Registry metadata size limit exceeded.');
          throw new UserError('Registry metadata exceeds the 16 MiB limit.');
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock();
    }
    const buffer = Buffer.concat(chunks, received);
    const parsed: unknown = JSON.parse(buffer.toString('utf8'));
    if (!isRecord(parsed)) throw new UserError('Registry metadata is not a JSON object.');
    return parsed;
  } catch (error) {
    if (error instanceof UserError) throw error;
    throw new UserError(`Cannot read registry metadata: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertTrustedUrl(url: URL, expectedHost: string, label: string): void {
  if (url.protocol !== 'https:' || url.host !== expectedHost) {
    throw new UserError(`Untrusted redirect while fetching ${label}: ${url.origin}`);
  }
}

async function downloadTarball(
  url: URL,
  destination: string,
  expectedHost: string,
  options: ResolveOptions,
): Promise<void> {
  const response = await fetchWithTimeout(url, expectedHost, options.limits.timeoutMs, 'package tarball');
  if (!response.ok || !response.body) throw new UserError(`Tarball download failed with HTTP ${response.status}.`);
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared > options.limits.maxArchiveBytes) {
    throw new UserError(`Compressed archive exceeds the ${options.limits.maxArchiveBytes}-byte limit.`);
  }
  let downloaded = 0;
  const limiter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      downloaded += chunk.length;
      if (downloaded > options.limits.maxArchiveBytes) {
        callback(new UserError(`Compressed archive exceeds the ${options.limits.maxArchiveBytes}-byte limit.`));
      } else {
        callback(null, chunk);
      }
    },
  });
  const partial = `${destination}.${process.pid}.${randomUUID()}.partial`;
  try {
    await pipeline(Readable.fromWeb(response.body as never), limiter, createWriteStream(partial, { flags: 'wx' }));
    try {
      await rename(partial, destination);
    } catch (error) {
      if (!(await isAccessible(destination))) throw error;
      await rm(partial, { force: true });
    }
  } catch (error) {
    await rm(partial, { force: true });
    if (error instanceof UserError) throw error;
    throw new UserError(`Tarball download failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function verifyArchiveDigest(file: string, integrity?: string, shasum?: string): Promise<void> {
  const normalizedIntegrity = integrity?.trim() ?? '';
  if (integrity !== undefined && !normalizedIntegrity) {
    throw new UserError('Tarball integrity is empty after whitespace normalization.');
  }
  if (normalizedIntegrity) {
    const candidates = normalizedIntegrity.split(/\s+/).filter(Boolean);
    for (const candidate of candidates) {
      const algorithm = ['sha512', 'sha384', 'sha256'].find((value) => candidate.startsWith(`${value}-`));
      if (algorithm && !new RegExp(`^${algorithm}-[A-Za-z0-9+/]+={0,2}$`).test(candidate)) {
        throw new UserError(`Tarball integrity contains a malformed ${algorithm} digest.`);
      }
    }
    const parsed = candidates.map((candidate) => {
      const match = /^(sha512|sha384|sha256)-([A-Za-z0-9+/]+={0,2})$/.exec(candidate);
      return match ? { algorithm: match[1]!, expected: match[2]! } : undefined;
    }).filter((candidate): candidate is { algorithm: string; expected: string } => candidate !== undefined);
    const algorithm = ['sha512', 'sha384', 'sha256'].find((value) => parsed.some((candidate) => candidate.algorithm === value));
    if (!algorithm) throw new UserError('Tarball integrity uses no supported, valid SHA-256/384/512 digest.');
    const actual = await hashFile(file, algorithm, 'base64');
    const expected = parsed.filter((candidate) => candidate.algorithm === algorithm).map((candidate) => candidate.expected);
    if (!expected.includes(actual)) throw new UserError(`Tarball integrity mismatch (${algorithm}).`);
    return;
  }
  if (shasum) {
    const actual = await hashFile(file, 'sha1', 'hex');
    if (actual !== shasum.toLowerCase()) throw new UserError('Tarball shasum mismatch (sha1).');
  }
}

async function hashFile(file: string, algorithm: string, encoding: 'base64' | 'hex'): Promise<string> {
  const hash = createHash(algorithm);
  await pipeline(createReadStream(file), new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      hash.update(chunk);
      callback();
    },
  }));
  return hash.digest(encoding);
}

async function loadTarball(
  archive: string,
  source: SourceDescriptor,
  options: ResolveOptions,
): Promise<LoadedPackage> {
  const archiveStat = await stat(archive);
  if (archiveStat.size > options.limits.maxArchiveBytes) {
    throw new UserError(`Compressed archive exceeds the ${options.limits.maxArchiveBytes}-byte limit.`);
  }
  let entries = 0;
  let totalBytes = 0;
  try {
    const parser = new tar.Parser({ file: archive, strict: true, maxDecompressionRatio: options.limits.maxCompressionRatio });
    parser.on('entry', (entry: tar.ReadEntry) => {
      let validationError: Error | undefined;
      try {
        assertSafeArchivePath(entry.path);
        entries += 1;
        totalBytes += entry.size;
        if (entries > options.limits.maxFiles) throw new UserError(`Archive contains more than ${options.limits.maxFiles} entries.`);
        if (entry.size > options.limits.maxFileBytes) throw new UserError(`Archive entry ${entry.path} exceeds the per-file limit.`);
        if (totalBytes > options.limits.maxTotalBytes) throw new UserError('Archive exceeds the total uncompressed size limit.');
        if (!['File', 'OldFile', 'ContiguousFile', 'Directory'].includes(entry.type)) {
          throw new UserError(`Archive contains unsupported ${entry.type} entry: ${entry.path}`);
        }
      } catch (error) {
        validationError = error instanceof Error ? error : new Error(String(error));
      }
      if (validationError) parser.abort(validationError);
      entry.resume();
    });
    await pipeline(createReadStream(archive), parser);
  } catch (error) {
    if (error instanceof UserError) throw error;
    throw new UserError(`Cannot inspect archive ${source.input}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const temporary = await mkdtemp(path.join(tmpdir(), 'depdiff-'));
  try {
    try {
      let extractionError: UserError | undefined;
      let extractedEntries = 0;
      let extractedBytes = 0;
      await tar.extract({
        file: archive,
        cwd: temporary,
        strict: true,
        preservePaths: false,
        maxDecompressionRatio: options.limits.maxCompressionRatio,
        filter(entryPath, entry) {
          if (extractionError) return false;
          try {
            assertSafeArchivePath(entryPath);
          } catch (error) {
            extractionError = error instanceof UserError ? error : new UserError(String(error));
            return false;
          }
          if (!('type' in entry) || !['File', 'OldFile', 'ContiguousFile', 'Directory'].includes(entry.type)) {
            extractionError = new UserError(`Archive contains an unsupported entry during extraction: ${entryPath}`);
            return false;
          }
          extractedEntries += 1;
          extractedBytes += 'size' in entry ? entry.size : 0;
          if (extractedEntries > options.limits.maxFiles || extractedBytes > options.limits.maxTotalBytes || ('size' in entry && entry.size > options.limits.maxFileBytes)) {
            extractionError = new UserError('Archive changed after preflight or exceeded configured extraction limits.');
            return false;
          }
          return true;
        },
      });
      if (extractionError) throw extractionError;
    } catch (error) {
      if (error instanceof UserError) throw error;
      throw new UserError(`Cannot extract archive ${source.input}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const root = await findArchiveRoot(temporary);
    return await scanDirectory(root, source, options);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

export function assertSafeArchivePath(entryPath: string): void {
  if (entryPath.includes('\0')) throw new UserError('Archive entry contains a NUL byte.');
  const normalizedSlashes = entryPath.replaceAll('\\', '/');
  if (path.posix.isAbsolute(normalizedSlashes) || /^[a-zA-Z]:/.test(normalizedSlashes)) {
    throw new UserError(`Archive entry uses an absolute path: ${entryPath}`);
  }
  const parts = normalizedSlashes.split('/');
  if (parts.includes('..')) throw new UserError(`Archive entry attempts path traversal: ${entryPath}`);
}

async function findArchiveRoot(temporary: string): Promise<string> {
  const npmRoot = path.join(temporary, 'package');
  const entries = await readdir(temporary, { withFileTypes: true });
  if (await isAccessible(path.join(npmRoot, 'package.json'))) {
    const unexpected = entries.filter((entry) => entry.name !== 'package');
    if (unexpected.length > 0) {
      throw new UserError(`Archive contains entries outside its canonical package/ root: ${unexpected.map((entry) => entry.name).join(', ')}`);
    }
    return npmRoot;
  }
  if (entries.length === 1 && entries[0]?.isDirectory()) return path.join(temporary, entries[0].name);
  return temporary;
}

async function scanDirectory(
  directory: string,
  source: SourceDescriptor,
  options: ResolveOptions,
): Promise<LoadedPackage> {
  const root = await realpath(directory);
  const files = new Map<string, LoadedFile>();
  let totalBytes = 0;
  let entriesVisited = 0;
  let packageManifest: Buffer | undefined;
  const ignorePatterns = source.kind === 'directory'
    ? [...options.localIgnore, ...options.ignore]
    : options.ignore;

  async function visit(current: string): Promise<void> {
    const entries = await readdir(current, { withFileTypes: true });
    entries.sort((a, b) => compareStrings(a.name, b.name));
    for (const entry of entries) {
      entriesVisited += 1;
      if (entriesVisited > options.limits.maxFiles) throw new UserError(`Input contains more than ${options.limits.maxFiles} entries.`);
      const absolute = path.join(current, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (ignorePatterns.some((pattern) => minimatch(relative, pattern, { dot: true }))) continue;
      if (entry.isSymbolicLink()) {
        const target = await readlink(absolute);
        const details = await lstat(absolute);
        files.set(relative, {
          path: relative,
          size: Buffer.byteLength(target),
          sha256: sha256(target),
          mode: details.mode,
          kind: 'symlink',
        });
        continue;
      }
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const resolved = await realpath(absolute);
      if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
        throw new UserError(`File escaped the source root: ${relative}`);
      }
      const details = await stat(resolved);
      if (details.size > options.limits.maxFileBytes) throw new UserError(`${relative} exceeds the per-file size limit.`);
      totalBytes += details.size;
      if (totalBytes > options.limits.maxTotalBytes) throw new UserError('Input exceeds the total uncompressed size limit.');
      const buffer = await readFile(resolved);
      if (relative === 'package.json') {
        if (buffer.length > options.limits.maxTextBytes) {
          throw new UserError(`package.json exceeds the ${options.limits.maxTextBytes}-byte parsed manifest limit.`);
        }
        packageManifest = buffer;
      }
      const kind = isProbablyText(buffer) ? 'text' : 'binary';
      const analyzable = buffer.length <= options.limits.maxTextBytes;
      files.set(relative, {
        path: relative,
        size: details.size,
        sha256: sha256(buffer),
        mode: details.mode,
        kind,
        // Files past the analyzed-text limit still keep a copied prefix so the
        // analyzer can classify them (shebang, JS shape) and fail closed.
        ...(analyzable ? { content: buffer } : { probe: Buffer.from(buffer.subarray(0, PROBE_BYTES)) }),
      });
    }
  }

  await visit(root);
  const metadata = parsePackageMetadata(packageManifest, source);
  const summaries: FileSummary[] = [...files.values()].map((file) => ({
    path: file.path,
    size: file.size,
    sha256: file.sha256,
    mode: file.mode,
    kind: file.kind,
  }));
  return {
    files,
    snapshot: {
      source,
      package: metadata,
      files: summaries,
      totalBytes,
    },
  };
}

function parsePackageMetadata(buffer: Buffer | undefined, source: SourceDescriptor): PackageMetadata {
  let document: Record<string, unknown> = {};
  if (buffer) {
    try {
      const parsed: unknown = JSON.parse(buffer.toString('utf8'));
      if (isRecord(parsed)) document = parsed;
    } catch (error) {
      throw new UserError(`Invalid package.json: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const maintainers = normalizeMaintainers(document.maintainers ?? document.author);
  const bundled = document.bundledDependencies ?? document.bundleDependencies;
  const repository = normalizeRepository(document.repository);
  return {
    entryPoints: manifestEntryPaths(document),
    name: typeof document.name === 'string' ? document.name : source.packageName ?? '(unknown package)',
    version: typeof document.version === 'string' ? document.version : source.version ?? '(unknown version)',
    ...(typeof document.description === 'string' ? { description: document.description } : {}),
    ...(typeof document.license === 'string' ? { license: document.license } : {}),
    ...(repository ? { repository } : {}),
    engines: asStringRecord(document.engines),
    scripts: asStringRecord(document.scripts),
    dependencies: asStringRecord(document.dependencies),
    optionalDependencies: asStringRecord(document.optionalDependencies),
    peerDependencies: asStringRecord(document.peerDependencies),
    devDependencies: asStringRecord(document.devDependencies),
    bundledDependencies: stringArray(bundled),
    maintainers,
    ...(Array.isArray(document.files) ? { files: stringArray(document.files) } : {}),
  };
}

function normalizeMaintainers(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
  return values.map((entry) => {
    if (typeof entry === 'string') return entry;
    if (!isRecord(entry)) return '';
    const name = typeof entry.name === 'string' ? entry.name : undefined;
    const email = typeof entry.email === 'string' ? entry.email : undefined;
    return formatMaintainer({ ...(name ? { name } : {}), ...(email ? { email } : {}) });
  }).filter(Boolean);
}

function formatMaintainer(value: { name?: string; email?: string }): string {
  const name = value.name?.trim() ?? '';
  const email = value.email?.trim() ?? '';
  return email ? `${name || '(unknown)'} <${email.toLowerCase()}>` : name;
}

function normalizeRepository(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  return isRecord(value) && typeof value.url === 'string' ? value.url : undefined;
}

function isProbablyText(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  if (sample.includes(0)) return false;
  let suspicious = 0;
  for (const byte of sample) {
    if (byte < 7 || (byte > 14 && byte < 32)) suspicious += 1;
  }
  return sample.length === 0 || suspicious / sample.length < 0.15;
}

async function isAccessible(target: string): Promise<boolean> {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

export const __test = {
  parseRegistrySpecifier,
  isProbablyText,
  parsePackageMetadata,
  normalizeRegistry,
  fetchWithTimeout,
  readRegistryDocument,
  verifyArchiveDigest,
};
