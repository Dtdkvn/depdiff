import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import * as tar from 'tar';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { audit } from '../src/audit.js';
import { assertArchiveCoverage, assertSafeArchivePath, __test } from '../src/source.js';


const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const temporaryPaths: string[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe('secure source loading', () => {
  it.each(['../escape', 'package/../../escape', '/absolute/file', 'C:\\Windows\\file', '..\\escape'])(
    'rejects unsafe archive path %s',
    (value) => expect(() => assertSafeArchivePath(value)).toThrow(),
  );

  it.each(['package/index.js', './package/package.json', 'scope/name/file.ts'])(
    'accepts contained archive path %s',
    (value) => expect(() => assertSafeArchivePath(value)).not.toThrow(),
  );

  it('parses scoped and unscoped npm specifiers', () => {
    expect(__test.parseRegistrySpecifier('kleur@4.1.5')).toEqual({ name: 'kleur', requestedVersion: '4.1.5' });
    expect(__test.parseRegistrySpecifier('@scope/pkg@2.0.0')).toEqual({ name: '@scope/pkg', requestedVersion: '2.0.0' });
    expect(__test.parseRegistrySpecifier('@scope/pkg')).toEqual({ name: '@scope/pkg', requestedVersion: 'latest' });
    expect(() => __test.parseRegistrySpecifier('@bad')).toThrow(/scoped/);
    expect(() => __test.normalizeRegistry('http://registry.example')).toThrow(/HTTPS/);
    expect(() => __test.normalizeRegistry('not a url')).toThrow(/Invalid registry URL/);
  });

  it('compares a gzip tar archive and directory without changing semantics', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-tar-test-'));
    temporaryPaths.push(root);
    const packageRoot = path.join(root, 'package');
    await mkdir(packageRoot);
    await import('node:fs/promises').then(({ cp }) => cp(safe, packageRoot, { recursive: true }));
    const archive = path.join(root, 'fixture.tgz');
    await tar.create({ gzip: true, file: archive, cwd: root, portable: true }, ['package']);
    const report = await audit(safe, archive, { offline: true });
    expect(report.inventory).toMatchObject({ added: [], removed: [], modified: [] });
    expect(report.findings).toEqual([]);
  });

  it('enforces per-file and file-count limits before analysis', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-limit-test-'));
    temporaryPaths.push(root);
    await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'limit', version: '1.0.0' }));
    await writeFile(path.join(root, 'large.js'), 'x'.repeat(200));
    await expect(audit(root, root, { offline: true, limits: { maxFileBytes: 100 } })).rejects.toThrow(/per-file size limit/);
    await expect(audit(root, root, { offline: true, limits: { maxFiles: 1 } })).rejects.toThrow(/more than 1 entries/);
  });

  it('reports malformed archives as user input errors', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-bad-tar-'));
    temporaryPaths.push(root);
    const archive = path.join(root, 'broken.tgz');
    await writeFile(archive, 'this is not a tar archive');
    await expect(audit(safe, archive, { offline: true })).rejects.toThrow(/Cannot inspect archive/);
  });

  it('rejects link entries and traversal paths in real archives', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-hostile-tar-'));
    temporaryPaths.push(root);
    const linkArchive = path.join(root, 'link.tgz');
    const traversalArchive = path.join(root, 'traversal.tgz');
    await writeFile(linkArchive, makeSingleEntryTar('package/link', '2', '../../outside'));
    await writeFile(traversalArchive, makeSingleEntryTar('../escape.js', '0'));
    await expect(audit(safe, linkArchive, { offline: true })).rejects.toThrow(/unsupported SymbolicLink entry/);
    await expect(audit(safe, traversalArchive, { offline: true })).rejects.toThrow(/path traversal/);
  });

  it('aborts archives that exceed the decompression ratio limit', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-ratio-tar-'));
    temporaryPaths.push(root);
    const archive = path.join(root, 'ratio.tgz');
    await writeFile(archive, makeSingleEntryTar('package/zeros.bin', '0', '', Buffer.alloc(128 * 1024)));
    await expect(audit(safe, archive, { offline: true, limits: { maxCompressionRatio: 1 } })).rejects.toThrow(/decompression ratio exceeded/);
  });

  it('rejects mixed-root npm archives instead of silently dropping sibling payloads', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-mixed-root-'));
    temporaryPaths.push(root);
    await mkdir(path.join(root, 'package'), { recursive: true });
    await mkdir(path.join(root, 'other'), { recursive: true });
    await writeFile(path.join(root, 'package', 'package.json'), JSON.stringify({ name: 'mixed-root', version: '1.0.0' }));
    await writeFile(path.join(root, 'other', 'payload.js'), "require('node:child_process').exec(process.env.CMD)");
    const archive = path.join(root, 'mixed.tgz');
    await tar.create({ gzip: true, file: archive, cwd: root, portable: true }, ['package', 'other']);
    await expect(audit(safe, archive, { offline: true })).rejects.toThrow(/outside its canonical package\/ root/);
  });

  it('analyzes bundled dependency payloads shipped under node_modules in archives', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-bundled-'));
    temporaryPaths.push(root);
    const beforeRoot = path.join(root, 'before');
    const afterRoot = path.join(root, 'after');
    for (const [directory, version, code] of [
      [beforeRoot, '1.0.0', 'export const ok = true;'],
      [afterRoot, '1.1.0', "require('node:child_process').exec(process.env.CMD)"],
    ] as const) {
      await mkdir(path.join(directory, 'package', 'node_modules', 'bundled-risk'), { recursive: true });
      await writeFile(path.join(directory, 'package', 'package.json'), JSON.stringify({
        name: 'bundled-host', version, dependencies: { 'bundled-risk': '1.0.0' }, bundledDependencies: ['bundled-risk'],
      }));
      await writeFile(path.join(directory, 'package', 'node_modules', 'bundled-risk', 'index.js'), code);
    }
    const beforeArchive = path.join(root, 'before.tgz');
    const afterArchive = path.join(root, 'after.tgz');
    await tar.create({ gzip: true, file: beforeArchive, cwd: beforeRoot, portable: true }, ['package']);
    await tar.create({ gzip: true, file: afterArchive, cwd: afterRoot, portable: true }, ['package']);
    const report = await audit(beforeArchive, afterArchive, { offline: true });
    expect(report.inventory.modified.map((change) => change.after.path)).toContain('node_modules/bundled-risk/index.js');
    expect(report.findings.map((finding) => finding.id)).toContain('capability.added.child_process');
  });

  it('fails closed when package.json exceeds the parsed manifest limit', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-large-manifest-'));
    temporaryPaths.push(root);
    await writeFile(path.join(root, 'package.json'), JSON.stringify({
      name: 'large-manifest', version: '1.0.0', scripts: { postinstall: 'node steal.js' }, padding: 'x'.repeat(512),
    }));
    await expect(audit(safe, root, { offline: true, limits: { maxTextBytes: 128 } })).rejects.toThrow(/parsed manifest limit/);
  });

  it('validates every redirect before issuing the next request', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn((input: URL | Request) => {
      calls.push(input instanceof URL ? input.toString() : input.url);
      return Promise.resolve(new Response(null, { status: 302, headers: { location: 'https://untrusted.example/payload' } }));
    }));
    await expect(__test.fetchWithTimeout(
      new URL('https://registry.example/package'), 'registry.example', 1_000, 'registry metadata',
    )).rejects.toThrow(/Untrusted redirect/);
    expect(calls).toEqual(['https://registry.example/package']);
  });

  it('follows a bounded relative redirect on the configured origin', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn((input: URL | Request) => {
      const url = input instanceof URL ? input.toString() : input.url;
      calls.push(url);
      return Promise.resolve(calls.length === 1
        ? new Response(null, { status: 302, headers: { location: '/metadata/final' } })
        : new Response('{}', { status: 200 }));
    }));
    const response = await __test.fetchWithTimeout(
      new URL('https://registry.example/package'), 'registry.example', 1_000, 'registry metadata',
    );
    expect(response.status).toBe(200);
    expect(calls).toEqual(['https://registry.example/package', 'https://registry.example/metadata/final']);
  });

  it('aborts chunked registry metadata before buffering beyond 16 MiB', async () => {
    let cancelled = false;
    const chunks = [Buffer.alloc(8 * 1024 * 1024), Buffer.alloc(8 * 1024 * 1024), Buffer.alloc(1)];
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks.shift();
        if (chunk) controller.enqueue(chunk);
        else controller.close();
      },
      cancel() { cancelled = true; },
    });
    await expect(__test.readRegistryDocument(new Response(body))).rejects.toThrow(/16 MiB limit/);
    expect(cancelled).toBe(true);
  });

  it('rejects unsupported SRI and verifies the strongest supported digest', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'depdiff-integrity-'));
    temporaryPaths.push(root);
    const archive = path.join(root, 'payload.tgz');
    const payload = Buffer.from('verified bytes');
    await writeFile(archive, payload);
    const sha256 = createHash('sha256').update(payload).digest('base64');
    const sha512 = createHash('sha512').update(payload).digest('base64');
    await expect(__test.verifyArchiveDigest(archive, 'sha1-ZGVhZGJlZWY=')).rejects.toThrow(/no supported/);
    await expect(__test.verifyArchiveDigest(archive, '')).rejects.toThrow(/empty after whitespace/);
    await expect(__test.verifyArchiveDigest(archive, '   ')).rejects.toThrow(/empty after whitespace/);
    await expect(__test.verifyArchiveDigest(archive, `sha256-${sha256} sha512-!!!`)).rejects.toThrow(/malformed sha512/);
    await expect(__test.verifyArchiveDigest(archive, `sha256-${sha256} sha512-AAAA`)).rejects.toThrow(/sha512/);
    await expect(__test.verifyArchiveDigest(archive, `sha256-AAAA sha512-${sha512}`)).resolves.toBeUndefined();
  });
});

function makeSingleEntryTar(name: string, type: '0' | '2', link = '', content = Buffer.alloc(0)): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  writeOctal(header, 0o644, 100, 8);
  writeOctal(header, 0, 108, 8);
  writeOctal(header, 0, 116, 8);
  writeOctal(header, content.length, 124, 12);
  writeOctal(header, 0, 136, 12);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  header.write(link, 157, 100, 'utf8');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  const checksum = header.reduce((total, value) => total + value, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  const padding = Buffer.alloc((512 - content.length % 512) % 512);
  return gzipSync(Buffer.concat([header, content, padding, Buffer.alloc(1024)]));
}

function writeOctal(buffer: Buffer, value: number, offset: number, width: number): void {
  buffer.write(`${value.toString(8).padStart(width - 1, '0')}\0`, offset, width, 'ascii');
}

describe('archive coverage reconciliation', () => {
  const temporary = path.join(path.sep === '\\' ? 'C:\\tmp' : '/tmp', 'depdiff-cov');
  const root = path.join(temporary, 'package');

  const inventoryOf = (paths: string[]): ReadonlyMap<string, unknown> => new Map(paths.map((filePath) => [filePath, {}]));

  it('accepts an archive whose every shipped path was inventoried', () => {
    expect(() => assertArchiveCoverage(
      temporary,
      root,
      ['package/package.json', 'package/index.js', 'package/lib/a.js'],
      inventoryOf(['package.json', 'index.js', 'lib/a.js']),
      [],
    )).not.toThrow();
  });

  it('fails closed when a case-colliding entry vanished during extraction', () => {
    // What a case-insensitive host produces: INDEX.js and index.js collapse and
    // only one survives, so the other is never inventoried.
    expect(() => assertArchiveCoverage(
      temporary,
      root,
      ['package/package.json', 'package/INDEX.js', 'package/index.js'],
      inventoryOf(['package.json', 'index.js']),
      [],
    )).toThrow(/INDEX\.js/u);
  });

  it('ignores entries outside the detected root and explicitly ignored paths', () => {
    expect(() => assertArchiveCoverage(
      temporary,
      root,
      ['pax_global_header', 'package/index.js', 'package/test/big.bin'],
      inventoryOf(['index.js']),
      ['test/**'],
    )).not.toThrow();
  });
});

describe('text detection', () => {
  it('distinguishes text and NUL-containing binary samples', () => {
    expect(__test.isProbablyText(Buffer.from('hello\nworld'))).toBe(true);
    expect(__test.isProbablyText(Buffer.from([0, 1, 2, 3]))).toBe(false);
  });
});

describe('portable package modes', () => {
  it('normalizes host-only permission differences without hiding executable transitions', () => {
    expect(__test.normalizePackageMode(0o100777, 'text')).toBe(0o755);
    expect(__test.normalizePackageMode(0o100755, 'text')).toBe(0o755);
    expect(__test.normalizePackageMode(0o100666, 'text')).toBe(0o644);
    expect(__test.normalizePackageMode(0o100644, 'text')).toBe(0o644);
    expect(__test.normalizePackageMode(0o120777, 'symlink')).toBe(0o777);
    expect(__test.normalizePackageMode(0o100644, 'text')).not.toBe(
      __test.normalizePackageMode(0o100755, 'text'),
    );
  });
});
