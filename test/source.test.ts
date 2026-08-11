import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import * as tar from 'tar';
import { afterEach, describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { assertSafeArchivePath, __test } from '../src/source.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const temporaryPaths: string[] = [];

afterEach(async () => {
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

describe('text detection', () => {
  it('distinguishes text and NUL-containing binary samples', () => {
    expect(__test.isProbablyText(Buffer.from('hello\nworld'))).toBe(true);
    expect(__test.isProbablyText(Buffer.from([0, 1, 2, 3]))).toBe(false);
  });
});
