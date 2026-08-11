import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { renderHtml, renderJson, renderMarkdown, renderSarif } from '../src/reports.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');

describe('report formats', () => {
  it('emits a schema-versioned JSON report', async () => {
    const parsed = JSON.parse(renderJson(await audit(safe, risky, { offline: true }))) as Record<string, unknown>;
    expect(parsed.schemaVersion).toBe('1.0.0');
    expect(parsed.analysis).toMatchObject({ packageCodeExecuted: false, offline: true });
  });

  it('emits SARIF with rules, results, fingerprints, and locations', async () => {
    const sarif = JSON.parse(renderSarif(await audit(safe, risky, { offline: true }))) as {
      version: string;
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: Array<Record<string, unknown>> }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.rules.length).toBeGreaterThan(5);
    expect(sarif.runs[0]?.results[0]).toHaveProperty('partialFingerprints.depdiffFingerprint');
  });

  it('emits a useful Markdown review artifact', async () => {
    const markdown = renderMarkdown(await audit(safe, risky, { offline: true }));
    expect(markdown).toContain('# Depdiff audit report');
    expect(markdown).toContain('Package code executed: **no**');
    expect(markdown).toContain('New child process capability');
    expect(markdown).toContain('## Scope and limits');
  });

  it('emits standalone HTML and escapes report-controlled markup', async () => {
    const report = await audit(safe, risky, { offline: true });
    report.findings[0]!.title = '<img src=x onerror=alert(1)>';
    const html = renderHtml(report);
    expect(html).toContain('<!doctype html>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toMatch(/https?:\/\/[^'" ]+\.(?:css|js)[?'" ]/);
    expect(html).toContain('Download JSON');
  });
});
