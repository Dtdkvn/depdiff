import { describe, expect, it } from 'vitest';
import {
  classifyCodeFile,
  codeExtension,
  foldStaticString,
  inertRegionsFromAst,
  looksLikeJavaScript,
  parseSource,
  resolveEntryReasons,
  scanInertRegions,
  walkAst,
} from '../src/codeprofile.js';

const CODE = "const cp = require('child_process');\n";

describe('shipped-code classification', () => {
  it.each([
    ['index.js', '.js'],
    ['index.js.', '.js'],
    ['index.js ', '.js'],
    ['index.js...  ', '.js'],
    ['bin/acme', ''],
    ['a/b.MJS', '.mjs'],
    ['.eslintrc', ''],
    ['addon.node', '.node'],
    ['addon.node.', '.node'],
  ])('derives the effective extension of %s', (filePath, expected) => {
    expect(codeExtension(filePath)).toBe(expected);
  });

  it('selects code by extension, manifest reference, shebang, and content', () => {
    const probe = Buffer.from(CODE);
    expect(classifyCodeFile({ filePath: 'a.js', kind: 'text', probe: undefined, entryReason: undefined })).toMatchObject({ code: true, reason: 'extension' });
    expect(classifyCodeFile({ filePath: 'index.js.', kind: 'text', probe: undefined, entryReason: undefined })).toMatchObject({ code: true, reason: 'extension' });
    expect(classifyCodeFile({ filePath: 'bin/acme', kind: 'binary', probe: undefined, entryReason: 'manifest-entry' })).toMatchObject({ code: true, reason: 'manifest-entry' });
    expect(classifyCodeFile({ filePath: 'bin/acme', kind: 'text', probe: Buffer.from('#!/usr/bin/env node\n'), entryReason: undefined })).toMatchObject({ code: true, reason: 'shebang' });
    expect(classifyCodeFile({ filePath: 'bin/acme', kind: 'text', probe, entryReason: undefined })).toMatchObject({ code: true, reason: 'content' });
  });

  it('never treats another language, data, or a symlink as JavaScript', () => {
    for (const input of [
      { filePath: 'bin/build.sh', kind: 'text' as const, probe: Buffer.from('#!/bin/sh\necho hi\n'), entryReason: 'manifest-entry' as const },
      { filePath: 'bin/tool', kind: 'text' as const, probe: Buffer.from('#!/usr/bin/env python3\nimport os\n'), entryReason: 'manifest-entry' as const },
      { filePath: 'data.json', kind: 'text' as const, probe: Buffer.from('{"a":1}'), entryReason: undefined },
      { filePath: 'README.md', kind: 'text' as const, probe: Buffer.from(`\`\`\`\n${CODE}\`\`\`\n`), entryReason: undefined },
      { filePath: 'link', kind: 'symlink' as const, probe: Buffer.from(CODE), entryReason: undefined },
      { filePath: 'NOTICE', kind: 'text' as const, probe: Buffer.from('Copyright 2026 Example.\n'), entryReason: undefined },
    ]) {
      expect(classifyCodeFile(input), input.filePath).toMatchObject({ code: false });
    }
  });

  it('requires corroborating markers before calling unknown content JavaScript', () => {
    expect(looksLikeJavaScript('just a sentence about const values\n')).toBe(false);
    expect(looksLikeJavaScript("const a = require('fs');\nmodule.exports = a;\n")).toBe(true);
  });

  it('resolves manifest and script references through Node implicit resolution', () => {
    const shipped = new Set(['lib/entry.js', 'hooks/setup', 'pkg/index.mjs', 'other.js']);
    const reasons = resolveEntryReasons(['./lib/entry', 'pkg', 'missing/*'], ['node', 'hooks/setup'], shipped);
    expect(reasons.get('lib/entry.js')).toBe('manifest-entry');
    expect(reasons.get('pkg/index.mjs')).toBe('manifest-entry');
    expect(reasons.get('hooks/setup')).toBe('lifecycle-script');
    expect(reasons.has('other.js')).toBe(false);
  });
});

describe('tolerant parsing', () => {
  it('parses a legacy TypeScript cast that the jsx plugin would reject', () => {
    const parsed = parseSource('const z = <string>(y as unknown);\n', '.ts');
    expect(parsed.error).toBeUndefined();
    expect(parsed.ast).toBeDefined();
  });

  it('parses tsx, flow-annotated js, and plain jsx', () => {
    expect(parseSource('const a = <div x={1}>t</div>;\n', '.tsx').error).toBeUndefined();
    expect(parseSource('const a = <div x={1}>t</div>;\n', '.jsx').error).toBeUndefined();
    expect(parseSource('// @flow\nfunction f(x: number): number { return x; }\n', '.js').error).toBeUndefined();
  });

  it('reports a stack-exhausting file as a parse failure instead of crashing', () => {
    const parsed = parseSource(`const x = ${'('.repeat(1_200)}1${')'.repeat(1_200)};\n`, '.js');
    expect(parsed.ast).toBeUndefined();
    expect(parsed.error).toMatch(/parser stack/);
  });

  it('walks deeply nested trees without recursing', () => {
    // The tree is built directly rather than parsed: how deep @babel/parser can
    // go before exhausting the stack depends on the host runtime (a Vitest
    // worker has far less stack than a plain node process), and this test is
    // about walkAst not recursing, not about the parser's depth limit.
    let tree: Record<string, unknown> = { type: 'NumericLiteral', value: 1 };
    for (let depth = 0; depth < 5_000; depth += 1) tree = { type: 'ArrayExpression', elements: [tree] };
    let arrays = 0;
    walkAst(tree, (node) => { if (node.type === 'ArrayExpression') arrays += 1; });
    expect(arrays).toBe(5_000);
  });
});

describe('inert regions', () => {
  const source = [
    '// eval( in a line comment',
    '/* require("child_process") in a block comment */',
    'const text = "eval( inside a string";',
    'eval(real);',
  ].join('\n');

  it.each([
    ['from the AST', (value: string) => inertRegionsFromAst(parseSource(value, '.js').ast)],
    ['from the fallback scanner', (value: string) => scanInertRegions(value)],
  ])('marks comments and string literals inert %s', (_label, build) => {
    const regions = build(source);
    expect(regions.comments.contains(source.indexOf('eval( in a line'))).toBe(true);
    expect(regions.comments.contains(source.indexOf('require("child_process")'))).toBe(true);
    expect(regions.literals.contains(source.indexOf('eval( inside'))).toBe(true);
    expect(regions.comments.contains(source.indexOf('eval(real)'))).toBe(false);
    expect(regions.literals.contains(source.indexOf('eval(real)'))).toBe(false);
  });

  it('keeps template expressions and division outside string literals', () => {
    const value = 'const a = `x${1 / 2}y`;\nconst b = 4 / 2;\neval(z);\n';
    const regions = scanInertRegions(value);
    expect(regions.literals.contains(value.indexOf('1 / 2'))).toBe(false);
    expect(regions.literals.contains(value.indexOf('4 / 2'))).toBe(false);
    expect(regions.literals.contains(value.indexOf('eval(z)'))).toBe(false);
    expect(regions.literals.contains(value.indexOf('y`'))).toBe(true);
  });
});

describe('static string folding', () => {
  function fold(expression: string): { value: string; literal: boolean } | undefined {
    let result: { value: string; literal: boolean } | undefined;
    walkAst(parseSource(`x(${expression});\n`, '.js').ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const callee = node.callee;
      const isTarget = callee !== null && typeof callee === 'object' && 'name' in callee && callee.name === 'x';
      if (isTarget && Array.isArray(node.arguments)) result ??= foldStaticString((node.arguments as unknown[])[0]);
    });
    return result;
  }

  it.each([
    ["'child_process'", 'child_process', true],
    ['`child_process`', 'child_process', true],
    ["'child' + '_process'", 'child_process', false],
    ["['child','process'].join('_')", 'child_process', false],
    ["Buffer.from('Y2hpbGRfcHJvY2Vzcw==','base64').toString()", 'child_process', false],
    ["atob('Y2hpbGRfcHJvY2Vzcw==')", 'child_process', false],
    ['String.fromCharCode(102,115)', 'fs', false],
    ["'ev'.concat('al')", 'eval', false],
  ])('folds %s', (expression, value, literal) => {
    expect(fold(expression)).toEqual({ value, literal });
  });

  it('leaves runtime-computed values unresolved', () => {
    expect(fold('process.env.PLUGIN')).toBeUndefined();
    expect(fold("'./' + name")).toBeUndefined();
    expect(fold("path.join(dir, 'x')")).toBeUndefined();
  });
});
