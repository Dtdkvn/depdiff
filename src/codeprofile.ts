import path from 'node:path';
import { parse } from '@babel/parser';
import type { ParserPlugin } from '@babel/parser';
import { isRecord } from './util.js';

/**
 * Static-analysis primitives shared by the analyzer: deciding whether a shipped
 * file is code, parsing it as tolerantly as possible, locating the regions of a
 * source file that cannot execute, and folding statically computable strings.
 *
 * Nothing in this module executes, imports, or resolves target package code.
 */

/** Extensions Node, npm, or a bundler treats as JavaScript/TypeScript source. */
export const CODE_EXTENSIONS = new Set([
  '.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts', '.tsx', '.es', '.es6', '.jsm',
]);

export const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.node', '.wasm', '.bin', '.dat', '.jar',
]);

/**
 * Extensions that are never JavaScript. Files carrying one of these are not
 * parsed and never raise an analysis-coverage finding, so shipping data, docs,
 * or another language does not make benign updates noisy.
 */
const NON_CODE_EXTENSIONS = new Set([
  '.md', '.markdown', '.mdx', '.txt', '.text', '.rst', '.adoc', '.license', '.flow',
  '.json', '.json5', '.jsonc', '.jsonl', '.ndjson', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.properties',
  '.html', '.htm', '.xhtml', '.xml', '.xsl', '.svg', '.css', '.scss', '.sass', '.less', '.styl',
  '.map', '.lock', '.snap', '.patch', '.diff', '.csv', '.tsv', '.proto', '.graphql', '.gql', '.sql', '.d',
  '.sh', '.bash', '.zsh', '.fish', '.ksh', '.ps1', '.psm1', '.bat', '.cmd', '.mk', '.makefile', '.cmake',
  '.py', '.pyi', '.rb', '.pl', '.pm', '.php', '.go', '.rs', '.java', '.scala', '.kt', '.kts', '.swift',
  '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.m', '.mm', '.cs', '.fs', '.ex', '.exs', '.erl', '.lua',
  '.vue', '.svelte', '.astro', '.hbs', '.handlebars', '.ejs', '.pug', '.jade', '.mustache', '.twig', '.liquid', '.njk',
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.bmp', '.tiff', '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.zip', '.gz', '.tgz', '.br', '.xz', '.bz2', '.7z', '.rar', '.pdf', '.mp3', '.mp4', '.webm', '.wav', '.ogg',
  ...BINARY_EXTENSIONS,
]);

/** Shebang interpreters that make the file JavaScript rather than another language. */
const JS_SHEBANG = /^#!.*?\b(?:node(?:js)?|bun|deno|ts-node|tsx|qjs)\b/;
const ANY_SHEBANG = /^#!/;

const CREATE_REQUIRE = 'createRequire';

/** Property names that load a module when called, including Node's internals. */
export const MODULE_LOAD_PROPERTIES = new Set(['require', '_load', '_compile', '_resolveFilename']);

/** Property names that compile a string into executable code when called. */
export const DYNAMIC_CODE_PROPERTIES = new Set(['eval', 'Function', 'constructor', 'runInThisContext', 'runInNewContext', 'compileFunction']);

const SKIPPED_AST_KEYS = new Set([
  'loc', 'tokens', 'comments', 'errors', 'leadingComments', 'trailingComments', 'innerComments', 'extra',
]);

/**
 * Derives the effective extension of a shipped path. Trailing dots and spaces
 * are stripped first: Windows and npm both tolerate `index.js.` and `index.js `,
 * and Node loads them as `index.js`, so they must not hide from the analyzer.
 */
export function codeExtension(filePath: string): string {
  const base = path.posix.basename(filePath.replaceAll('\\', '/')).replace(/[.\s]+$/, '');
  return path.posix.extname(base).toLowerCase();
}

export type CodeReason = 'extension' | 'manifest-entry' | 'lifecycle-script' | 'shebang' | 'content';

/**
 * Decides whether a shipped path holds JavaScript/TypeScript, using content and
 * manifest metadata rather than an extension allowlist. `probe` is the leading
 * bytes of the file and is available even when the full content is not.
 */
export function classifyCodeFile(input: {
  filePath: string;
  kind: 'text' | 'binary' | 'symlink';
  probe: Buffer | undefined;
  entryReason: CodeReason | undefined;
}): { code: boolean; reason?: CodeReason } {
  if (input.kind === 'symlink') return { code: false };
  const extension = codeExtension(input.filePath);
  if (CODE_EXTENSIONS.has(extension)) return { code: true, reason: 'extension' };
  const head = input.probe ? stripBom(input.probe.toString('utf8')) : '';
  // A non-JavaScript interpreter line is authoritative: never parse a shell or
  // Python script as JavaScript, whatever the manifest says about it.
  if (ANY_SHEBANG.test(head) && !JS_SHEBANG.test(head)) return { code: false };
  if (input.entryReason) return { code: true, reason: input.entryReason };
  if (NON_CODE_EXTENSIONS.has(extension)) return { code: false };
  if (JS_SHEBANG.test(head)) return { code: true, reason: 'shebang' };
  return looksLikeJavaScript(head) ? { code: true, reason: 'content' } : { code: false };
}

function stripBom(value: string): string {
  return value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
}

/**
 * Conservative JavaScript sniffer for files with no usable extension. Requires
 * corroborating markers so plain text and configuration data stay out.
 */
export function looksLikeJavaScript(text: string): boolean {
  let score = 0;
  if (/\brequire\s*\(\s*['"`]/.test(text)) score += 2;
  if (/\bmodule\s*\.\s*exports\b/.test(text)) score += 2;
  if (/^\s*(?:import|export)\b[^\n]*\bfrom\s*['"]/m.test(text)) score += 2;
  if (/\bexports\s*\.\s*[A-Za-z_$]/.test(text)) score += 1;
  if (/\bfunction\s*[*A-Za-z_$(]/.test(text)) score += 1;
  if (/=>\s*[{(A-Za-z_$'"`]/.test(text)) score += 1;
  if (/\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=/.test(text)) score += 1;
  if (/\bclass\s+[A-Za-z_$][\w$]*\s*(?:extends\b|\{)/.test(text)) score += 1;
  if (/\b(?:async\s+)?function\s*\*?\s*[A-Za-z_$]*\s*\([^)]*\)\s*\{/.test(text)) score += 1;
  return score >= 3;
}

/**
 * Collects every relative path the manifest points at: `main`, `module`,
 * `browser`, `bin`, `exports`, `imports`, and `types`. npm and Node load these
 * regardless of their file extension.
 */
export function manifestEntryPaths(document: Record<string, unknown>): string[] {
  const entries: string[] = [];
  for (const field of ['main', 'module', 'browser', 'types', 'typings', 'unpkg', 'jsdelivr', 'bin', 'exports', 'imports']) {
    collectPathStrings(document[field], entries, 0);
  }
  return [...new Set(entries)].sort(compareCodeUnits);
}

/** Extracts candidate file references from lifecycle and other npm scripts. */
export function scriptEntryTokens(scripts: Record<string, string>): string[] {
  const tokens: string[] = [];
  for (const command of Object.values(scripts)) tokens.push(...shellTokens(command));
  return [...new Set(tokens)].sort(compareCodeUnits);
}

function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function collectPathStrings(value: unknown, into: string[], depth: number): void {
  if (depth > 8) return;
  if (typeof value === 'string') {
    if (value && !value.includes('*')) into.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPathStrings(item, into, depth + 1);
    return;
  }
  if (isRecord(value)) {
    for (const item of Object.values(value)) collectPathStrings(item, into, depth + 1);
  }
}

/** Splits a lifecycle command into candidate file references. */
function shellTokens(command: string): string[] {
  return command
    .split(/[\s;|&<>()"']+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0 && !token.startsWith('-'));
}

/**
 * Resolves manifest and lifecycle references against the shipped inventory,
 * applying Node's implicit extension and directory-index resolution.
 */
export function resolveEntryReasons(
  entries: readonly string[],
  scriptTokens: readonly string[],
  shipped: ReadonlySet<string>,
): Map<string, CodeReason> {
  const reasons = new Map<string, CodeReason>();
  for (const [list, reason] of [[entries, 'manifest-entry'], [scriptTokens, 'lifecycle-script']] as const) {
    for (const raw of list) {
      const resolved = resolveShippedPath(raw, shipped);
      if (resolved !== undefined && !reasons.has(resolved)) reasons.set(resolved, reason);
    }
  }
  return reasons;
}

function resolveShippedPath(raw: string, shipped: ReadonlySet<string>): string | undefined {
  const normalized = raw.replaceAll('\\', '/').replace(/^\.\//, '').replace(/^\/+/, '');
  if (!normalized || normalized.startsWith('../') || normalized.includes('\0')) return undefined;
  const candidates = [
    normalized,
    `${normalized}.js`, `${normalized}.cjs`, `${normalized}.mjs`, `${normalized}.json`,
    `${normalized}/index.js`, `${normalized}/index.cjs`, `${normalized}/index.mjs`,
  ];
  return candidates.find((candidate) => shipped.has(candidate));
}

const RANGE_ERROR = 'RangeError';

export interface ParsedSource {
  ast?: unknown;
  /** True when the AST came from error recovery, so coverage is incomplete. */
  degraded: boolean;
  error?: string;
}

/**
 * Parses a source file, trying the plugin combinations that are actually valid
 * for its extension. `typescript` and `jsx` conflict on legacy `<T>x` casts, so
 * they are never forced on together for a `.ts` file. When every strict attempt
 * fails, one recovering attempt still yields a partial AST for the detectors.
 */
export function parseSource(source: string, extension: string): ParsedSource {
  let firstError: unknown;
  for (const plugins of parsePlan(extension)) {
    try {
      return { ast: parseWith(source, plugins, false), degraded: false };
    } catch (error) {
      firstError ??= error;
      if (isStackExhaustion(error)) return { degraded: false, error: describeParseError(error) };
    }
  }
  for (const plugins of parsePlan(extension)) {
    try {
      return { ast: parseWith(source, plugins, true), degraded: true, error: describeParseError(firstError) };
    } catch {
      // Keep the strict error; recovery is best effort.
    }
  }
  return { degraded: false, error: describeParseError(firstError) };
}

function parsePlan(extension: string): ParserPlugin[][] {
  if (extension === '.ts' || extension === '.cts' || extension === '.mts') {
    return [['typescript'], ['typescript', 'jsx']];
  }
  if (extension === '.tsx') return [['typescript', 'jsx'], ['typescript']];
  return [['jsx'], ['typescript', 'jsx'], ['typescript'], ['jsx', 'flow']];
}

function parseWith(source: string, plugins: ParserPlugin[], errorRecovery: boolean): unknown {
  return parse(source, {
    sourceType: 'unambiguous',
    errorRecovery,
    allowAwaitOutsideFunction: true,
    allowNewTargetOutsideFunction: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    plugins: [...plugins, 'decorators-legacy', 'importAttributes', 'topLevelAwait'],
  });
}

function isStackExhaustion(error: unknown): boolean {
  return error instanceof RangeError || (error instanceof Error && error.name === RANGE_ERROR);
}

function describeParseError(error: unknown): string {
  if (isStackExhaustion(error)) {
    return 'Source nesting exhausted the parser stack, so no abstract syntax tree could be produced.';
  }
  return error instanceof Error ? error.message : String(error);
}

/** Iterative pre-order AST walk. Never recurses, so nesting cannot exhaust the stack. */
export function walkAst(root: unknown, visit: (node: Record<string, unknown>) => void): void {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) stack.push(value[index]);
      continue;
    }
    if (!isRecord(value)) continue;
    if (typeof value.type === 'string') visit(value);
    const children: unknown[] = [];
    for (const [key, child] of Object.entries(value)) {
      if (SKIPPED_AST_KEYS.has(key)) continue;
      if (Array.isArray(child) || isRecord(child)) children.push(child);
    }
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
}

/** Sorted, merged, half-open `[start, end)` ranges with binary-search lookup. */
export class RangeSet {
  private readonly starts: number[] = [];
  private readonly ends: number[] = [];

  constructor(ranges: Array<readonly [number, number]>) {
    const sorted = [...ranges]
      .filter(([start, end]) => Number.isFinite(start) && Number.isFinite(end) && end > start)
      .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    for (const [start, end] of sorted) {
      const last = this.ends.length - 1;
      const previousEnd = this.ends[last];
      if (previousEnd !== undefined && start <= previousEnd) {
        this.ends[last] = Math.max(previousEnd, end);
        continue;
      }
      this.starts.push(start);
      this.ends.push(end);
    }
  }

  contains(index: number): boolean {
    let low = 0;
    let high = this.starts.length - 1;
    while (low <= high) {
      const middle = (low + high) >> 1;
      if (index < (this.starts[middle] ?? 0)) high = middle - 1;
      else if (index >= (this.ends[middle] ?? 0)) low = middle + 1;
      else return true;
    }
    return false;
  }
}

/**
 * Regions of a source file that cannot run.
 *
 * `comments` can never execute, so a capability named there is not a capability
 * and a URL named there is not a destination. `literals` hold data: an `eval(`
 * spelled inside a string is not a call, but a URL inside a string literal very
 * much is a destination, so the two sets are tracked separately.
 */
export interface InertRegions {
  comments: RangeSet;
  literals: RangeSet;
}

const LITERAL_NODE_TYPES = new Set(['StringLiteral', 'TemplateElement', 'RegExpLiteral', 'DirectiveLiteral', 'JSXText']);

/** Derives inert regions from a parsed AST, the authoritative source. */
export function inertRegionsFromAst(ast: unknown): InertRegions {
  const comments: Array<[number, number]> = [];
  const literals: Array<[number, number]> = [];
  if (isRecord(ast) && Array.isArray(ast.comments)) {
    for (const comment of ast.comments as unknown[]) {
      const range = nodeRange(comment);
      if (range) comments.push(range);
    }
  }
  walkAst(ast, (node) => {
    if (typeof node.type !== 'string' || !LITERAL_NODE_TYPES.has(node.type)) return;
    const range = nodeRange(node);
    if (range) literals.push(range);
  });
  return { comments: new RangeSet(comments), literals: new RangeSet(literals) };
}

function nodeRange(value: unknown): [number, number] | undefined {
  if (!isRecord(value)) return undefined;
  const { start, end } = value;
  return typeof start === 'number' && typeof end === 'number' ? [start, end] : undefined;
}

const REGEX_PRECEDING = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', ';', '+', '-', '*', '%', '~', '^', '<', '>']);
const REGEX_KEYWORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'do', 'else', 'yield', 'await', 'case']);

/**
 * Brace bookkeeping for the fallback scanner. `braces` is the current depth and
 * `templates` records, for each open `${`, the depth the template resumes at, so
 * that an object literal inside an interpolation is not mistaken for its end.
 */
type ScanState = { braces: number; templates: number[] };

/**
 * Fallback scanner used when a file could not be parsed at all. It deliberately
 * errs toward marking less content inert: under-masking keeps a detector firing,
 * while over-masking would hide a real capability.
 */
export function scanInertRegions(source: string): InertRegions {
  const comments: Array<[number, number]> = [];
  const literals: Array<[number, number]> = [];
  let index = 0;
  // `templates` records, per open `${`, the brace depth the template resumes at.
  const state: ScanState = { braces: 0, templates: [] };
  while (index < source.length) {
    const character = source[index] ?? '';
    const nextCharacter = source[index + 1] ?? '';
    if (character === '/' && nextCharacter === '/') {
      const end = source.indexOf('\n', index);
      comments.push([index, end === -1 ? source.length : end]);
      index = end === -1 ? source.length : end;
      continue;
    }
    if (character === '/' && nextCharacter === '*') {
      const end = source.indexOf('*/', index + 2);
      const stop = end === -1 ? source.length : end + 2;
      comments.push([index, stop]);
      index = stop;
      continue;
    }
    if (character === '"' || character === "'") {
      index = readQuoted(source, index, character, literals);
      continue;
    }
    if (character === '`') {
      index = readTemplateChunk(source, index + 1, literals, state);
      continue;
    }
    if (character === '}') {
      state.braces -= 1;
      if (state.templates[state.templates.length - 1] === state.braces) {
        state.templates.pop();
        index = readTemplateChunk(source, index + 1, literals, state);
        continue;
      }
      index += 1;
      continue;
    }
    if (character === '{') {
      state.braces += 1;
      index += 1;
      continue;
    }
    if (character === '/' && regexAllowed(source, index)) {
      const end = readRegex(source, index);
      if (end > index) {
        literals.push([index, end]);
        index = end;
        continue;
      }
    }
    index += 1;
  }
  return { comments: new RangeSet(comments), literals: new RangeSet(literals) };
}

function readQuoted(source: string, start: number, quote: string, literals: Array<[number, number]>): number {
  let index = start + 1;
  while (index < source.length) {
    const character = source[index];
    if (character === '\\') {
      index += 2;
      continue;
    }
    if (character === quote) {
      literals.push([start, index + 1]);
      return index + 1;
    }
    if (character === '\n') break;
    index += 1;
  }
  literals.push([start, index]);
  return index;
}

function readTemplateChunk(
  source: string,
  start: number,
  literals: Array<[number, number]>,
  state: ScanState,
): number {
  let index = start;
  while (index < source.length) {
    const character = source[index];
    if (character === '\\') {
      index += 2;
      continue;
    }
    if (character === '`') {
      literals.push([start, index]);
      return index + 1;
    }
    if (character === '$' && source[index + 1] === '{') {
      literals.push([start, index]);
      // `${` opens a brace of its own, so record the depth the template resumes
      // at and enter the interpolation one level deeper. Without the increment
      // the interpolation's closing brace would never match the recorded depth.
      state.templates.push(state.braces);
      state.braces += 1;
      return index + 2;
    }
    index += 1;
  }
  literals.push([start, index]);
  return index;
}

function regexAllowed(source: string, slash: number): boolean {
  let index = slash - 1;
  while (index >= 0 && /\s/.test(source[index] ?? '')) index -= 1;
  if (index < 0) return true;
  const character = source[index] ?? '';
  if (REGEX_PRECEDING.has(character)) return true;
  if (!/[\w$]/.test(character)) return false;
  const wordEnd = index + 1;
  while (index >= 0 && /[\w$]/.test(source[index] ?? '')) index -= 1;
  return REGEX_KEYWORDS.has(source.slice(index + 1, wordEnd));
}

function readRegex(source: string, start: number): number {
  let index = start + 1;
  let inClass = false;
  while (index < source.length) {
    const character = source[index];
    if (character === '\\') {
      index += 2;
      continue;
    }
    if (character === '\n') return start;
    if (character === '[') inClass = true;
    else if (character === ']') inClass = false;
    else if (character === '/' && !inClass) {
      index += 1;
      while (index < source.length && /[a-z]/.test(source[index] ?? '')) index += 1;
      return index;
    }
    index += 1;
  }
  return start;
}

/** Precomputed line offsets so evidence lookup stays linear in the file size. */
export class LineIndex {
  private readonly starts: number[] = [0];

  constructor(private readonly source: string) {
    for (let index = source.indexOf('\n'); index !== -1; index = source.indexOf('\n', index + 1)) {
      this.starts.push(index + 1);
    }
  }

  lineNumber(offset: number): number {
    let low = 0;
    let high = this.starts.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if ((this.starts[middle] ?? 0) <= offset) low = middle;
      else high = middle - 1;
    }
    return low + 1;
  }

  lineText(offset: number): string {
    const line = this.lineNumber(offset) - 1;
    const start = this.starts[line] ?? 0;
    const end = this.starts[line + 1];
    return this.source.slice(start, end === undefined ? this.source.length : end - 1);
  }
}

export interface FoldedString {
  value: string;
  /** True when the source spelled the value out as a plain string literal. */
  literal: boolean;
}

/**
 * Folds statically computable strings. `require(['child','_process'].join('_'))`
 * and `require(Buffer.from('…','base64').toString())` name a module just as
 * plainly as a quoted literal does, and must report the same capability.
 * Runtime-computed values stay unresolved by design.
 */
export function foldStaticString(node: unknown, depth = 0): FoldedString | undefined {
  if (depth > 12 || !isRecord(node)) return undefined;
  const type = node.type;
  if (type === 'StringLiteral' || type === 'DirectiveLiteral') {
    return typeof node.value === 'string' ? { value: node.value, literal: true } : undefined;
  }
  if (type === 'TemplateLiteral') return foldTemplate(node, depth);
  if (type === 'TSAsExpression' || type === 'TSTypeAssertion' || type === 'TSNonNullExpression' || type === 'TSSatisfiesExpression') {
    return foldStaticString(node.expression, depth + 1);
  }
  if (type === 'ParenthesizedExpression') return foldStaticString(node.expression, depth + 1);
  if (type === 'BinaryExpression' && node.operator === '+') {
    const left = foldStaticString(node.left, depth + 1);
    const right = foldStaticString(node.right, depth + 1);
    return left && right ? { value: left.value + right.value, literal: false } : undefined;
  }
  if (type === 'CallExpression' || type === 'NewExpression') return foldCall(node, depth);
  return undefined;
}

function foldTemplate(node: Record<string, unknown>, depth: number): FoldedString | undefined {
  const quasis = Array.isArray(node.quasis) ? (node.quasis as unknown[]) : [];
  const expressions = Array.isArray(node.expressions) ? (node.expressions as unknown[]) : [];
  const parts: string[] = [];
  for (const [index, quasi] of quasis.entries()) {
    const cooked = isRecord(quasi) && isRecord(quasi.value) ? quasi.value.cooked : undefined;
    if (typeof cooked !== 'string') return undefined;
    parts.push(cooked);
    if (index < expressions.length) {
      const folded = foldStaticString(expressions[index], depth + 1);
      if (!folded) return undefined;
      parts.push(folded.value);
    }
  }
  return { value: parts.join(''), literal: expressions.length === 0 };
}

function foldCall(node: Record<string, unknown>, depth: number): FoldedString | undefined {
  const callee = node.callee;
  const args = Array.isArray(node.arguments) ? (node.arguments as unknown[]) : [];
  if (isRecord(callee) && callee.type === 'Identifier' && callee.name === 'atob') {
    const encoded = foldStaticString(args[0], depth + 1);
    return encoded ? { value: decodeBase64(encoded.value), literal: false } : undefined;
  }
  if (!isRecord(callee) || callee.type !== 'MemberExpression') return undefined;
  const property = memberPropertyName(callee, depth);
  const object = callee.object;
  if (property === 'join' && isRecord(object) && object.type === 'ArrayExpression') {
    const items = Array.isArray(object.elements) ? (object.elements as unknown[]) : [];
    const parts: string[] = [];
    for (const item of items) {
      const folded = foldStaticString(item, depth + 1);
      if (!folded) return undefined;
      parts.push(folded.value);
    }
    const separator = args.length > 0 ? foldStaticString(args[0], depth + 1) : { value: ',', literal: true };
    return separator ? { value: parts.join(separator.value), literal: false } : undefined;
  }
  if (property === 'concat') {
    const head = foldStaticString(object, depth + 1);
    if (!head) return undefined;
    const parts = [head.value];
    for (const argument of args) {
      const folded = foldStaticString(argument, depth + 1);
      if (!folded) return undefined;
      parts.push(folded.value);
    }
    return { value: parts.join(''), literal: false };
  }
  if (property === 'fromCharCode' && isRecord(object) && object.type === 'Identifier' && object.name === 'String') {
    const codes: number[] = [];
    for (const argument of args) {
      if (!isRecord(argument) || argument.type !== 'NumericLiteral' || typeof argument.value !== 'number') return undefined;
      codes.push(argument.value);
    }
    return { value: String.fromCharCode(...codes), literal: false };
  }
  if (property === 'toString') return foldBufferDecode(object, args, depth);
  if (property === 'from' && isRecord(object) && object.type === 'Identifier' && object.name === 'Buffer') {
    // `Buffer.from(x)` alone is not a string; only `.toString()` on it is.
    return undefined;
  }
  return undefined;
}

function foldBufferDecode(object: unknown, args: unknown[], depth: number): FoldedString | undefined {
  if (!isRecord(object) || object.type !== 'CallExpression') return undefined;
  const innerCallee = object.callee;
  if (!isRecord(innerCallee) || innerCallee.type !== 'MemberExpression') return undefined;
  if (memberPropertyName(innerCallee, depth) !== 'from') return undefined;
  const target = innerCallee.object;
  if (!isRecord(target) || target.type !== 'Identifier' || target.name !== 'Buffer') return undefined;
  const innerArgs = Array.isArray(object.arguments) ? (object.arguments as unknown[]) : [];
  const data = foldStaticString(innerArgs[0], depth + 1);
  if (!data) return undefined;
  const sourceEncoding = innerArgs.length > 1 ? foldStaticString(innerArgs[1], depth + 1)?.value : 'utf8';
  const targetEncoding = args.length > 0 ? foldStaticString(args[0], depth + 1)?.value : 'utf8';
  if (sourceEncoding === undefined || targetEncoding === undefined) return undefined;
  if (!['utf8', 'utf-8', 'base64', 'base64url', 'hex', 'latin1', 'ascii', 'binary'].includes(sourceEncoding)) return undefined;
  if (!['utf8', 'utf-8', 'latin1', 'ascii', 'binary'].includes(targetEncoding)) return undefined;
  try {
    return { value: Buffer.from(data.value, sourceEncoding as BufferEncoding).toString(targetEncoding as BufferEncoding), literal: false };
  } catch {
    return undefined;
  }
}

function decodeBase64(value: string): string {
  try {
    return Buffer.from(value, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

/** Resolves a member expression's property name, folding computed keys. */
export function memberPropertyName(node: Record<string, unknown>, depth = 0): string | undefined {
  const property = node.property;
  if (!isRecord(property)) return undefined;
  if (node.computed === true) return foldStaticString(property, depth + 1)?.value;
  if (property.type === 'Identifier' && typeof property.name === 'string') return property.name;
  if (property.type === 'StringLiteral' && typeof property.value === 'string') return property.value;
  return undefined;
}

export interface AliasTables {
  /** Local names that hold a module-loading function. */
  requireLike: Set<string>;
  /** Local names that hold `eval`, `Function`, or another code compiler. */
  dynamicLike: Set<string>;
  /** Local names that produce a require function when called. */
  requireFactories: Set<string>;
}

interface Binding {
  target: string;
  init: unknown;
}

/**
 * Resolves local aliases of `require`, `createRequire`, and the dynamic-code
 * constructors, so `const r = require; r('child_process')` reports the same
 * capability as a direct call.
 */
export function collectAliases(ast: unknown): AliasTables {
  const bindings: Binding[] = [];
  const requireLike = new Set<string>();
  const dynamicLike = new Set<string>();
  const requireFactories = new Set([CREATE_REQUIRE]);
  walkAst(ast, (node) => {
    const type = node.type;
    if (type === 'VariableDeclarator') {
      collectPatternBinding(node.id, node.init, bindings, requireFactories);
      return;
    }
    if (type === 'AssignmentExpression' && node.operator === '=') {
      collectPatternBinding(node.left, node.right, bindings, requireFactories);
      return;
    }
    if (type === 'ImportSpecifier') {
      const imported = isRecord(node.imported) ? node.imported : undefined;
      const importedName = imported && typeof imported.name === 'string' ? imported.name : undefined;
      const local = isRecord(node.local) && typeof node.local.name === 'string' ? node.local.name : undefined;
      if (importedName === CREATE_REQUIRE && local) requireFactories.add(local);
    }
  });
  for (let round = 0; round < 6; round += 1) {
    let changed = false;
    for (const { target, init } of bindings) {
      const kind = classifyInit(init, requireLike, dynamicLike, requireFactories);
      if (kind === 'require' && !requireLike.has(target)) { requireLike.add(target); changed = true; }
      if (kind === 'dynamic' && !dynamicLike.has(target)) { dynamicLike.add(target); changed = true; }
      if (kind === 'factory' && !requireFactories.has(target)) { requireFactories.add(target); changed = true; }
    }
    if (!changed) break;
  }
  return { requireLike, dynamicLike, requireFactories };
}

function collectPatternBinding(
  target: unknown,
  init: unknown,
  bindings: Binding[],
  requireFactories: Set<string>,
): void {
  if (!isRecord(target)) return;
  if (target.type === 'Identifier' && typeof target.name === 'string' && init !== undefined && init !== null) {
    bindings.push({ target: target.name, init });
    return;
  }
  if (target.type !== 'ObjectPattern' || !Array.isArray(target.properties)) return;
  // `const { createRequire } = require('module')` binds the factory locally.
  for (const property of target.properties as unknown[]) {
    if (!isRecord(property) || property.type !== 'ObjectProperty') continue;
    const key = isRecord(property.key) && typeof property.key.name === 'string' ? property.key.name : undefined;
    const value = isRecord(property.value) && typeof property.value.name === 'string' ? property.value.name : undefined;
    if (key === CREATE_REQUIRE && value) requireFactories.add(value);
  }
}

type InitKind = 'require' | 'dynamic' | 'factory' | undefined;

function classifyInit(
  init: unknown,
  requireLike: ReadonlySet<string>,
  dynamicLike: ReadonlySet<string>,
  requireFactories: ReadonlySet<string>,
): InitKind {
  if (!isRecord(init)) return undefined;
  const type = init.type;
  if (type === 'TSAsExpression' || type === 'TSNonNullExpression' || type === 'ParenthesizedExpression') {
    return classifyInit(init.expression, requireLike, dynamicLike, requireFactories);
  }
  if (type === 'Identifier' && typeof init.name === 'string') {
    if (init.name === 'require' || requireLike.has(init.name)) return 'require';
    if (init.name === 'eval' || init.name === 'Function' || dynamicLike.has(init.name)) return 'dynamic';
    if (requireFactories.has(init.name)) return 'factory';
    return undefined;
  }
  if (type === 'MemberExpression') {
    const property = memberPropertyName(init);
    if (property === undefined) return undefined;
    if (property === CREATE_REQUIRE) return 'factory';
    if (MODULE_LOAD_PROPERTIES.has(property)) return 'require';
    if (DYNAMIC_CODE_PROPERTIES.has(property)) return 'dynamic';
    return undefined;
  }
  if (type === 'CallExpression') {
    const callee = init.callee;
    if (!isRecord(callee)) return undefined;
    if (callee.type === 'Identifier' && typeof callee.name === 'string' && requireFactories.has(callee.name)) return 'require';
    if (callee.type === 'MemberExpression' && memberPropertyName(callee) === CREATE_REQUIRE) return 'require';
    return undefined;
  }
  return undefined;
}
