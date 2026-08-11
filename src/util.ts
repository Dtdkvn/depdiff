import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Severity } from './types.js';

export class UserError extends Error {
  readonly exitCode = 2;

  constructor(message: string) {
    super(message);
    this.name = 'UserError';
  }
}

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(sortValue(value), null, 2);
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, sortValue(child)]),
    );
  }
  return value;
}

export async function writeTextFile(
  filePath: string,
  content: string,
  options: { overwrite?: boolean } = {},
): Promise<void> {
  const destination = path.resolve(filePath);
  await mkdir(path.dirname(destination), { recursive: true });
  const temporary = path.join(path.dirname(destination), `.${path.basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, content, { encoding: 'utf8', flag: 'wx' });
    if (options.overwrite === false) {
      await link(temporary, destination);
      await rm(temporary, { force: true });
    } else {
      await rename(temporary, destination);
    }
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

export function severityRank(severity: Severity | 'never'): number {
  return severity === 'never'
    ? Number.POSITIVE_INFINITY
    : ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } satisfies Record<Severity, number>)[severity];
}

export function byteSize(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB'];
  let size = value / 1024;
  let unit = units[0] ?? 'KB';
  for (let index = 1; size >= 1024 && index < units.length; index += 1) {
    size /= 1024;
    unit = units[index] ?? unit;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${unit}`;
}

export function truncate(value: string, length = 180): string {
  const flattened = value.replace(/\s+/g, ' ').trim();
  return flattened.length <= length ? flattened : `${flattened.slice(0, length - 1)}…`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function asStringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
}

export function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
