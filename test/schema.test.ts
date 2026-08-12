import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type AnySchema, type ErrorObject } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const safe = path.join(projectRoot, 'fixtures', 'safe-v1');
const risky = path.join(projectRoot, 'fixtures', 'risky-v2');

describe('public report schema', () => {
  it('accepts a real report and rejects incomplete snapshot and inventory files', async () => {
    const schema: unknown = JSON.parse(await readFile(path.join(projectRoot, 'schemas', 'report.schema.json'), 'utf8'));
    const validate = new Ajv2020({ strict: true, validateFormats: false }).compile(schema as AnySchema);
    const report = await audit(safe, risky, { offline: true });
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true);

    const missingSnapshotFields = structuredClone(report) as unknown as {
      before: { files: unknown[] };
      inventory: { added: unknown[]; modified: Array<{ before: unknown; after: unknown }> };
    };
    missingSnapshotFields.before.files[0] = {};
    expect(validate(missingSnapshotFields)).toBe(false);
    expect(validate.errors?.some((error: ErrorObject) => error.instancePath === '/before/files/0')).toBe(true);

    const missingInventoryFields = structuredClone(report) as unknown as {
      inventory: { added: unknown[]; modified: Array<{ before: unknown; after: unknown }> };
    };
    missingInventoryFields.inventory.added[0] = {};
    expect(validate(missingInventoryFields)).toBe(false);
    expect(validate.errors?.some((error: ErrorObject) => error.instancePath === '/inventory/added/0')).toBe(true);

    const missingModifiedFields = structuredClone(report) as unknown as {
      inventory: { modified: Array<{ before: unknown; after: unknown }> };
    };
    missingModifiedFields.inventory.modified[0]!.after = {};
    expect(validate(missingModifiedFields)).toBe(false);
    expect(validate.errors?.some((error: ErrorObject) => error.instancePath === '/inventory/modified/0/after')).toBe(true);
  });
});
