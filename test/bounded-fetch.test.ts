import { describe, expect, it, vi } from 'vitest';
import { fetchBounded } from '../src/bounded-fetch.js';

const url = new URL('https://registry.example/package/1.0.0');
const options = {
  expectedHost: 'registry.example',
  label: 'registry metadata',
  maximumBytes: 8,
  mediaTypes: ['application/json'],
  accept: 'application/json',
} as const;

describe('bounded benchmark fetch', () => {
  it('streams an allowed response with redirect following disabled', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response('{"ok":1}', {
      headers: { 'content-type': 'application/json', 'content-length': '8' },
    })));
    vi.stubGlobal('fetch', fetchMock);
    await expect(fetchBounded(url, options)).resolves.toEqual(Buffer.from('{"ok":1}'));
    expect(fetchMock).toHaveBeenCalledWith(url, expect.objectContaining({ redirect: 'error' }));
  });

  it('cancels a chunked body as soon as its running limit is exceeded', async () => {
    let cancelled = false;
    const chunks = [Buffer.alloc(8), Buffer.alloc(1)];
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks.shift();
        if (chunk) controller.enqueue(chunk);
      },
      cancel() { cancelled = true; },
    });
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(body, {
      headers: { 'content-type': 'application/json' },
    }))));
    await expect(fetchBounded(url, options)).rejects.toThrow(/8-byte limit/u);
    expect(cancelled).toBe(true);
  });

  it('rejects unexpected origins and media types', async () => {
    await expect(fetchBounded(new URL('https://evil.example/data'), options)).rejects.toThrow(/Untrusted/u);
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response('plain', {
      headers: { 'content-type': 'text/plain' },
    }))));
    await expect(fetchBounded(url, options)).rejects.toThrow(/unexpected content type/u);
  });
});
