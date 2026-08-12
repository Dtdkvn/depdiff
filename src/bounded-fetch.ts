export interface BoundedFetchOptions {
  expectedHost: string;
  label: string;
  maximumBytes: number;
  mediaTypes: readonly string[];
  accept: string;
  timeoutMs?: number;
}

/** Fetches a trusted HTTPS resource without redirects or unbounded buffering. */
export async function fetchBounded(url: URL, options: BoundedFetchOptions): Promise<Buffer> {
  if (url.protocol !== 'https:' || url.host !== options.expectedHost) {
    throw new Error(`Untrusted ${options.label} URL: ${url.origin}`);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const response = await fetch(url, {
      redirect: 'error',
      signal: controller.signal,
      headers: { accept: options.accept, 'user-agent': 'depdiff-precision/0.1.0' },
    });
    if (response.redirected || (response.url && response.url !== url.href)) {
      throw new Error(`${options.label} redirected away from its pinned URL.`);
    }
    if (!response.ok || !response.body) {
      throw new Error(`${options.label} returned HTTP ${response.status}.`);
    }
    const mediaType = (response.headers.get('content-type') ?? '').split(';', 1)[0]!.trim().toLowerCase();
    if (!options.mediaTypes.includes(mediaType)) {
      throw new Error(`${options.label} returned unexpected content type ${mediaType || '(missing)'}.`);
    }
    const contentLength = response.headers.get('content-length');
    if (contentLength !== null && !/^\d+$/u.test(contentLength)) {
      throw new Error(`${options.label} returned an invalid Content-Length.`);
    }
    const declared = contentLength === null ? 0 : Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared > options.maximumBytes) {
      throw new Error(`${options.label} exceeds the ${options.maximumBytes}-byte limit.`);
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > options.maximumBytes) {
        await reader.cancel('bounded fetch limit exceeded');
        throw new Error(`${options.label} exceeds the ${options.maximumBytes}-byte limit.`);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks, received);
  } catch (error) {
    if (controller.signal.aborted) throw new Error(`${options.label} timed out.`);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
