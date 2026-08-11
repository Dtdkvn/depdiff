import { readFile } from 'node:fs/promises';

export async function greet(name) {
  const banner = await readFile('./banner.txt', 'utf8');
  return `${banner}: Hello, ${name}!`;
}
