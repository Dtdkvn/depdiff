import { existsSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export function spawnNpm(args, options = {}) {
  const configuredCli = process.env.npm_execpath;
  const bundledCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  const npmCli = configuredCli && existsSync(configuredCli)
    ? configuredCli
    : process.platform === 'win32' && existsSync(bundledCli)
      ? bundledCli
      : undefined;
  if (npmCli) return spawnSync(process.execPath, [npmCli, ...args], options);
  if (process.platform === 'win32') {
    throw new Error('Unable to locate npm-cli.js next to the active Node.js runtime.');
  }
  return spawnSync('npm', args, options);
}
