import { realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export function spawnNpm(args, options = {}) {
  const npmCli = bundledNpmCli();
  const safeOptions = { ...options, shell: false };
  if (npmCli) return spawnSync(process.execPath, [npmCli, ...args], safeOptions);
  if (process.platform === 'win32') {
    throw new Error('Unable to locate npm-cli.js next to the active Node.js runtime.');
  }
  return spawnSync('npm', args, safeOptions);
}

function bundledNpmCli() {
  const candidate = path.resolve(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  try {
    const canonical = realpathSync.native(candidate);
    return statSync(canonical).isFile() ? canonical : undefined;
  } catch {
    return undefined;
  }
}
