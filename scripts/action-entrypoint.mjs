import { appendFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const before = required('INPUT_BEFORE');
const after = required('INPUT_AFTER');
const report = process.env.INPUT_REPORT || 'depdiff-report.html';
const sarif = process.env.INPUT_SARIF || 'depdiff-results.sarif';
const args = [
  '/app/dist/cli.js', 'compare', before, after, '--ci', '--output', report, '--sarif', sarif,
  '--fail-on', process.env.INPUT_FAIL_ON || 'high',
];
addOptional(args, '--policy', process.env.INPUT_POLICY);
addOptional(args, '--baseline', process.env.INPUT_BASELINE);
if ((process.env.INPUT_OFFLINE || '').toLowerCase() === 'true') args.push('--offline');

const exitCode = await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, args, { cwd: workspace, env: process.env, stdio: 'inherit' });
  child.once('error', reject);
  child.once('exit', (code, signal) => signal ? reject(new Error(`Depdiff terminated by ${signal}`)) : resolve(code ?? 3));
});

if (process.env.GITHUB_OUTPUT) {
  await appendFile(process.env.GITHUB_OUTPUT, `report=${path.resolve(workspace, report)}\nsarif=${path.resolve(workspace, sarif)}\nrisk_exit_code=${exitCode}\n`, 'utf8');
}
process.exitCode = exitCode;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required Action input: ${name.slice(6).toLowerCase()}`);
  return value;
}

function addOptional(target, flag, value) {
  if (value) target.push(flag, value);
}
