import { randomUUID } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

class ActionInputError extends Error {}

await main().catch((error) => {
  const inputError = error instanceof ActionInputError;
  process.stderr.write(`depdiff Action ${inputError ? 'input' : 'internal'} error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = inputError ? 2 : 3;
});

async function main() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const [beforeInput, afterInput, policy, baseline, failOn, reportInput, sarifInput, offlineInput] = process.argv.slice(2);
  const before = required('before', beforeInput);
  const after = required('after', afterInput);
  const report = singleLine(reportInput || 'depdiff-report.html', 'report');
  const sarif = singleLine(sarifInput || 'depdiff-results.sarif', 'sarif');
  const args = [
    '/app/dist/cli.js', 'compare', before, after, '--ci', '--output', report, '--sarif', sarif,
  ];
  addOptional(args, '--policy', policy);
  addOptional(args, '--baseline', baseline);
  addOptional(args, '--fail-on', failOn);
  if ((offlineInput || '').toLowerCase() === 'true') args.push('--offline');

  const exitCode = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd: workspace, env: process.env, stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code, signal) => signal ? reject(new Error(`Depdiff terminated by ${signal}`)) : resolve(code ?? 3));
  });

  if (process.env.GITHUB_OUTPUT) {
    const delimiter = `depdiff_${randomUUID()}`;
    await appendFile(process.env.GITHUB_OUTPUT, [
      `report<<${delimiter}`, path.resolve(workspace, report), delimiter,
      `sarif<<${delimiter}`, path.resolve(workspace, sarif), delimiter,
      `risk_exit_code=${exitCode}`,
      '',
    ].join('\n'), 'utf8');
  }
  process.exitCode = exitCode;
}

function required(name, value) {
  if (!value) throw new ActionInputError(`Missing required Action input: ${name}`);
  return value;
}

function addOptional(target, flag, value) {
  if (value) target.push(flag, value);
}

function singleLine(value, name) {
  if (/[\r\n\0]/.test(value)) throw new ActionInputError(`Action input ${name} must be a single path line.`);
  return value;
}
