#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { audit } from './audit.js';
import { DEFAULT_LIMITS, VERSION } from './constants.js';
import { POLICY_TEMPLATE, writeBaseline } from './policy.js';
import { renderHtml, renderJson, renderMarkdown, renderSarif } from './reports.js';
import type { DiffReport, Severity } from './types.js';
import { errorMessage, UserError, writeTextFile } from './util.js';

interface CompareOptions {
  output: string;
  json?: string;
  markdown?: string;
  sarif?: string;
  stdout: 'summary' | 'json' | 'markdown' | 'sarif';
  offline: boolean;
  deterministic: boolean;
  ci: boolean;
  fail: boolean;
  failOn?: Severity | 'never';
  policy?: string;
  baseline?: string;
  writeBaseline?: string;
  registry: string;
  cacheDir: string;
  ignore: string[];
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
  maxArchiveBytes: number;
  maxCompressionRatio: number;
  timeout: number;
  quiet: boolean;
}

export async function runCli(argv = process.argv): Promise<number> {
  const program = new Command();
  program
    .name('depdiff')
    .description('See what an npm update can do now that it could not do before.')
    .version(VERSION)
    .showHelpAfterError()
    .configureOutput({ outputError: (value, write) => write(pc.red(value)) });

  addCompareOptions(program.command('compare')
    .description('Compare registry versions, tarballs, or directories without executing package code.')
    .argument('<before>', 'old package@version, .tgz, or directory')
    .argument('<after>', 'new package@version, .tgz, or directory'))
    .action(async (before: string, after: string, options: CompareOptions) => {
      process.exitCode = await compare(before, after, options);
    });

  addCompareOptions(program.command('demo')
    .description('Run the deterministic offline demo against bundled safe/risky fixtures.'))
    .action(async (options: CompareOptions) => {
      const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
      const fixtureRoot = path.resolve(moduleDirectory, '../fixtures');
      options.offline = true;
      options.deterministic = true;
      process.exitCode = await compare(path.join(fixtureRoot, 'safe-v1'), path.join(fixtureRoot, 'risky-v2'), options);
    });

  program.command('init')
    .description('Write a documented starter policy.')
    .argument('[file]', 'policy path', '.depdiff.yml')
    .option('-f, --force', 'overwrite an existing file', false)
    .action(async (file: string, options: { force: boolean }) => {
      const { access } = await import('node:fs/promises');
      if (!options.force) {
        try {
          await access(file);
          throw new UserError(`${file} already exists; pass --force to replace it.`);
        } catch (error) {
          if (error instanceof UserError) throw error;
        }
      }
      await writeTextFile(file, POLICY_TEMPLATE);
      process.stdout.write(`${pc.green('✓')} Wrote ${path.resolve(file)}\n`);
    });

  try {
    await program.parseAsync(argv);
    if (argv.length <= 2) program.outputHelp();
    return typeof process.exitCode === 'number' ? process.exitCode : 0;
  } catch (error) {
    if (error instanceof UserError) {
      process.stderr.write(`${pc.red('depdiff:')} ${error.message}\n`);
      return error.exitCode;
    }
    if (isCommanderExit(error)) return error.exitCode;
    process.stderr.write(`${pc.red('depdiff internal error:')} ${errorMessage(error)}\n`);
    if (process.env.DEBUG) process.stderr.write(`${error instanceof Error ? error.stack ?? '' : ''}\n`);
    return 3;
  }
}

function addCompareOptions(command: Command): Command {
  return command
    .option('-o, --output <file>', 'standalone HTML report', 'depdiff-report.html')
    .option('--json <file>', 'JSON report path')
    .option('--markdown <file>', 'Markdown report path')
    .option('--sarif <file>', 'SARIF 2.1.0 report path')
    .addOption(new Option('--stdout <format>', 'stdout format').choices(['summary', 'json', 'markdown', 'sarif']).default('summary'))
    .option('--offline', 'forbid all network access', false)
    .option('--deterministic', 'use SOURCE_DATE_EPOCH (or Unix epoch) for reproducible output', false)
    .option('--ci', 'emit GitHub annotations and default fail-on to high', false)
    .option('--no-fail', 'always exit zero after a completed audit')
    .addOption(new Option('--fail-on <severity>', 'override failure threshold').choices(['info', 'low', 'medium', 'high', 'critical', 'never']))
    .option('--policy <file>', 'YAML or JSON policy path')
    .option('--baseline <file>', 'accepted finding baseline JSON')
    .option('--write-baseline <file>', 'write current findings as a baseline')
    .option('--registry <url>', 'trusted npm registry origin', 'https://registry.npmjs.org/')
    .option('--cache-dir <path>', 'verified tarball cache', '.depdiff-cache')
    .option('--ignore <glob>', 'additional local-file ignore glob', collect, [])
    .option('--max-files <count>', 'maximum files/entries', integerOption, DEFAULT_LIMITS.maxFiles)
    .option('--max-total-bytes <bytes>', 'maximum unpacked bytes', integerOption, DEFAULT_LIMITS.maxTotalBytes)
    .option('--max-file-bytes <bytes>', 'maximum bytes in one file', integerOption, DEFAULT_LIMITS.maxFileBytes)
    .option('--max-archive-bytes <bytes>', 'maximum compressed tarball bytes', integerOption, DEFAULT_LIMITS.maxArchiveBytes)
    .option('--max-compression-ratio <ratio>', 'maximum expanded/compressed ratio', integerOption, DEFAULT_LIMITS.maxCompressionRatio)
    .option('--timeout <ms>', 'network timeout in milliseconds', integerOption, DEFAULT_LIMITS.timeoutMs)
    .option('-q, --quiet', 'suppress human summary and file notices', false);
}

async function compare(before: string, after: string, options: CompareOptions): Promise<number> {
  const report = await audit(before, after, {
    offline: options.offline,
    deterministic: options.deterministic,
    registry: options.registry,
    cacheDir: options.cacheDir,
    ignore: options.ignore,
    ...(options.policy ? { policyPath: options.policy } : {}),
    ...(options.baseline ? { baselinePath: options.baseline } : {}),
    ...(options.failOn !== undefined ? { failOn: options.failOn } : {}),
    ci: options.ci,
    limits: {
      maxFiles: options.maxFiles,
      maxTotalBytes: options.maxTotalBytes,
      maxFileBytes: options.maxFileBytes,
      maxArchiveBytes: options.maxArchiveBytes,
      maxCompressionRatio: options.maxCompressionRatio,
      timeoutMs: options.timeout,
    },
  });
  const outputs: Array<Promise<void>> = [];
  if (options.output) outputs.push(writeTextFile(options.output, renderHtml(report)));
  if (options.json) outputs.push(writeTextFile(options.json, renderJson(report)));
  if (options.markdown) outputs.push(writeTextFile(options.markdown, renderMarkdown(report)));
  if (options.sarif) outputs.push(writeTextFile(options.sarif, renderSarif(report)));
  if (options.writeBaseline) outputs.push(writeBaseline(options.writeBaseline, report));
  await Promise.all(outputs);

  if (options.ci) emitAnnotations(report);
  if (!options.quiet) {
    if (options.stdout === 'json') process.stdout.write(renderJson(report));
    else if (options.stdout === 'markdown') process.stdout.write(renderMarkdown(report));
    else if (options.stdout === 'sarif') process.stdout.write(renderSarif(report));
    else printSummary(report, options);
  }
  return !report.policy.passed && options.fail ? 1 : 0;
}

function printSummary(report: DiffReport, options: CompareOptions): void {
  const riskColor = report.risk.level === 'critical' || report.risk.level === 'high'
    ? pc.red : report.risk.level === 'medium' ? pc.yellow : pc.green;
  process.stdout.write(`\n${pc.bold('DE P DIFF')}  ${pc.dim('static update audit')}\n\n`);
  process.stdout.write(`  ${pc.bold(report.before.package.name)}  ${report.before.package.version} ${pc.dim('→')} ${report.after.package.version}\n`);
  process.stdout.write(`  Risk ${riskColor(pc.bold(`${report.risk.score}/100 ${report.risk.level.toUpperCase()}`))}  ·  ${report.risk.newFindings} new finding(s)\n`);
  process.stdout.write(`  Files ${pc.green(`+${report.inventory.added.length}`)} ${pc.red(`−${report.inventory.removed.length}`)} ${pc.yellow(`~${report.inventory.modified.length}`)}  ·  package code executed: ${pc.green('no')}\n\n`);
  for (const finding of report.findings.filter((item) => item.status === 'new').slice(0, 8)) {
    const color = finding.severity === 'critical' || finding.severity === 'high' ? pc.red : finding.severity === 'medium' ? pc.yellow : pc.cyan;
    process.stdout.write(`  ${color(finding.severity.toUpperCase().padEnd(8))} ${finding.title}${finding.evidence[0]?.file ? pc.dim(` · ${finding.evidence[0].file}`) : ''}\n`);
  }
  if (report.risk.newFindings > 8) process.stdout.write(pc.dim(`  … ${report.risk.newFindings - 8} more in the report\n`));
  process.stdout.write(`\n  Policy ${report.policy.passed ? pc.green(pc.bold('PASS')) : pc.red(pc.bold('FAIL'))}`);
  if (!report.policy.passed) process.stdout.write(pc.dim(` · ${report.policy.violations.map((violation) => violation.rule).join(', ')}`));
  process.stdout.write('\n');
  if (options.output) process.stdout.write(`  HTML   ${pc.cyan(path.resolve(options.output))}\n`);
  if (options.json) process.stdout.write(`  JSON   ${pc.cyan(path.resolve(options.json))}\n`);
  if (options.sarif) process.stdout.write(`  SARIF  ${pc.cyan(path.resolve(options.sarif))}\n`);
  process.stdout.write('\n');
}

function emitAnnotations(report: DiffReport): void {
  for (const finding of report.findings.filter((item) => item.status === 'new' && ['critical', 'high', 'medium'].includes(item.severity))) {
    const evidence = finding.evidence[0];
    const kind = finding.severity === 'medium' ? 'warning' : 'error';
    const metadata = [evidence?.file ? `file=${escapeWorkflow(evidence.file)}` : '', evidence?.line ? `line=${evidence.line}` : '', `title=${escapeWorkflow(`Depdiff ${finding.severity}`)}`].filter(Boolean).join(',');
    process.stdout.write(`::${kind} ${metadata}::${escapeWorkflow(`${finding.title} — ${finding.description}`)}\n`);
  }
}

function escapeWorkflow(value: string): string {
  return value.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A').replaceAll(':', '%3A').replaceAll(',', '%2C');
}

function integerOption(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new UserError(`Expected a positive integer, received: ${value}`);
  return parsed;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function isCommanderExit(error: unknown): error is { exitCode: number } {
  return Boolean(error && typeof error === 'object' && 'code' in error && String(error.code).startsWith('commander.') && 'exitCode' in error && typeof error.exitCode === 'number');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().then((code) => { process.exitCode = code; }).catch((error: unknown) => {
    process.stderr.write(`${pc.red('depdiff internal error:')} ${errorMessage(error)}\n`);
    process.exitCode = 3;
  });
}
