import type { ScanLimits } from './types.js';

export const VERSION = '0.1.0';

export const DEFAULT_LIMITS: ScanLimits = {
  maxFiles: 25_000,
  maxTotalBytes: 512 * 1024 * 1024,
  maxFileBytes: 32 * 1024 * 1024,
  maxArchiveBytes: 128 * 1024 * 1024,
  maxTextBytes: 2 * 1024 * 1024,
  maxCompressionRatio: 100,
  timeoutMs: 30_000,
};

export const DEFAULT_IGNORES = [
  '**/.git/**',
  '**/node_modules/**',
  '**/.depdiff-cache/**',
  '**/.depdiff-demo/**',
];

export const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
] as const;
