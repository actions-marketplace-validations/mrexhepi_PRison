import { ConfigError } from '../utils/errors.js';
import { MODES, type Mode } from '../types.js';
import {
  AI_MODES,
  FAIL_ON,
  PROVIDER_ERROR_POLICIES,
  REPORT_DESTINATIONS,
  type AiMode,
  type FailOn,
  type ProviderErrorPolicy,
  type ReportDestination,
} from './schema.js';

export const DEFAULT_CONFIG_PATH = '.github/subq-pr-risk.yml';
export const PROVIDERS = ['subq', 'mock'] as const;
export type ProviderName = (typeof PROVIDERS)[number];

/**
 * Raw Action inputs. Policy-related inputs are `undefined` when the workflow did not set
 * them, so repository configuration can fill them in (explicit inputs win).
 */
export interface ActionInputs {
  subqApiKey: string;
  githubToken: string;
  configPath: string;
  configPathExplicit: boolean;
  mode?: Mode;
  failOn?: FailOn;
  aiMode?: AiMode;
  report?: ReportDestination;
  maxFiles?: number;
  maxDiffLines?: number;
  contextFiles?: number;
  dryRun: boolean;
  providerErrorPolicy?: ProviderErrorPolicy;
  provider: ProviderName;
  timeoutSeconds: number;
  gitleaksReport?: string;
  checkovReport?: string;
  sarifFiles: string[];
  dependencyReport?: string;
}

export type InputReader = (name: string) => string;

function oneOf<T extends string>(name: string, raw: string, allowed: readonly T[]): T | undefined {
  const v = raw.trim().toLowerCase();
  if (v === '') return undefined;
  if (!(allowed as readonly string[]).includes(v)) {
    throw new ConfigError(
      `Invalid value for input '${name}': '${raw.trim().slice(0, 50)}'. Expected one of: ${allowed.join(', ')}.`,
    );
  }
  return v as T;
}

function int(name: string, raw: string, min: number, max: number): number | undefined {
  const v = raw.trim();
  if (v === '') return undefined;
  if (!/^\d+$/.test(v)) {
    throw new ConfigError(`Invalid value for input '${name}': expected a whole number.`);
  }
  const n = Number(v);
  if (n < min || n > max) {
    throw new ConfigError(`Invalid value for input '${name}': must be between ${min} and ${max}.`);
  }
  return n;
}

function bool(name: string, raw: string, fallback: boolean): boolean {
  const v = raw.trim().toLowerCase();
  if (v === '') return fallback;
  if (['true', 'yes', '1', 'on'].includes(v)) return true;
  if (['false', 'no', '0', 'off'].includes(v)) return false;
  throw new ConfigError(`Invalid value for input '${name}': expected true or false.`);
}

function optionalPath(raw: string): string | undefined {
  const v = raw.trim();
  return v === '' ? undefined : v;
}

export function parseInputs(read: InputReader): ActionInputs {
  const configRaw = read('config').trim();
  const configPath = configRaw === '' ? DEFAULT_CONFIG_PATH : configRaw;
  if (configPath.startsWith('/') || configPath.split(/[\\/]/).includes('..')) {
    throw new ConfigError(
      "Invalid value for input 'config': must be a repository-relative path without '..'.",
    );
  }

  return {
    subqApiKey: read('subq-api-key').trim(),
    githubToken: read('github-token').trim(),
    configPath,
    configPathExplicit: configRaw !== '' && configRaw !== DEFAULT_CONFIG_PATH,
    mode: oneOf('mode', read('mode'), MODES),
    failOn: oneOf('fail-on', read('fail-on'), FAIL_ON),
    aiMode: oneOf('ai-mode', read('ai-mode'), AI_MODES),
    report: oneOf('report', read('report'), REPORT_DESTINATIONS),
    maxFiles: int('max-files', read('max-files'), 1, 3000),
    maxDiffLines: int('max-diff-lines', read('max-diff-lines'), 1, 200_000),
    contextFiles: int('context-files', read('context-files'), 0, 100),
    dryRun: bool('dry-run', read('dry-run'), false),
    providerErrorPolicy: oneOf(
      'provider-error-policy',
      read('provider-error-policy'),
      PROVIDER_ERROR_POLICIES,
    ),
    provider: oneOf('provider', read('provider'), PROVIDERS) ?? 'subq',
    timeoutSeconds: int('timeout-seconds', read('timeout-seconds'), 5, 600) ?? 60,
    gitleaksReport: optionalPath(read('gitleaks-report')),
    checkovReport: optionalPath(read('checkov-report')),
    sarifFiles: read('sarif-files')
      .split(/\r?\n|,/)
      .map((s) => s.trim())
      .filter(Boolean),
    dependencyReport: optionalPath(read('dependency-report')),
  };
}
