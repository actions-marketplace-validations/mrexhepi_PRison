import { parse } from 'yaml';
import { ConfigError } from '../utils/errors.js';
import { repoConfigSchema, DEFAULT_SETTINGS, type RepoConfig, type Settings } from './schema.js';
import type { ActionInputs } from './inputs.js';

const MAX_CONFIG_BYTES = 64 * 1024;

/**
 * Parse repository configuration YAML. YAML is parsed as data only (no custom tags,
 * no code evaluation) and validated against a strict schema.
 */
export function parseRepoConfig(text: string, source: string): RepoConfig {
  if (Buffer.byteLength(text, 'utf8') > MAX_CONFIG_BYTES) {
    throw new ConfigError(`Configuration ${source} exceeds ${MAX_CONFIG_BYTES} bytes.`);
  }
  let data: unknown;
  try {
    data = parse(text, {
      schema: 'core',
      maxAliasCount: 50,
      prettyErrors: true,
      uniqueKeys: true,
      logLevel: 'error',
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message.split('\n')[0] : 'parse error';
    throw new ConfigError(`Configuration ${source} is not valid YAML: ${msg}`);
  }
  if (data === null || data === undefined) {
    throw new ConfigError(`Configuration ${source} is empty; expected at least 'version: 1'.`);
  }
  const result = repoConfigSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues
      .slice(0, 10)
      .map((i) => `  - ${i.path.length ? i.path.join('.') : '(root)'}: ${i.message}`)
      .join('\n');
    throw new ConfigError(`Configuration ${source} is invalid:\n${issues}`);
  }
  return result.data;
}

/**
 * Resolve effective settings. Precedence, highest first:
 *   1. Explicit Action inputs (`with:` in the workflow)
 *   2. Repository configuration file (read from the PR base commit)
 *   3. Built-in defaults
 * Mandatory safety behaviour (deterministic policy, redaction) is not configurable by
 * either source in a way the model output can influence.
 */
export function resolveSettings(inputs: ActionInputs, repo: RepoConfig | undefined): Settings {
  const d = DEFAULT_SETTINGS;
  const scanners = {
    secrets: repo?.scanners?.secrets ?? d.scanners.secrets,
    terraform: repo?.scanners?.terraform ?? d.scanners.terraform,
    sarif: repo?.scanners?.sarif ?? d.scanners.sarif,
    dependencies: repo?.scanners?.dependencies ?? d.scanners.dependencies,
  };
  const requiredScanners = repo?.scanners?.required ?? d.requiredScanners;
  for (const r of requiredScanners) {
    if (!scanners[r]) {
      throw new ConfigError(
        `Configuration lists scanner '${r}' as required but scanners.${r} is false.`,
      );
    }
  }
  return {
    mode: inputs.mode ?? repo?.mode ?? d.mode,
    failOn: inputs.failOn ?? repo?.risk?.fail_on ?? d.failOn,
    report: inputs.report ?? repo?.report?.destination ?? d.report,
    maxFiles: inputs.maxFiles ?? repo?.analysis?.max_files ?? d.maxFiles,
    maxDiffLines: inputs.maxDiffLines ?? repo?.analysis?.max_diff_lines ?? d.maxDiffLines,
    contextFiles: inputs.contextFiles ?? repo?.analysis?.context_files ?? d.contextFiles,
    maxContextTokens: repo?.analysis?.max_context_tokens ?? d.maxContextTokens,
    failOnIncompleteContext:
      repo?.analysis?.fail_on_incomplete_context ?? d.failOnIncompleteContext,
    requireReview: repo?.risk?.require_review ?? d.requireReview,
    protectedPaths: repo?.policies?.protected_paths ?? d.protectedPaths,
    requireReviewFor: repo?.policies?.require_review_for ?? d.requireReviewFor,
    criticalFindingsAlwaysFail:
      repo?.policies?.critical_findings_always_fail ?? d.criticalFindingsAlwaysFail,
    conventions: repo?.policies?.conventions ?? d.conventions,
    scanners,
    requiredScanners,
    includeFileAnnotations: repo?.report?.include_file_annotations ?? d.includeFileAnnotations,
    includeAiExplanation: repo?.report?.include_ai_explanation ?? d.includeAiExplanation,
    dryRun: inputs.dryRun,
    providerErrorPolicy: inputs.providerErrorPolicy ?? d.providerErrorPolicy,
  };
}
