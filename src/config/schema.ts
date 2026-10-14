import { z } from 'zod';
import { MODES, POLICY_TAGS, RISK_LEVELS } from '../types.js';

export const FAIL_ON = ['never', 'medium', 'high', 'critical'] as const;
export type FailOn = (typeof FAIL_ON)[number];

export const REPORT_DESTINATIONS = ['check', 'comment', 'both'] as const;
export type ReportDestination = (typeof REPORT_DESTINATIONS)[number];

export const AI_MODES = ['decide', 'advisory'] as const;
export type AiMode = (typeof AI_MODES)[number];

export const PROVIDER_ERROR_POLICIES = ['fail', 'warn', 'require-review'] as const;
export type ProviderErrorPolicy = (typeof PROVIDER_ERROR_POLICIES)[number];

export const SCANNER_NAMES = ['secrets', 'terraform', 'sarif', 'dependencies'] as const;
export type ScannerName = (typeof SCANNER_NAMES)[number];

const globPattern = z
  .string()
  .min(1)
  .max(500)
  .refine((g) => !g.includes('\0'), 'must not contain NUL bytes');

/**
 * Schema for `.github/subq-pr-risk.yml`. Strict: unknown keys are rejected so a typo
 * never silently disables a policy.
 */
export const repoConfigSchema = z.strictObject({
  version: z.literal(1),
  mode: z.enum(MODES).optional(),
  analysis: z
    .strictObject({
      max_files: z.int().min(1).max(3000).optional(),
      max_diff_lines: z.int().min(1).max(200_000).optional(),
      context_files: z.int().min(0).max(100).optional(),
      max_context_tokens: z.int().min(10_000).max(350_000).optional(),
      fail_on_incomplete_context: z.boolean().optional(),
    })
    .optional(),
  risk: z
    .strictObject({
      fail_on: z.enum(FAIL_ON).optional(),
      require_review: z.array(z.enum(RISK_LEVELS)).max(4).optional(),
      ai_mode: z.enum(AI_MODES).optional(),
    })
    .optional(),
  policies: z
    .strictObject({
      protected_paths: z.array(globPattern).max(200).optional(),
      require_review_for: z.array(z.enum(POLICY_TAGS)).optional(),
      critical_findings_always_fail: z.boolean().optional(),
      conventions: z.array(z.string().min(1).max(500)).max(30).optional(),
    })
    .optional(),
  scanners: z
    .strictObject({
      secrets: z.boolean().optional(),
      terraform: z.boolean().optional(),
      sarif: z.boolean().optional(),
      dependencies: z.boolean().optional(),
      required: z.array(z.enum(SCANNER_NAMES)).optional(),
    })
    .optional(),
  report: z
    .strictObject({
      destination: z.enum(REPORT_DESTINATIONS).optional(),
      include_file_annotations: z.boolean().optional(),
      include_ai_explanation: z.boolean().optional(),
    })
    .optional(),
});

export type RepoConfig = z.infer<typeof repoConfigSchema>;

/** Fully resolved settings used by the rest of the application. */
export interface Settings {
  mode: (typeof MODES)[number];
  failOn: FailOn;
  /** decide: the AI can raise risk and request review. advisory: the AI is reported only. */
  aiMode: AiMode;
  report: ReportDestination;
  maxFiles: number;
  maxDiffLines: number;
  contextFiles: number;
  maxContextTokens: number;
  failOnIncompleteContext: boolean;
  requireReview: (typeof RISK_LEVELS)[number][];
  protectedPaths: string[];
  requireReviewFor: (typeof POLICY_TAGS)[number][];
  criticalFindingsAlwaysFail: boolean;
  conventions: string[];
  scanners: Record<ScannerName, boolean>;
  requiredScanners: ScannerName[];
  includeFileAnnotations: boolean;
  includeAiExplanation: boolean;
  dryRun: boolean;
  providerErrorPolicy: ProviderErrorPolicy;
}

export const DEFAULT_SETTINGS: Omit<Settings, 'dryRun'> = {
  mode: 'general',
  failOn: 'never',
  aiMode: 'decide',
  report: 'check',
  maxFiles: 200,
  maxDiffLines: 12_000,
  contextFiles: 10,
  maxContextTokens: 250_000,
  failOnIncompleteContext: false,
  requireReview: ['critical', 'high'],
  protectedPaths: ['.github/workflows/**'],
  requireReviewFor: [],
  criticalFindingsAlwaysFail: true,
  conventions: [],
  scanners: { secrets: true, terraform: true, sarif: true, dependencies: true },
  requiredScanners: [],
  includeFileAnnotations: true,
  includeAiExplanation: true,
  providerErrorPolicy: 'require-review',
};
