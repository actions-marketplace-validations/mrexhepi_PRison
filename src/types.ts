/**
 * Internal application contracts. These are NOT claims about the SubQ API
 * wire format; see src/subq/api.ts for the verified Decisions API schema.
 */

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const MODES = ['general', 'terraform', 'security', 'dependencies'] as const;
export type Mode = (typeof MODES)[number];

export const RISK_CATEGORIES = [
  'security',
  'infrastructure',
  'reliability',
  'compatibility',
  'testing',
] as const;
export type RiskCategory = (typeof RISK_CATEGORIES)[number];

/** Named policy triggers that `policies.require_review_for` can reference. */
export const POLICY_TAGS = [
  'iam_changes',
  'security_group_changes',
  'database_migrations',
  'destructive_infrastructure_changes',
  'public_exposure',
  'encryption_changes',
  'tls_changes',
  'auth_changes',
  'secrets',
  'workflow_changes',
  'dependency_changes',
  'production_infrastructure',
  'reliability_settings',
  'missing_tests',
  'prompt_injection',
] as const;
export type PolicyTag = (typeof POLICY_TAGS)[number];

/**
 * How strongly the evidence supports a finding.
 * - confirmed: a deterministic detector matched concrete evidence with high precision
 *   (for example a private key block), or an upstream scanner marked it verified.
 * - plausible: a heuristic or scanner signal that warrants review but may be benign.
 * - insufficient_evidence: the signal exists but context was missing to judge it.
 */
export type EvidenceStatus = 'confirmed' | 'plausible' | 'insufficient_evidence';

export interface ScannerFinding {
  id: string;
  source: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  ruleId?: string;
  evidence?: string;
  fingerprint?: string;
  /** Evidence status as determined by the producing scanner, never by the model. */
  status: EvidenceStatus;
  /** Policy tags this finding triggers. */
  tags: PolicyTag[];
  /** All sources that reported this finding after deduplication. */
  sources: string[];
  /** Upstream scanner verification flag, preserved verbatim when present. */
  verified?: boolean;
}

export type FileStatus =
  'added' | 'removed' | 'modified' | 'renamed' | 'copied' | 'changed' | 'unchanged';

export interface ChangedFile {
  path: string;
  previousPath?: string;
  status: FileStatus;
  additions: number;
  deletions: number;
  /** Redacted unified diff patch, if GitHub returned one and it was within budget. */
  patch?: string;
  /** Why the patch is not available or was not sent. */
  patchOmittedReason?:
    'binary_or_too_large' | 'sensitive_file' | 'diff_budget_exceeded' | 'file_limit_exceeded';
  /** Line numbers (in the head version) added by this PR, parsed from the patch. */
  addedLines: number[];
  sensitive: boolean;
}

export interface PullRequestMetadata {
  owner: string;
  repo: string;
  number: number;
  title: string;
  body: string;
  author: string;
  labels: string[];
  baseRef: string;
  baseSha: string;
  headRef: string;
  headSha: string;
  headRepoFullName: string;
  isFork: boolean;
  draft: boolean;
  changedFilesCount: number;
  additions: number;
  deletions: number;
}

export interface ContextFile {
  path: string;
  reason: string;
  content: string;
  truncated: boolean;
}

export interface RepositoryContext {
  files: ContextFile[];
  omitted: { path: string; reason: string }[];
  treeTruncated: boolean;
}

export interface ContextCompleteness {
  totalFiles: number;
  filesAnalyzed: number;
  filesWithoutPatch: number;
  sensitiveFilesExcluded: number;
  diffLinesTotal: number;
  diffLinesIncluded: number;
  contextFilesIncluded: number;
  contextFilesOmitted: number;
  truncated: boolean;
  limitations: string[];
}

export interface RiskPolicySummary {
  mode: Mode;
  protectedPaths: string[];
  requireReviewFor: PolicyTag[];
  conventions: string[];
}

export interface AssessmentInput {
  pullRequest: PullRequestMetadata;
  changedFiles: ChangedFile[];
  repositoryContext: RepositoryContext;
  scannerFindings: ScannerFinding[];
  policy: RiskPolicySummary;
  contextCompleteness: ContextCompleteness;
}

/** Model judgment about one deterministic finding. */
export interface FindingJudgment {
  findingId: string;
  /** Probability (0-1) that the finding is a real risk, as returned by the model. */
  probability: number;
}

export interface CategoryJudgment {
  category: RiskCategory;
  probability: number;
}

export interface AssessmentResult {
  provider: string;
  model: string;
  riskLevel: RiskLevel;
  /** 0-100, derived from the model's probability-weighted score answer. */
  riskScore: number;
  confidence: number;
  summary: string;
  categories: CategoryJudgment[];
  findingJudgments: FindingJudgment[];
  recommendedAction: string;
  requiresHumanReview: boolean;
  humanReviewProbability: number;
  usage?: { inputTokens: number; estimatedCostUsd: number };
  latencyMs: number;
}

export interface DecisionProvider {
  readonly name: string;
  assess(input: AssessmentInput): Promise<AssessmentResult>;
}

export type FinalDecision = 'pass' | 'review_required' | 'blocked' | 'inconclusive';

/**
 * completed: the model returned a valid assessment.
 * not_required: no model call was needed (e.g. documentation-only change); deterministic only.
 * skipped: the model could not be called (e.g. secrets unavailable to a forked PR).
 * failed: the model call failed or returned an invalid response.
 */
export type AssessmentStatus = 'completed' | 'not_required' | 'failed' | 'skipped';

export interface ScannerStatus {
  name: string;
  status: 'completed' | 'not_configured' | 'missing' | 'invalid' | 'disabled';
  required: boolean;
  findings: number;
  detail?: string;
}
