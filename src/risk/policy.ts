import picomatch from 'picomatch';
import type { Settings } from '../config/schema.js';
import type {
  AssessmentResult,
  AssessmentStatus,
  ChangedFile,
  ContextCompleteness,
  FinalDecision,
  PolicyTag,
  RiskLevel,
  ScannerFinding,
  ScannerStatus,
} from '../types.js';
import { LEVEL_RANK, maxLevel, severityToLevel } from './scoring.js';

export interface PolicyInput {
  settings: Settings;
  findings: ScannerFinding[];
  files: ChangedFile[];
  completeness: ContextCompleteness;
  scannerStatuses: ScannerStatus[];
  ai: { status: AssessmentStatus; result?: AssessmentResult; error?: string };
}

export interface PolicyOutcome {
  decision: FinalDecision;
  /** Max of AI level and deterministic level; never lower than the deterministic level. */
  effectiveLevel: RiskLevel;
  deterministicLevel: RiskLevel | 'none';
  aiLevel?: RiskLevel;
  aiScore?: number;
  reasons: string[];
  requiresReview: boolean;
  protectedPathsTouched: string[];
  triggeredTags: PolicyTag[];
  /** Whether the workflow step should fail, and why. */
  fail: boolean;
  failReason?: string;
  /** True when a risk-based failure was suppressed by dry-run. */
  dryRunSuppressed: boolean;
  /** GO / NO GO: true only when the decision is pass. */
  go: boolean;
}

/**
 * Deterministic policy engine. In ai_mode 'decide' the model can raise the effective risk
 * level and request review, but nothing it returns can lower a deterministic finding, change
 * thresholds or turn a failed assessment into a pass. An uncertain answer (no level reached
 * UNCERTAIN_BELOW) never raises the level. In ai_mode 'advisory' the model is reported only
 * and the decision comes from rules, scanners and policy alone.
 */
export function evaluatePolicy(input: PolicyInput): PolicyOutcome {
  const { settings, findings, completeness, ai } = input;
  const reasons: string[] = [];

  const counted = findings.filter((f) => f.status !== 'insufficient_evidence');
  const detLevels = counted
    .map((f) => severityToLevel(f.severity))
    .filter((l): l is RiskLevel => !!l);
  const deterministicLevel: RiskLevel | 'none' = detLevels.length ? maxLevel(...detLevels) : 'none';

  const aiResult = ai.status === 'completed' ? ai.result : undefined;
  const advisory = settings.aiMode === 'advisory';
  const aiRaises = !advisory && aiResult !== undefined && !aiResult.uncertain;
  const effectiveLevel = maxLevel(
    deterministicLevel === 'none' ? undefined : deterministicLevel,
    aiRaises ? aiResult.riskLevel : undefined,
  );
  if (advisory) {
    reasons.push(
      "ai_mode 'advisory': SubQ Snap is reported only and does not affect the decision.",
    );
  } else if (aiResult?.uncertain) {
    reasons.push(
      `SubQ Snap's answer was uncertain (most likely ${aiResult.riskLevel} at ${Math.round((aiResult.levelProbability ?? 0) * 100)}%), so it was not used to raise risk.`,
    );
  }

  const confirmedCritical = findings.filter(
    (f) => f.status === 'confirmed' && f.severity === 'critical',
  );
  const matchers = settings.protectedPaths.map((g) => picomatch(g, { dot: true }));
  const protectedPathsTouched = input.files
    .flatMap((f) => [f.path, ...(f.previousPath ? [f.previousPath] : [])])
    .filter((p) => matchers.some((m) => m(p)));
  const allTags = new Set(counted.flatMap((f) => f.tags));
  const triggeredTags = settings.requireReviewFor.filter((t) => allTags.has(t));

  let blocked = false;
  if (confirmedCritical.length > 0 && settings.criticalFindingsAlwaysFail) {
    blocked = true;
    reasons.push(
      `${confirmedCritical.length} confirmed critical finding(s); critical_findings_always_fail is enabled.`,
    );
  }
  if (settings.failOn !== 'never' && LEVEL_RANK[effectiveLevel] >= LEVEL_RANK[settings.failOn]) {
    blocked = true;
    reasons.push(`Effective risk ${effectiveLevel} meets fail-on threshold '${settings.failOn}'.`);
  }

  let review = false;
  if (settings.requireReview.includes(effectiveLevel)) {
    review = true;
    reasons.push(`Effective risk ${effectiveLevel} requires review by policy.`);
  }
  if (protectedPathsTouched.length > 0) {
    review = true;
    reasons.push(
      `Protected paths changed: ${[...new Set(protectedPathsTouched)].slice(0, 5).join(', ')}.`,
    );
  }
  if (triggeredTags.length > 0) {
    review = true;
    reasons.push(`Policy requires review for: ${triggeredTags.join(', ')}.`);
  }
  if (!advisory && aiResult?.requiresHumanReview) {
    review = true;
    reasons.push('SubQ Snap indicated that close human review is needed.');
  }
  const scannerProblems = input.scannerStatuses.filter(
    (s) => s.status === 'invalid' || (s.required && s.status !== 'completed'),
  );
  if (scannerProblems.length > 0) {
    review = true;
    reasons.push(
      `Scanner results unavailable or invalid: ${scannerProblems.map((s) => `${s.name} (${s.status})`).join(', ')}. They are not counted as passing checks.`,
    );
  }
  if (completeness.truncated) {
    review = true;
    reasons.push('Analysis was incomplete (diff or context truncated); see limitations.');
  }

  let decision: FinalDecision;
  let fail = false;
  let failReason: string | undefined;
  let dryRunSuppressed = false;

  if (advisory && (ai.status === 'failed' || ai.status === 'skipped')) {
    reasons.push(
      `AI assessment ${ai.status}${ai.error ? `: ${ai.error}` : ''} (advisory; no effect).`,
    );
    decision = blocked ? 'blocked' : review ? 'review_required' : 'pass';
  } else if (ai.status === 'failed' || ai.status === 'skipped') {
    const what = ai.status === 'skipped' ? 'skipped' : 'failed';
    reasons.push(`AI assessment ${what}${ai.error ? `: ${ai.error}` : ''}.`);
    if (settings.providerErrorPolicy === 'require-review') {
      review = true;
      reasons.push("provider-error-policy 'require-review': human review required.");
    }
    if (settings.providerErrorPolicy === 'fail') {
      fail = true;
      failReason = `AI assessment ${what} and provider-error-policy is 'fail'.`;
    }
    // Deterministic blocking evidence still blocks; otherwise the outcome is unknown.
    decision = blocked ? 'blocked' : 'inconclusive';
  } else {
    decision = blocked ? 'blocked' : review ? 'review_required' : 'pass';
  }

  if (decision === 'blocked') {
    if (settings.dryRun) {
      dryRunSuppressed = true;
      reasons.push('dry-run is enabled: blocking decision reported but not enforced.');
    } else if (!fail) {
      fail = true;
      failReason = 'Pull request blocked by risk policy.';
    }
  }

  if (completeness.truncated && settings.failOnIncompleteContext) {
    fail = true;
    failReason =
      failReason ?? 'Analysis context was incomplete and fail_on_incomplete_context is enabled.';
  }

  return {
    decision,
    effectiveLevel,
    deterministicLevel,
    ...(aiResult ? { aiLevel: aiResult.riskLevel, aiScore: aiResult.riskScore } : {}),
    reasons,
    requiresReview: review || decision === 'blocked',
    protectedPathsTouched: [...new Set(protectedPathsTouched)],
    triggeredTags,
    fail,
    ...(failReason ? { failReason } : {}),
    dryRunSuppressed,
    go: decision === 'pass',
  };
}
