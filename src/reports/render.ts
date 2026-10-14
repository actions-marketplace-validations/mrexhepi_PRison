import type { AiMode } from '../config/schema.js';
import type { PolicyOutcome } from '../risk/policy.js';
import { SEVERITY_RANK } from '../scanners/finding.js';
import {
  RISK_LEVELS,
  type AssessmentResult,
  type AssessmentStatus,
  type ContextCompleteness,
  type FinalDecision,
  type ScannerFinding,
  type ScannerStatus,
} from '../types.js';
import { code, md, plain } from './escape.js';
import type { CheckAnnotation, CheckConclusion } from '../github/api.js';

export const REPORT_TITLE = 'SubQ PR Risk Assessment';
export const COMMENT_MARKER = '<!-- subq-pr-risk-scanner:report -->';
const MAX_SUMMARY_CHARS = 60_000;
const MAX_FINDINGS_RENDERED = 25;
const MAX_ANNOTATIONS = 50;

export interface ReportModel {
  outcome: PolicyOutcome;
  ai: { status: AssessmentStatus; result?: AssessmentResult; error?: string; provider: string };
  findings: ScannerFinding[];
  scannerStatuses: ScannerStatus[];
  completeness: ContextCompleteness;
  includeAiExplanation: boolean;
  dryRun: boolean;
  /** Defaults to 'decide'. */
  aiMode?: AiMode;
  outsideDiffFindings: number;
  runUrl?: string;
}

const DECISION_LABEL: Record<FinalDecision, string> = {
  pass: 'PASS',
  review_required: 'REVIEW REQUIRED',
  blocked: 'BLOCKED',
  inconclusive: 'INCONCLUSIVE',
};

const STATUS_LABEL: Record<ScannerFinding['status'], string> = {
  confirmed: 'Confirmed',
  plausible: 'Plausible risk',
  insufficient_evidence: 'Insufficient evidence',
};

const NEXT_STEP: Record<string, string> = {
  secrets: 'Remove the credential from the change and rotate it; assume it is compromised.',
  iam_changes:
    'Confirm the permissions follow least privilege and are scoped to specific resources.',
  security_group_changes:
    'Verify effective ingress/egress rules against the approved network design.',
  public_exposure: 'Confirm public exposure is intended and approved.',
  destructive_infrastructure_changes:
    'Review the Terraform plan for destroy/replace actions before applying.',
  database_migrations: 'Verify the migration is backward compatible and has a rollback plan.',
  encryption_changes: 'Confirm encryption remains enabled with the approved keys.',
  tls_changes: 'Keep certificate verification and modern TLS versions enabled.',
  workflow_changes: 'Have a maintainer review workflow permissions, triggers and secret usage.',
  auth_changes: 'Request review from an owner of the authentication/authorization code.',
  prompt_injection: 'Treat the flagged text as untrusted; verify the PR on its merits.',
};

export function aiStatusText(m: ReportModel['ai']): string {
  if (m.status === 'completed') {
    return m.provider === 'mock'
      ? 'Completed with MOCK provider (not a real AI assessment)'
      : `Completed (${m.result?.model ?? 'SubQ'})`;
  }
  if (m.status === 'not_required') return `Not required${m.error ? `: ${m.error}` : ''}`;
  return m.status === 'skipped'
    ? `Skipped${m.error ? `: ${m.error}` : ''}`
    : `Failed${m.error ? `: ${m.error}` : ''}`;
}

export function checkConclusion(outcome: PolicyOutcome): CheckConclusion {
  if (outcome.fail) return 'failure';
  switch (outcome.decision) {
    case 'pass':
      return 'success';
    case 'blocked':
      // Only reached under dry-run: reported, not enforced.
      return 'neutral';
    default:
      return 'neutral';
  }
}

const HEADLINE: Record<FinalDecision, string> = {
  pass: '✅ GO',
  review_required: '⚠️ NO GO (review required)',
  blocked: '⛔ NO GO (blocked)',
  inconclusive: '❔ NO GO (inconclusive: SubQ result unavailable)',
};

/** Reasons that describe configuration rather than this PR; shown in the footer instead. */
const isSettingNote = (reason: string) =>
  reason.startsWith("ai_mode 'advisory'") || reason.startsWith('dry-run is enabled');

/** Inline code that is also safe inside a table cell. */
const cell = (text: string, max = 120) => code(text, max).replace(/\|/g, '\\|');

function findingDetail(f: ScannerFinding): string {
  const parts = [
    `**${f.severity.toUpperCase()} - ${md(f.title, 200)}**${f.file ? ` in ${code(f.file + (f.startLine ? `:${f.startLine}` : ''))}` : ''}`,
  ];
  if (f.description) parts.push(md(f.description, 400));
  const step = f.tags.map((t) => NEXT_STEP[t]).find(Boolean);
  if (step) parts.push(`Next: ${step}`);
  if (f.evidence) parts.push(`Evidence: ${code(f.evidence, 200)}`);
  parts.push(
    `${STATUS_LABEL[f.status]}${f.verified ? ' (verified by scanner)' : ''}; source: ${f.sources.map((x) => md(x, 60)).join(', ')}.`,
  );
  return `- ${parts.join('<br>')}`;
}

/**
 * Compact report: the decision and why first, one table row per finding, and everything
 * else (explanations, the SubQ answer, scanners, completeness) in a collapsed section.
 */
export function renderMarkdown(m: ReportModel): string {
  const o = m.outcome;
  const r = m.ai.status === 'completed' ? m.ai.result : undefined;
  const judgments = new Map(r?.findingJudgments.map((j) => [j.findingId, j.probability]) ?? []);
  const sorted = [...m.findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );
  const shown = sorted.slice(0, MAX_FINDINGS_RENDERED);
  const out: string[] = [];

  out.push(
    `## PR risk: ${HEADLINE[o.decision]}${m.dryRun && !o.go ? ', dry-run: not enforced' : ''}`,
    '',
  );
  if (m.ai.provider === 'mock') {
    out.push('> [!WARNING]', '> MOCK provider in use. This is not a real SubQ assessment.', '');
  }

  const why = o.reasons.filter((x) => !isSettingNote(x));
  if (why.length) {
    out.push('**Why**', '');
    for (const reason of why) out.push(`- ${md(reason, 300)}`);
    out.push('');
  } else if (o.go) {
    out.push('No blocking findings and no policy triggers.', '');
  }

  if (shown.length) {
    const withAi = shown.some((f) => judgments.has(f.id));
    out.push(
      `| Severity | Finding | File${withAi ? ' | SubQ: real risk?' : ''} |`,
      `| --- | --- | ---${withAi ? ' | ---' : ''} |`,
    );
    for (const f of shown) {
      const file = f.file ? cell(f.file + (f.startLine ? `:${f.startLine}` : '')) : '';
      const j = judgments.get(f.id);
      out.push(
        `| ${f.severity.toUpperCase()} | ${md(f.title, 120)} | ${file}${withAi ? ` | ${j === undefined ? '' : pct(j)}` : ''} |`,
      );
    }
    if (sorted.length > shown.length) {
      out.push('', `_${sorted.length - shown.length} lower-severity finding(s) not shown._`);
    }
    out.push('');
  } else {
    out.push('No findings in the changed files.', '');
  }

  const det =
    o.deterministicLevel === 'none'
      ? 'none'
      : `${o.deterministicLevel.toUpperCase()} (${m.findings.length} finding${m.findings.length === 1 ? '' : 's'})`;
  const subq = r
    ? `${aiVerdict(r, m.aiMode)}`
    : m.ai.status === 'not_required'
      ? 'not needed'
      : `n/a (${m.ai.status})`;
  out.push(
    `Risk: **${o.effectiveLevel.toUpperCase()}** · Rules and scanners: ${det} · SubQ: ${subq}`,
    '',
  );

  // ---- Details (collapsed)
  out.push('<details>', '<summary>Details</summary>', '');
  if (shown.length) {
    out.push('**Findings**', '');
    for (const f of shown) out.push(findingDetail(f));
    out.push('');
  }
  if (r) {
    out.push('**SubQ Snap**', '');
    if (r.levelProbabilities) {
      const p = r.levelProbabilities;
      out.push(
        '| Low | Medium | High | Critical |',
        '| --- | --- | --- | --- |',
        `| ${RISK_LEVELS.map((l) => (l === r.riskLevel ? `**${pct(p[l])}**` : pct(p[l]))).join(' | ')} |`,
        '',
      );
    }
    const notes = [
      `Confidence ${pct(r.confidence)}${r.uncertain ? ' (no level reached 50%, treated as uncertain)' : ''}.`,
      `Close human review needed: ${pct(r.humanReviewProbability)}.`,
    ];
    if (m.includeAiExplanation && r.categories.length) {
      notes.push(
        `Category risk: ${r.categories.map((c) => `${c.category} ${pct(c.probability)}`).join(', ')}.`,
      );
    }
    notes.push(`Suggested next step: ${md(r.recommendedAction, 200)}.`);
    if (r.usage) {
      notes.push(
        `${r.usage.inputTokens.toLocaleString('en-US')} input tokens (about $${r.usage.estimatedCostUsd.toFixed(4)}).`,
      );
    }
    for (const n of notes) out.push(`- ${n}`);
    out.push('');
  } else {
    out.push(`**SubQ Snap:** ${md(aiStatusText(m.ai), 300)}`, '');
  }

  out.push('**Scanners**', '', '| Scanner | Status | Findings |', '| --- | --- | --- |');
  for (const s of m.scannerStatuses) {
    out.push(
      `| ${md(s.name, 80)}${s.required ? ' (required)' : ''} | ${s.status}${s.detail ? `: ${md(s.detail, 150)}` : ''} | ${s.findings} |`,
    );
  }
  out.push('');
  if (m.outsideDiffFindings > 0) {
    out.push(
      `${m.outsideDiffFindings} scanner finding(s) in files this PR does not change are not counted.`,
      '',
    );
  }

  const c = m.completeness;
  out.push(
    '**Coverage**',
    '',
    `- Files: ${c.filesAnalyzed}/${c.totalFiles}; changed lines: ${c.diffLinesIncluded}/${c.diffLinesTotal}; context files: ${c.contextFilesIncluded}${c.contextFilesOmitted ? ` (${c.contextFilesOmitted} omitted)` : ''}; sensitive files kept from AI: ${c.sensitiveFilesExcluded}.`,
    `- Truncated: ${c.truncated ? 'Yes' : 'No'}.`,
  );
  for (const l of c.limitations.slice(0, 20)) out.push(`- ${md(l, 300)}`);
  out.push('');
  const settingNotes = o.reasons.filter(isSettingNote).map((x) => md(x, 200));
  out.push(
    `_${[...settingNotes, 'SubQ probabilities are model judgments, not measured incident rates; the model can raise but never lower risk from rules and scanners.'].join(' ')}_`,
    '',
    '</details>',
  );
  if (m.runUrl) out.push('', `[Workflow run](${encodeURI(m.runUrl)})`);

  let text = out.join('\n');
  if (text.length > MAX_SUMMARY_CHARS) {
    text = text.slice(0, MAX_SUMMARY_CHARS - 100) + '\n\n_Report truncated to fit GitHub limits._';
  }
  return text;
}

const pct = (n: number) => `${Math.round(n * 100)}%`;

/** One-line AI verdict: the most likely level and its probability, never a blended score. */
export function aiVerdict(r: AssessmentResult, aiMode: AiMode = 'decide'): string {
  const level = r.riskLevel.toUpperCase();
  const base = r.levelProbability !== undefined ? `${level} (${pct(r.levelProbability)})` : level;
  const notes = [
    ...(r.uncertain ? ['uncertain'] : []),
    ...(aiMode === 'advisory' ? ['advisory'] : []),
  ];
  return notes.length ? `${base}, ${notes.join(', ')}` : base;
}

export function checkTitle(m: ReportModel): string {
  const o = m.outcome;
  const ai =
    m.ai.status === 'completed' && m.ai.result
      ? `, AI ${aiVerdict(m.ai.result, m.aiMode)}`
      : ', AI n/a';
  const go = o.go ? 'GO' : 'NO GO';
  return `${go} - ${DECISION_LABEL[o.decision]}: ${o.effectiveLevel} risk${ai}${m.dryRun ? ' (dry-run)' : ''}`;
}

/** Build check annotations only for lines that are verifiably part of the PR diff. */
export function buildAnnotations(
  findings: ScannerFinding[],
  annotatableLines: Map<string, Set<number>>,
): CheckAnnotation[] {
  const out: CheckAnnotation[] = [];
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );
  for (const f of sorted) {
    if (out.length >= MAX_ANNOTATIONS) break;
    if (!f.file || !f.startLine) continue;
    const lines = annotatableLines.get(f.file);
    if (!lines || !lines.has(f.startLine)) continue;
    const end =
      f.endLine && f.endLine >= f.startLine && lines.has(f.endLine) ? f.endLine : f.startLine;
    out.push({
      path: f.file,
      start_line: f.startLine,
      end_line: end,
      annotation_level:
        SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high
          ? 'failure'
          : f.severity === 'medium'
            ? 'warning'
            : 'notice',
      title: plain(`${f.severity.toUpperCase()}: ${f.title}`, 250),
      message: plain(
        `${f.description} [${STATUS_LABEL[f.status]}; source: ${f.sources.join(', ')}]`,
        2000,
      ),
    });
  }
  return out;
}
