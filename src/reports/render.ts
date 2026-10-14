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

function findingBlock(f: ScannerFinding, judgment: number | undefined): string {
  const lines = [`### ${f.severity.toUpperCase()} - ${md(f.title, 200)}`, ''];
  if (f.file) lines.push(`- File: ${code(f.file + (f.startLine ? `:${f.startLine}` : ''))}`);
  lines.push(
    `- Evidence status: ${STATUS_LABEL[f.status]}${f.verified ? ' (verified by scanner)' : ''}`,
  );
  lines.push(`- Source: ${f.sources.map((s) => md(s, 60)).join(', ')}`);
  if (f.evidence) lines.push(`- Evidence: ${code(f.evidence, 200)}`);
  if (f.description) lines.push(`- Impact: ${md(f.description, 400)}`);
  if (judgment !== undefined) {
    lines.push(
      `- SubQ Snap: ${Math.round(judgment * 100)}% probability this is a real risk in context`,
    );
  }
  const step = f.tags.map((t) => NEXT_STEP[t]).find(Boolean);
  if (step) lines.push(`- Recommended action: ${step}`);
  return lines.join('\n');
}

export function renderMarkdown(m: ReportModel): string {
  const o = m.outcome;
  const r = m.ai.status === 'completed' ? m.ai.result : undefined;
  const judgments = new Map(r?.findingJudgments.map((j) => [j.findingId, j.probability]) ?? []);
  const out: string[] = [];

  out.push(`# ${REPORT_TITLE}`, '');
  if (m.ai.provider === 'mock') {
    out.push('> [!WARNING]', '> MOCK provider in use. This is not a real SubQ assessment.', '');
  }
  const effectiveNote = r
    ? ''
    : m.ai.status === 'not_required'
      ? ' (deterministic only; AI assessment not required)'
      : ' (deterministic findings only; AI assessment unavailable)';
  out.push(`**Effective risk:** ${o.effectiveLevel.toUpperCase()}${effectiveNote}  `);
  out.push(`**AI verdict:** ${r ? aiVerdict(r, m.aiMode) : 'n/a'}  `);
  out.push(
    `**Deterministic findings:** ${m.findings.length}${o.deterministicLevel !== 'none' ? ` (highest: ${o.deterministicLevel})` : ''}  `,
  );
  out.push(
    `**Decision:** ${DECISION_LABEL[o.decision]}${m.dryRun ? ' (dry-run: not enforced)' : ''}`,
    '',
  );

  out.push('## Summary', '');
  if (r && m.includeAiExplanation) out.push(md(r.summary, 1000), '');
  if (r) out.push(`Recommended next step: ${md(r.recommendedAction, 200)}`, '');
  if (o.reasons.length) {
    out.push('Policy evaluation:', '');
    for (const reason of o.reasons) out.push(`- ${md(reason, 400)}`);
    out.push('');
  }
  if (!r && o.reasons.length === 0) out.push('No AI assessment and no policy triggers.', '');

  out.push('## Findings', '');
  if (m.findings.length === 0) {
    out.push('No deterministic findings in the changed files.', '');
  } else {
    const sorted = [...m.findings].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    );
    for (const f of sorted.slice(0, MAX_FINDINGS_RENDERED))
      out.push(findingBlock(f, judgments.get(f.id)), '');
    if (sorted.length > MAX_FINDINGS_RENDERED) {
      out.push(
        `_${sorted.length - MAX_FINDINGS_RENDERED} lower-severity finding(s) not shown._`,
        '',
      );
    }
  }

  if (r?.levelProbabilities) {
    const p = r.levelProbabilities;
    out.push(
      '## SubQ Snap overall answer',
      '',
      '| Low | Medium | High | Critical |',
      '| --- | --- | --- | --- |',
      `| ${RISK_LEVELS.map((l) => (l === r.riskLevel ? `**${pct(p[l])}**` : pct(p[l]))).join(' | ')} |`,
      '',
      `SubQ confidence: ${pct(r.confidence)}.${r.uncertain ? ' No level reached 50%, so the answer is treated as uncertain.' : ''}`,
      '',
    );
  }

  if (r && m.includeAiExplanation && r.categories.length) {
    out.push(
      '## AI category assessment',
      '',
      '| Category | Probability of material risk |',
      '| --- | --- |',
    );
    for (const c of r.categories)
      out.push(`| ${c.category} | ${Math.round(c.probability * 100)}% |`);
    out.push('');
  }

  const c = m.completeness;
  out.push('## Analysis completeness', '');
  out.push(`- Changed files analyzed: ${c.filesAnalyzed}/${c.totalFiles}`);
  out.push(`- Changed lines included: ${c.diffLinesIncluded}/${c.diffLinesTotal}`);
  out.push(
    `- Repository context files: ${c.contextFilesIncluded} included, ${c.contextFilesOmitted} omitted`,
  );
  out.push(`- Sensitive files excluded from AI context: ${c.sensitiveFilesExcluded}`);
  out.push(`- Context truncated: ${c.truncated ? 'Yes' : 'No'}`);
  out.push(`- AI assessment: ${md(aiStatusText(m.ai), 300)}`);
  if (r?.usage) {
    out.push(
      `- SubQ input tokens: ${r.usage.inputTokens} (estimated cost $${r.usage.estimatedCostUsd.toFixed(4)})`,
    );
  }
  out.push('');
  out.push('| Scanner | Status | Findings |', '| --- | --- | --- |');
  for (const s of m.scannerStatuses) {
    out.push(
      `| ${md(s.name, 80)}${s.required ? ' (required)' : ''} | ${s.status}${s.detail ? `: ${md(s.detail, 150)}` : ''} | ${s.findings} |`,
    );
  }
  out.push('');
  if (m.outsideDiffFindings > 0) {
    out.push(
      `- ${m.outsideDiffFindings} upstream scanner finding(s) outside the changed files were not included.`,
    );
  }
  if (c.limitations.length) {
    out.push('', '### Limitations', '');
    for (const l of c.limitations.slice(0, 20)) out.push(`- ${md(l, 300)}`);
  }
  out.push(
    '',
    '---',
    '_AI probabilities are SubQ Snap judgments, not calibrated incident rates. Findings come from deterministic rules and scanners; the model can raise but never lower deterministic risk, and uncertain or advisory answers never raise it._',
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
