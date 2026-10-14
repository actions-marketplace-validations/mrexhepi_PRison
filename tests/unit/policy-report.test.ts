import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, type Settings } from '../../src/config/schema.js';
import { evaluatePolicy, type PolicyInput } from '../../src/risk/policy.js';
import { scoreToLevel } from '../../src/risk/scoring.js';
import { makeFinding } from '../../src/scanners/finding.js';
import {
  buildAnnotations,
  checkConclusion,
  checkTitle,
  renderMarkdown,
  type ReportModel,
} from '../../src/reports/render.js';
import { code, md } from '../../src/reports/escape.js';
import type { AssessmentResult, ChangedFile, ContextCompleteness } from '../../src/types.js';

const settings = (over: Partial<Settings> = {}): Settings => ({
  ...DEFAULT_SETTINGS,
  dryRun: false,
  ...over,
});
const complete: ContextCompleteness = {
  totalFiles: 1,
  filesAnalyzed: 1,
  filesWithoutPatch: 0,
  sensitiveFilesExcluded: 0,
  diffLinesTotal: 1,
  diffLinesIncluded: 1,
  contextFilesIncluded: 0,
  contextFilesOmitted: 0,
  truncated: false,
  limitations: [],
};
const files: ChangedFile[] = [
  {
    path: 'src/a.ts',
    status: 'modified',
    additions: 1,
    deletions: 0,
    addedLines: [1],
    sensitive: false,
  },
];
const ai = (score: number, review = false): AssessmentResult => ({
  provider: 'subq',
  model: 'subq-snap-preview',
  riskLevel: scoreToLevel(score),
  riskScore: score,
  uncertain: false,
  confidence: 0.8,
  summary: 's',
  categories: [],
  findingJudgments: [],
  recommendedAction: 'r',
  requiresHumanReview: review,
  humanReviewProbability: review ? 0.9 : 0.1,
  latencyMs: 1,
});
const secret = makeFinding({
  source: 'subq-secret-detector',
  category: 'security',
  severity: 'critical',
  title: 'AWS key',
  description: 'd',
  file: 'src/a.ts',
  startLine: 1,
  status: 'confirmed',
  tags: ['secrets'],
});
const plausibleHigh = makeFinding({
  source: 'subq-rules',
  category: 'infrastructure',
  severity: 'high',
  title: 'Open ingress',
  description: 'd',
  file: 'src/a.ts',
  startLine: 1,
  tags: ['security_group_changes'],
});

function evalP(over: Partial<PolicyInput>) {
  return evaluatePolicy({
    settings: settings(),
    findings: [],
    files,
    completeness: complete,
    scannerStatuses: [],
    ai: { status: 'completed', result: ai(5) },
    ...over,
  });
}

describe('scoring bands', () => {
  it.each([
    [0, 'low'],
    [16, 'low'],
    [17, 'medium'],
    [49, 'medium'], // the 1.47/3 answer from the first live run is nearest to medium
    [50, 'high'],
    [83, 'high'],
    [84, 'critical'],
    [100, 'critical'],
  ])('%i -> %s', (s, l) => expect(scoreToLevel(s)).toBe(l));
  it('rejects invalid scores', () => {
    expect(() => scoreToLevel(101)).toThrow();
    expect(() => scoreToLevel(-1)).toThrow();
    expect(() => scoreToLevel(Number.NaN)).toThrow();
  });
});

describe('policy engine', () => {
  it('passes a low-risk change', () => {
    expect(evalP({})).toMatchObject({ decision: 'pass', effectiveLevel: 'low', fail: false });
  });

  it('a low AI score cannot downgrade a confirmed critical secret', () => {
    const o = evalP({ findings: [secret], ai: { status: 'completed', result: ai(0) } });
    expect(o).toMatchObject({
      decision: 'blocked',
      effectiveLevel: 'critical',
      aiLevel: 'low',
      fail: true,
    });
  });

  it('critical_findings_always_fail can be disabled but still requires review', () => {
    const o = evalP({
      settings: settings({ criticalFindingsAlwaysFail: false }),
      findings: [secret],
    });
    expect(o.decision).toBe('review_required');
    expect(o.fail).toBe(false);
  });

  it('AI can raise risk and require review', () => {
    const o = evalP({ ai: { status: 'completed', result: ai(55, true) } });
    expect(o).toMatchObject({ decision: 'review_required', effectiveLevel: 'high' });
  });

  it('fail-on threshold blocks', () => {
    const o = evalP({ settings: settings({ failOn: 'high' }), findings: [plausibleHigh] });
    expect(o).toMatchObject({ decision: 'blocked', fail: true });
  });

  it('dry-run suppresses risk failures but still reports blocked', () => {
    const o = evalP({
      settings: settings({ failOn: 'medium', dryRun: true }),
      findings: [plausibleHigh],
    });
    expect(o).toMatchObject({ decision: 'blocked', fail: false, dryRunSuppressed: true });
    expect(checkConclusion(o)).toBe('neutral');
  });

  it('protected paths and require_review_for tags require review', () => {
    const o = evalP({
      settings: settings({
        protectedPaths: ['src/**'],
        requireReviewFor: ['security_group_changes'],
        requireReview: [],
      }),
      findings: [plausibleHigh],
    });
    expect(o.decision).toBe('review_required');
    expect(o.protectedPathsTouched).toEqual(['src/a.ts']);
    expect(o.triggeredTags).toEqual(['security_group_changes']);
  });

  it.each([
    ['require-review', false, true],
    ['warn', false, false],
    ['fail', true, true],
  ] as const)('provider failure with policy %s', (policy, fail, review) => {
    const o = evalP({
      settings: settings({ providerErrorPolicy: policy }),
      ai: { status: 'failed', error: 'timeout' },
    });
    expect(o.decision).toBe('inconclusive');
    expect(o.fail).toBe(fail);
    if (policy !== 'fail') expect(o.requiresReview).toBe(review);
  });

  it('provider failure in dry-run with policy fail still fails (operational)', () => {
    const o = evalP({
      settings: settings({ providerErrorPolicy: 'fail', dryRun: true }),
      ai: { status: 'failed' },
    });
    expect(o.fail).toBe(true);
  });

  it('provider failure never yields pass, but deterministic blocks still block', () => {
    expect(evalP({ ai: { status: 'failed' } }).decision).toBe('inconclusive');
    expect(evalP({ ai: { status: 'failed' }, findings: [secret] }).decision).toBe('blocked');
  });

  it('missing required or invalid scanner artifacts require review', () => {
    const o = evalP({
      scannerStatuses: [{ name: 'Checkov report', status: 'missing', required: true, findings: 0 }],
    });
    expect(o.decision).toBe('review_required');
    expect(o.reasons.join()).toMatch(/not counted as passing/);
  });

  it('incomplete context is visible and optionally fails', () => {
    const inc = { ...complete, truncated: true };
    expect(evalP({ completeness: inc }).decision).toBe('review_required');
    const o = evalP({
      completeness: inc,
      settings: settings({ failOnIncompleteContext: true, dryRun: true }),
    });
    expect(o.fail).toBe(true);
  });

  it('an uncertain AI answer never raises the level', () => {
    const o = evalP({
      ai: {
        status: 'completed',
        result: { ...ai(55), uncertain: true, riskLevel: 'high', levelProbability: 0.4 },
      },
    });
    expect(o.effectiveLevel).toBe('low');
    expect(o.reasons.join()).toMatch(/uncertain \(most likely high at 40%\)/);
  });

  it('advisory mode: AI level, review flag and failures do not affect the decision', () => {
    const adv = settings({ aiMode: 'advisory', providerErrorPolicy: 'fail' });
    const raised = evalP({ settings: adv, ai: { status: 'completed', result: ai(90, true) } });
    expect(raised).toMatchObject({ decision: 'pass', effectiveLevel: 'low', go: true });
    const failed = evalP({ settings: adv, ai: { status: 'failed', error: 'timeout' } });
    expect(failed).toMatchObject({ decision: 'pass', fail: false, go: true });
    const det = evalP({ settings: adv, findings: [secret], ai: { status: 'failed' } });
    expect(det).toMatchObject({ decision: 'blocked', go: false });
  });

  it('go is true only for pass', () => {
    expect(evalP({}).go).toBe(true);
    expect(evalP({ ai: { status: 'completed', result: ai(55, true) } }).go).toBe(false);
    expect(evalP({ ai: { status: 'failed' } }).go).toBe(false);
  });

  it('insufficient-evidence findings do not raise the level', () => {
    const weak = makeFinding({
      source: 's',
      category: 'testing',
      severity: 'high',
      title: 't',
      description: '',
      status: 'insufficient_evidence',
    });
    expect(evalP({ findings: [weak] }).deterministicLevel).toBe('none');
  });
});

describe('report rendering', () => {
  const model = (over: Partial<ReportModel> = {}): ReportModel => ({
    outcome: evalP({ findings: [plausibleHigh] }),
    ai: { status: 'completed', result: ai(62), provider: 'subq' },
    findings: [plausibleHigh],
    scannerStatuses: [{ name: 'Built-in', status: 'completed', required: false, findings: 1 }],
    completeness: complete,
    includeAiExplanation: true,
    dryRun: false,
    outsideDiffFindings: 0,
    ...over,
  });

  it('renders the required sections', () => {
    const m = renderMarkdown(model());
    for (const s of [
      '## PR risk: ⚠️ NO GO (review required)',
      '**Why**',
      '- Effective risk high requires review by policy.',
      '| HIGH | Open ingress | `src/a.ts:1` |',
      'Risk: **HIGH** · Rules and scanners: HIGH (1 finding) · SubQ: HIGH',
      '<summary>Details</summary>',
      '**HIGH - Open ingress** in `src/a.ts:1`',
      'Files: 1/1; changed lines: 1/1',
      'Truncated: No.',
    ]) {
      expect(m).toContain(s);
    }
    // Decision first; details collapsed after the one-line risk summary.
    expect(m.indexOf('NO GO')).toBeLessThan(m.indexOf('**Why**'));
    expect(m.indexOf('Risk: **HIGH**')).toBeLessThan(m.indexOf('<details>'));
  });

  it('a GO report is short and keeps setting notes out of the reasons', () => {
    const m = renderMarkdown(
      model({
        outcome: evalP({ settings: settings({ aiMode: 'advisory' }) }),
        findings: [],
        aiMode: 'advisory',
      }),
    );
    expect(m).toMatch(/^## PR risk: ✅ GO\n/);
    expect(m).toContain('No blocking findings and no policy triggers.');
    expect(m).not.toContain('**Why**');
    expect(m).toMatch(/_ai\\_mode 'advisory'.*<\/details>/s);
  });

  it('shows the most likely level and the per-level probabilities, not a blended score', () => {
    const result: AssessmentResult = {
      ...ai(49),
      riskLevel: 'medium',
      levelProbabilities: { low: 0.1, medium: 0.45, high: 0.4, critical: 0.05 },
      levelProbability: 0.45,
      uncertain: true,
      confidence: 0.47,
    };
    const m = renderMarkdown(model({ ai: { status: 'completed', result, provider: 'subq' } }));
    expect(m).toContain('SubQ: MEDIUM (45%), uncertain');
    expect(m).toContain('| 10% | **45%** | 40% | 5% |');
    expect(m).toContain('treated as uncertain');
    expect(m).not.toMatch(/49\/100/);
    expect(checkTitle(model({ ai: { status: 'completed', result, provider: 'subq' } }))).toMatch(
      /^NO GO - REVIEW REQUIRED: .*AI MEDIUM \(45%\), uncertain/,
    );
  });

  it('labels mock provider output', () => {
    expect(
      renderMarkdown(model({ ai: { status: 'completed', result: ai(1), provider: 'mock' } })),
    ).toMatch(/MOCK provider/);
  });

  it('shows failed AI without a score', () => {
    const m = renderMarkdown(
      model({ ai: { status: 'failed', error: 'SubQ request timed out.', provider: 'subq' } }),
    );
    expect(m).toContain('SubQ: n/a (failed)');
    expect(m).toContain('Failed: SubQ request timed out');
  });

  it('escapes untrusted markdown, HTML, links and mentions', () => {
    expect(md('<img src=x onerror=alert(1)> [x](javascript:alert(1)) @org/team')).not.toMatch(
      /<img|\]\(|@org/,
    );
    expect(code('a`b\nc')).toBe("`a'b c`");
  });

  it('builds annotations only for diff-mapped lines and caps them', () => {
    const many = Array.from({ length: 80 }, (_, i) =>
      makeFinding({
        source: 's',
        category: 'security',
        severity: 'medium',
        title: `t${i}`,
        description: '',
        file: 'a.ts',
        startLine: i + 1,
      }),
    );
    const lines = new Map([['a.ts', new Set(Array.from({ length: 60 }, (_, i) => i + 1))]]);
    const a = buildAnnotations(
      [
        ...many,
        makeFinding({
          source: 's',
          category: 'security',
          severity: 'high',
          title: 'x',
          description: '',
          file: 'other.ts',
          startLine: 1,
        }),
      ],
      lines,
    );
    expect(a).toHaveLength(50);
    expect(a.every((x) => x.path === 'a.ts' && x.start_line <= 60)).toBe(true);
  });
});
