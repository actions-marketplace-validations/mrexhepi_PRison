import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RawPullRequestFile } from '../../src/github/api.js';
import { run } from '../../src/main.js';
import type { DecisionProvider, FinalDecision } from '../../src/types.js';
import { DEFAULT_INPUTS, FakeGitHub, deps, fakeCore, rawPr } from '../helpers.js';

export interface EvalCase {
  id: string;
  label: 'low' | 'high' | 'ambiguous' | 'incomplete';
  title: string;
  maxFiles?: number;
  files: RawPullRequestFile[];
  expected: { highRisk: boolean; critical: boolean; decisions: FinalDecision[] };
}

export interface CaseResult {
  id: string;
  label: EvalCase['label'];
  expectedHigh: boolean;
  predictedHigh: boolean;
  expectedCritical: boolean;
  predictedCritical: boolean;
  decision: FinalDecision | 'error';
  decisionAgrees: boolean;
  aiStatus: string;
  latencyMs: number;
  costUsd: number;
}

export interface EvalMetrics {
  cases: number;
  precisionHigh: number | null;
  recallHigh: number | null;
  falsePositiveRate: number | null;
  falseNegativeRateCritical: number | null;
  decisionAgreement: number;
  averageLatencyMs: number;
  averageCostUsd: number;
  inconclusiveRate: number;
}

export function loadCases(): EvalCase[] {
  const path = join(import.meta.dirname, '..', 'fixtures', 'eval', 'cases.json');
  return (JSON.parse(readFileSync(path, 'utf8')) as { cases: EvalCase[] }).cases;
}

export async function evaluate(
  cases: EvalCase[],
  provider: () => DecisionProvider,
): Promise<{ results: CaseResult[]; metrics: EvalMetrics }> {
  const results: CaseResult[] = [];
  for (const c of cases) {
    const gh = new FakeGitHub(rawPr({ title: c.title, changed_files: c.files.length }), c.files);
    const core = fakeCore({
      ...DEFAULT_INPUTS,
      ...(c.maxFiles ? { 'max-files': String(c.maxFiles) } : {}),
    });
    const started = Date.now();
    const r = await run(deps(gh, core, provider()));
    const latencyMs = r.ai?.result?.latencyMs ?? Date.now() - started;
    const level = r.outcome?.effectiveLevel;
    const decision = r.outcome?.decision ?? 'error';
    results.push({
      id: c.id,
      label: c.label,
      expectedHigh: c.expected.highRisk,
      predictedHigh: level === 'high' || level === 'critical',
      expectedCritical: c.expected.critical,
      predictedCritical: level === 'critical' && decision === 'blocked',
      decision,
      decisionAgrees: decision !== 'error' && c.expected.decisions.includes(decision),
      aiStatus: r.ai?.status ?? 'none',
      latencyMs,
      costUsd: r.ai?.result?.usage?.estimatedCostUsd ?? 0,
    });
  }
  return { results, metrics: metrics(results) };
}

const ratio = (n: number, d: number) => (d === 0 ? null : n / d);

export function metrics(results: CaseResult[]): EvalMetrics {
  const tp = results.filter((r) => r.expectedHigh && r.predictedHigh).length;
  const fp = results.filter((r) => !r.expectedHigh && r.predictedHigh).length;
  const fn = results.filter((r) => r.expectedHigh && !r.predictedHigh).length;
  const tn = results.filter((r) => !r.expectedHigh && !r.predictedHigh).length;
  const critical = results.filter((r) => r.expectedCritical);
  const n = results.length || 1;
  return {
    cases: results.length,
    precisionHigh: ratio(tp, tp + fp),
    recallHigh: ratio(tp, tp + fn),
    falsePositiveRate: ratio(fp, fp + tn),
    falseNegativeRateCritical: ratio(
      critical.filter((r) => !r.predictedCritical).length,
      critical.length,
    ),
    decisionAgreement: results.filter((r) => r.decisionAgrees).length / n,
    averageLatencyMs: results.reduce((s, r) => s + r.latencyMs, 0) / n,
    averageCostUsd: results.reduce((s, r) => s + r.costUsd, 0) / n,
    inconclusiveRate: results.filter((r) => r.decision === 'inconclusive').length / n,
  };
}
