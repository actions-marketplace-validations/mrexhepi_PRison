/**
 * Evaluate the scanner against the labeled dataset in tests/fixtures/eval/cases.json.
 *
 *   npm run eval                       # deterministic layer with the mock provider
 *   SUBQ_API_KEY=... npm run eval -- --provider subq   # real SubQ Snap calls (costs credits)
 *
 * Results are written to eval-results/<timestamp>.json. Labels reflect expert judgment
 * on synthetic fixtures; treat metrics as a regression signal, not a security claim.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { MockDecisionProvider } from '../src/subq/mock.js';
import { SubQClient } from '../src/subq/client.js';
import { SubQDecisionProvider } from '../src/subq/provider.js';
import type { DecisionProvider } from '../src/types.js';
import { evaluate, loadCases } from '../tests/evaluation/harness.js';

const providerArg = process.argv.includes('--provider')
  ? process.argv[process.argv.indexOf('--provider') + 1]
  : 'mock';

let factory: () => DecisionProvider;
if (providerArg === 'subq') {
  const apiKey = process.env.SUBQ_API_KEY;
  if (!apiKey) {
    console.error('SUBQ_API_KEY is not set.');
    process.exit(1);
  }
  factory = () => new SubQDecisionProvider(new SubQClient({ apiKey, timeoutMs: 60_000 }));
} else if (providerArg === 'mock') {
  factory = () => new MockDecisionProvider();
} else {
  console.error(`Unknown provider '${providerArg}'. Use mock or subq.`);
  process.exit(1);
}

const { results, metrics } = await evaluate(loadCases(), factory);
const pct = (v: number | null) => (v === null ? 'n/a' : `${(v * 100).toFixed(1)}%`);

console.log(`Provider: ${providerArg}`);
console.table(
  results.map((r) => ({
    case: r.id,
    label: r.label,
    decision: r.decision,
    agrees: r.decisionAgrees,
    expectedHigh: r.expectedHigh,
    predictedHigh: r.predictedHigh,
    ai: r.aiStatus,
    ms: Math.round(r.latencyMs),
  })),
);
console.log(`Precision (high risk):          ${pct(metrics.precisionHigh)}`);
console.log(`Recall (high risk):             ${pct(metrics.recallHigh)}`);
console.log(`False-positive rate:            ${pct(metrics.falsePositiveRate)}`);
console.log(`False-negative rate (critical): ${pct(metrics.falseNegativeRateCritical)}`);
console.log(`Agreement with expert decision: ${pct(metrics.decisionAgreement)}`);
console.log(`Average latency:                ${metrics.averageLatencyMs.toFixed(0)} ms`);
console.log(`Average API cost per PR:        $${metrics.averageCostUsd.toFixed(5)}`);
console.log(`Inconclusive assessments:       ${pct(metrics.inconclusiveRate)}`);

mkdirSync('eval-results', { recursive: true });
const out = `eval-results/${providerArg}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
writeFileSync(out, JSON.stringify({ provider: providerArg, metrics, results }, null, 2));
console.log(`Wrote ${out}`);
