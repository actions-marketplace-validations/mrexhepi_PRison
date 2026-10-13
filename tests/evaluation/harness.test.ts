import { describe, expect, it } from 'vitest';
import { MockDecisionProvider } from '../../src/subq/mock.js';
import { evaluate, loadCases } from './harness.js';

/**
 * Runs the labeled dataset with the deterministic mock provider. This measures the
 * deterministic layer (rules + policy) only; it says nothing about SubQ model quality.
 * Use `npm run eval -- --provider subq` with SUBQ_API_KEY to measure the real model.
 */
describe('evaluation dataset (deterministic layer, mock provider)', () => {
  it('covers low, high, ambiguous and incomplete cases', () => {
    const labels = new Set(loadCases().map((c) => c.label));
    expect([...labels].sort()).toEqual(['ambiguous', 'high', 'incomplete', 'low']);
  });

  it('never misses a labeled critical issue and agrees with expert decisions on clear cases', async () => {
    const cases = loadCases();
    const { results, metrics } = await evaluate(cases, () => new MockDecisionProvider());
    expect(metrics.falseNegativeRateCritical).toBe(0);
    expect(metrics.recallHigh).toBe(1);
    for (const r of results.filter((x) => x.label === 'low' || x.label === 'high')) {
      expect({ id: r.id, agrees: r.decisionAgrees }).toEqual({ id: r.id, agrees: true });
    }
    expect(results.find((r) => r.id === 'incomplete-large-pr')?.decisionAgrees).toBe(true);
  });
});
