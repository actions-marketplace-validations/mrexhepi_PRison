import type { RiskLevel, Severity } from '../types.js';

/**
 * Initial reporting bands for the 0-100 AI score. These are defaults for presentation,
 * not statistically calibrated incident probabilities.
 */
export const SCORE_BANDS: { level: RiskLevel; min: number; max: number }[] = [
  { level: 'low', min: 0, max: 19 },
  { level: 'medium', min: 20, max: 39 },
  { level: 'high', min: 40, max: 69 },
  { level: 'critical', min: 70, max: 100 },
];

export const LEVEL_RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function scoreToLevel(score: number): RiskLevel {
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new RangeError('risk score must be between 0 and 100');
  }
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

export function severityToLevel(s: Severity): RiskLevel | undefined {
  switch (s) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return undefined;
  }
}

export function maxLevel(...levels: (RiskLevel | undefined)[]): RiskLevel {
  return levels.reduce<RiskLevel>(
    (m, l) => (l !== undefined && LEVEL_RANK[l] > LEVEL_RANK[m] ? l : m),
    'low',
  );
}
