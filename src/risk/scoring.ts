import type { RiskLevel, Severity } from '../types.js';

/**
 * Bands for the 0-100 AI score, used only when the model returns no per-level probabilities.
 * The score is the 0-3 level scale rescaled, so the boundaries sit halfway between levels
 * (0, 33, 67, 100): a score maps to the nearest level.
 */
export const SCORE_BANDS: { level: RiskLevel; min: number; max: number }[] = [
  { level: 'low', min: 0, max: 16 },
  { level: 'medium', min: 17, max: 49 },
  { level: 'high', min: 50, max: 83 },
  { level: 'critical', min: 84, max: 100 },
];

/** An AI answer whose most likely level has less probability than this is "uncertain". */
export const UNCERTAIN_BELOW = 0.5;

export const LEVEL_RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function scoreToLevel(score: number): RiskLevel {
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new RangeError('risk score must be between 0 and 100');
  }
  if (score >= 84) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 17) return 'medium';
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
