import { createHash } from 'node:crypto';

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function truncate(text: string, max: number, marker = '…'): string {
  if (text.length <= max) return text;
  return text.slice(0, Math.max(0, max - marker.length)) + marker;
}

/** Rough token estimate. Conservative (over-estimates) so we stay under the context limit. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 3);
}
