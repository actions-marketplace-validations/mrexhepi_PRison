import { z } from 'zod';
import { POLICY_TAGS, SEVERITIES, type ScannerFinding, type Severity } from '../types.js';
import { redactSecrets } from '../utils/redact.js';
import { sha256, truncate } from '../utils/text.js';

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/** Runtime schema for normalized findings; every scanner output is validated with it. */
export const scannerFindingSchema = z.object({
  id: z.string().min(1).max(200),
  source: z.string().min(1).max(100),
  category: z.string().min(1).max(100),
  severity: z.enum(SEVERITIES),
  title: z.string().min(1).max(500),
  description: z.string().max(4000),
  file: z.string().max(4096).optional(),
  startLine: z.int().positive().optional(),
  endLine: z.int().positive().optional(),
  ruleId: z.string().max(300).optional(),
  evidence: z.string().max(1000).optional(),
  fingerprint: z.string().max(200).optional(),
  status: z.enum(['confirmed', 'plausible', 'insufficient_evidence']),
  tags: z.array(z.enum(POLICY_TAGS)),
  sources: z.array(z.string()),
  verified: z.boolean().optional(),
});

export interface FindingInit extends Omit<
  ScannerFinding,
  'id' | 'fingerprint' | 'sources' | 'tags' | 'status'
> {
  tags?: ScannerFinding['tags'];
  status?: ScannerFinding['status'];
}

/** Create a normalized finding. Strings are redacted and length-bounded. */
export function makeFinding(init: FindingInit): ScannerFinding {
  const file = init.file?.replace(/^\.\//, '');
  const fingerprint = sha256(
    [
      init.category,
      file ?? '',
      init.startLine ?? '',
      (init.ruleId ?? init.title).toLowerCase(),
    ].join('|'),
  ).slice(0, 24);
  const finding: ScannerFinding = {
    ...init,
    ...(file !== undefined ? { file } : {}),
    title: truncate(redactSecrets(init.title), 300),
    description: truncate(redactSecrets(init.description), 2000),
    ...(init.evidence !== undefined
      ? { evidence: truncate(redactSecrets(init.evidence.trim()), 300) }
      : {}),
    id: `${init.source}-${fingerprint.slice(0, 12)}`,
    fingerprint,
    status: init.status ?? 'plausible',
    tags: init.tags ?? [],
    sources: [init.source],
  };
  return scannerFindingSchema.parse(finding) as ScannerFinding;
}

/**
 * Deduplicate findings. Identical fingerprints merge; findings from different sources at
 * the same file/line/category merge too. The highest severity and strongest evidence
 * status win, and every source reference is preserved.
 */
export function dedupeFindings(findings: ScannerFinding[]): ScannerFinding[] {
  const statusRank = { insufficient_evidence: 0, plausible: 1, confirmed: 2 } as const;
  const byKey = new Map<string, ScannerFinding>();
  for (const f of findings) {
    const key =
      f.file && f.startLine
        ? `${f.category}|${f.file}|${f.startLine}|${(f.ruleId ?? f.title).toLowerCase()}`
        : `fp|${f.fingerprint ?? f.id}`;
    const crossKey = f.file && f.startLine ? `${f.category}|${f.file}|${f.startLine}` : undefined;
    const existing =
      byKey.get(key) ??
      (crossKey
        ? [...byKey.values()].find(
            (e) => e.source !== f.source && `${e.category}|${e.file}|${e.startLine}` === crossKey,
          )
        : undefined);
    if (!existing) {
      byKey.set(key, { ...f, sources: [...f.sources] });
      continue;
    }
    existing.sources = [...new Set([...existing.sources, ...f.sources])];
    existing.tags = [...new Set([...existing.tags, ...f.tags])];
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity]) {
      existing.severity = f.severity;
      existing.title = f.title;
      existing.description = f.description;
    }
    if (statusRank[f.status] > statusRank[existing.status]) existing.status = f.status;
    if (f.verified) existing.verified = true;
  }
  return [...byKey.values()].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.startLine ?? 0) - (b.startLine ?? 0),
  );
}
