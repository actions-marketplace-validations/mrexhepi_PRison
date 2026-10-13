import { z } from 'zod';
import type { PolicyTag, ScannerFinding, Severity } from '../types.js';
import { makeFinding } from './finding.js';

const MAX_FINDINGS_PER_ARTIFACT = 500;

function cleanPath(p: string | undefined): string | undefined {
  if (!p) return undefined;
  let out = p.replace(/^file:\/\//, '').replace(/\\/g, '/');
  const ws = process.env.GITHUB_WORKSPACE?.replace(/\\/g, '/');
  if (ws && out.startsWith(ws + '/')) out = out.slice(ws.length + 1);
  out = out.replace(/^\.?\//, '');
  if (out.split('/').includes('..') || out.includes('\0')) return undefined;
  return out;
}

function positive(n: unknown): number | undefined {
  return typeof n === 'number' && Number.isInteger(n) && n > 0 ? n : undefined;
}

// ---------------------------------------------------------------- Gitleaks
const gitleaksSchema = z.array(
  z
    .object({
      RuleID: z.string().optional(),
      Description: z.string().optional(),
      File: z.string().optional(),
      StartLine: z.number().optional(),
      EndLine: z.number().optional(),
      Fingerprint: z.string().optional(),
    })
    .loose(),
);

/**
 * Parse a Gitleaks JSON report (`gitleaks detect --report-format json`). The `Secret` and
 * `Match` fields are deliberately ignored so secret values never reach reports or the model.
 * Gitleaks does not verify secrets, so findings stay `plausible`.
 */
export function parseGitleaks(data: unknown): ScannerFinding[] {
  const parsed = gitleaksSchema.safeParse(data);
  if (!parsed.success) throw new Error('Gitleaks report must be a JSON array of findings.');
  return parsed.data.slice(0, MAX_FINDINGS_PER_ARTIFACT).map((r) =>
    makeFinding({
      source: 'gitleaks',
      category: 'security',
      severity: 'critical',
      title: `Secret detected: ${r.Description || r.RuleID || 'unknown rule'}`,
      description: 'Gitleaks reported a potential secret. The value is not reproduced here.',
      ...(cleanPath(r.File) ? { file: cleanPath(r.File) } : {}),
      ...(positive(r.StartLine) ? { startLine: positive(r.StartLine) } : {}),
      ...(positive(r.EndLine) ? { endLine: positive(r.EndLine) } : {}),
      ...(r.RuleID ? { ruleId: r.RuleID } : {}),
      tags: ['secrets'],
      status: 'plausible',
    }),
  );
}

// ---------------------------------------------------------------- Checkov
const checkovCheck = z
  .object({
    check_id: z.string(),
    check_name: z.string().optional(),
    file_path: z.string().optional(),
    repo_file_path: z.string().optional(),
    file_line_range: z.array(z.number()).optional(),
    resource: z.string().optional(),
    severity: z.string().nullable().optional(),
    guideline: z.string().nullable().optional(),
  })
  .loose();
const checkovReport = z
  .object({
    check_type: z.string().optional(),
    results: z.object({ failed_checks: z.array(checkovCheck).default([]) }).loose(),
  })
  .loose();

function mapSeverity(raw: string | null | undefined, fallback: Severity): Severity {
  switch ((raw ?? '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'error':
      return 'high';
    case 'medium':
    case 'moderate':
    case 'warning':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
    case 'informational':
    case 'note':
    case 'none':
      return 'info';
    default:
      return fallback;
  }
}

function checkovTags(id: string, name: string): PolicyTag[] {
  const t = `${id} ${name}`.toLowerCase();
  const tags: PolicyTag[] = [];
  if (/iam|privilege|policy|role/.test(t)) tags.push('iam_changes');
  if (/security group|ingress|egress|0\.0\.0\.0|port|nacl|firewall/.test(t))
    tags.push('security_group_changes');
  if (/public/.test(t)) tags.push('public_exposure');
  if (/encrypt|kms/.test(t)) tags.push('encryption_changes');
  if (/tls|ssl|https/.test(t)) tags.push('tls_changes');
  return tags;
}

/** Parse Checkov JSON output (`checkov -o json`): a single report or an array of reports. */
export function parseCheckov(data: unknown): ScannerFinding[] {
  const reports = Array.isArray(data) ? data : [data];
  const out: ScannerFinding[] = [];
  for (const r of reports) {
    const parsed = checkovReport.safeParse(r);
    if (!parsed.success) throw new Error('Checkov report does not match the expected JSON shape.');
    for (const c of parsed.data.results.failed_checks) {
      if (out.length >= MAX_FINDINGS_PER_ARTIFACT) break;
      const [start, end] = c.file_line_range ?? [];
      const file = cleanPath(c.repo_file_path ?? c.file_path);
      out.push(
        makeFinding({
          source: 'checkov',
          category: 'infrastructure',
          // Checkov's open-source output often has no severity; treat unknown as medium.
          severity: mapSeverity(c.severity, 'medium'),
          title: `${c.check_id}: ${c.check_name ?? 'failed check'}`,
          description: `${c.resource ? `Resource ${c.resource}. ` : ''}${c.guideline ? `Guideline: ${c.guideline}` : ''}`,
          ...(file ? { file } : {}),
          ...(positive(start) ? { startLine: positive(start) } : {}),
          ...(positive(end) ? { endLine: positive(end) } : {}),
          ruleId: c.check_id,
          tags: checkovTags(c.check_id, c.check_name ?? ''),
          status: 'plausible',
        }),
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------- SARIF 2.1.0
const sarifResult = z
  .object({
    ruleId: z.string().optional(),
    rule: z.object({ id: z.string().optional() }).loose().optional(),
    level: z.string().optional(),
    message: z.object({ text: z.string().optional(), markdown: z.string().optional() }).loose(),
    locations: z
      .array(
        z
          .object({
            physicalLocation: z
              .object({
                artifactLocation: z.object({ uri: z.string().optional() }).loose().optional(),
                region: z
                  .object({ startLine: z.number().optional(), endLine: z.number().optional() })
                  .loose()
                  .optional(),
              })
              .loose()
              .optional(),
          })
          .loose(),
      )
      .optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
    suppressions: z.array(z.unknown()).optional(),
  })
  .loose();
const sarifRule = z
  .object({
    id: z.string(),
    name: z.string().optional(),
    shortDescription: z.object({ text: z.string().optional() }).loose().optional(),
    defaultConfiguration: z.object({ level: z.string().optional() }).loose().optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();
const sarifSchema = z
  .object({
    version: z.string().optional(),
    runs: z.array(
      z
        .object({
          tool: z
            .object({
              driver: z.object({ name: z.string(), rules: z.array(sarifRule).optional() }).loose(),
            })
            .loose(),
          results: z.array(sarifResult).optional(),
        })
        .loose(),
    ),
  })
  .loose();

function sarifSeverity(level: string | undefined, securitySeverity: unknown): Severity {
  const ss = typeof securitySeverity === 'string' ? Number(securitySeverity) : securitySeverity;
  if (typeof ss === 'number' && Number.isFinite(ss)) {
    // GitHub code scanning thresholds for security-severity.
    if (ss >= 9) return 'critical';
    if (ss >= 7) return 'high';
    if (ss >= 4) return 'medium';
    if (ss > 0) return 'low';
  }
  return mapSeverity(level, 'medium');
}

/** Parse SARIF 2.1.0 (CodeQL, Semgrep, Trivy, tfsec, ...). Suppressed results are skipped. */
export function parseSarif(data: unknown): ScannerFinding[] {
  const parsed = sarifSchema.safeParse(data);
  if (!parsed.success) throw new Error('SARIF file does not match the SARIF 2.1.0 structure.');
  const out: ScannerFinding[] = [];
  for (const run of parsed.data.runs) {
    const tool = run.tool.driver.name.slice(0, 80);
    const rules = new Map((run.tool.driver.rules ?? []).map((r) => [r.id, r]));
    for (const res of run.results ?? []) {
      if (out.length >= MAX_FINDINGS_PER_ARTIFACT) break;
      if (res.suppressions && res.suppressions.length > 0) continue;
      const ruleId = res.ruleId ?? res.rule?.id;
      const rule = ruleId ? rules.get(ruleId) : undefined;
      const loc = res.locations?.[0]?.physicalLocation;
      const file = cleanPath(loc?.artifactLocation?.uri);
      const start = positive(loc?.region?.startLine);
      const end = positive(loc?.region?.endLine);
      const severity = sarifSeverity(
        res.level ?? rule?.defaultConfiguration?.level,
        res.properties?.['security-severity'] ?? rule?.properties?.['security-severity'],
      );
      const tagsRaw = rule?.properties?.['tags'];
      const isSecurity = Array.isArray(tagsRaw) && tagsRaw.some((t) => t === 'security');
      out.push(
        makeFinding({
          source: `sarif:${tool}`,
          category:
            isSecurity || /codeql|semgrep|trivy|tfsec|snyk|grype/i.test(tool)
              ? 'security'
              : 'reliability',
          severity,
          title: `${ruleId ?? 'result'}: ${rule?.shortDescription?.text ?? rule?.name ?? (res.message.text ?? '').slice(0, 120)}`,
          description: res.message.text ?? res.message.markdown ?? '',
          ...(file ? { file } : {}),
          ...(start ? { startLine: start } : {}),
          ...(end ? { endLine: end } : {}),
          ...(ruleId ? { ruleId } : {}),
          tags: [],
          status: 'plausible',
        }),
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------- npm audit (v2 JSON)
const npmAuditSchema = z
  .object({
    auditReportVersion: z.number().optional(),
    vulnerabilities: z.record(
      z.string(),
      z
        .object({
          name: z.string(),
          severity: z.string(),
          isDirect: z.boolean().optional(),
          range: z.string().optional(),
          fixAvailable: z.unknown().optional(),
          via: z.array(z.unknown()).optional(),
        })
        .loose(),
    ),
  })
  .loose();

/** Parse `npm audit --json` (lockfile v2+ format). */
export function parseNpmAudit(data: unknown): ScannerFinding[] {
  const parsed = npmAuditSchema.safeParse(data);
  if (!parsed.success) throw new Error('Dependency report must be `npm audit --json` output (v2).');
  return Object.values(parsed.data.vulnerabilities)
    .slice(0, MAX_FINDINGS_PER_ARTIFACT)
    .map((v) => {
      const advisories = (v.via ?? [])
        .filter((x): x is { title?: string; url?: string } => typeof x === 'object' && x !== null)
        .map((x) => x.title)
        .filter(Boolean)
        .slice(0, 3);
      return makeFinding({
        source: 'npm-audit',
        category: 'security',
        severity: mapSeverity(v.severity, 'medium'),
        title: `Vulnerable dependency: ${v.name}${v.range ? ` (${v.range})` : ''}`,
        description: `${v.isDirect ? 'Direct' : 'Transitive'} dependency. ${advisories.join('; ')}${v.fixAvailable ? ' A fix is available.' : ''}`,
        file: 'package-lock.json',
        ruleId: `npm:${v.name}`,
        tags: ['dependency_changes'],
        status: 'plausible',
      });
    });
}
