import type { ScannerName, Settings } from '../config/schema.js';
import type { ChangedFile, ScannerFinding, ScannerStatus } from '../types.js';
import { errorMessage } from '../utils/errors.js';
import { ArtifactError, expandArtifactGlobs, readJsonArtifact } from './artifacts.js';
import { dedupeFindings } from './finding.js';
import { parseCheckov, parseGitleaks, parseNpmAudit, parseSarif } from './parsers.js';
import { runChangedFileRules } from './rules.js';

export interface ScannerArtifactInputs {
  gitleaksReport?: string;
  checkovReport?: string;
  sarifFiles: string[];
  dependencyReport?: string;
}

export interface ScannerRunResult {
  findings: ScannerFinding[];
  statuses: ScannerStatus[];
  /** Findings dropped because they point at files this PR did not change. */
  outsideDiff: number;
}

interface ArtifactSpec {
  scanner: ScannerName;
  label: string;
  paths: string[];
  parse: (data: unknown) => ScannerFinding[];
}

/**
 * Run built-in deterministic rules and ingest artifacts from trusted upstream scanners.
 * No external tool or PR code is executed here.
 */
export async function runScanners(args: {
  settings: Settings;
  artifacts: ScannerArtifactInputs;
  files: ChangedFile[];
  rawPatches: Map<string, string>;
  prTitle: string;
  prBody: string;
  roots: string[];
}): Promise<ScannerRunResult> {
  const { settings } = args;
  const statuses: ScannerStatus[] = [];
  let findings: ScannerFinding[] = [];

  const ruleFindings = runChangedFileRules({
    files: args.files,
    rawPatches: args.rawPatches,
    prTitle: args.prTitle,
    prBody: args.prBody,
    scanSecrets: settings.scanners.secrets,
    scanTerraform: settings.scanners.terraform,
  });
  findings.push(...ruleFindings);
  statuses.push({
    name: 'Built-in change rules and secret detector',
    status: 'completed',
    required: false,
    findings: ruleFindings.length,
  });

  const specs: ArtifactSpec[] = [
    {
      scanner: 'secrets',
      label: 'Gitleaks report',
      paths: args.artifacts.gitleaksReport ? [args.artifacts.gitleaksReport] : [],
      parse: parseGitleaks,
    },
    {
      scanner: 'terraform',
      label: 'Checkov report',
      paths: args.artifacts.checkovReport ? [args.artifacts.checkovReport] : [],
      parse: parseCheckov,
    },
    {
      scanner: 'sarif',
      label: 'SARIF results',
      paths: args.artifacts.sarifFiles,
      parse: parseSarif,
    },
    {
      scanner: 'dependencies',
      label: 'Dependency audit (npm audit JSON)',
      paths: args.artifacts.dependencyReport ? [args.artifacts.dependencyReport] : [],
      parse: parseNpmAudit,
    },
  ];

  for (const spec of specs) {
    const required = settings.requiredScanners.includes(spec.scanner);
    if (!settings.scanners[spec.scanner]) {
      statuses.push({ name: spec.label, status: 'disabled', required, findings: 0 });
      continue;
    }
    if (spec.paths.length === 0) {
      statuses.push({
        name: spec.label,
        status: required ? 'missing' : 'not_configured',
        required,
        findings: 0,
        ...(required ? { detail: 'Required artifact input was not provided.' } : {}),
      });
      continue;
    }
    let files: string[];
    try {
      files = await expandArtifactGlobs(spec.paths, args.roots);
    } catch (err) {
      statuses.push({
        name: spec.label,
        status: 'invalid',
        required,
        findings: 0,
        detail: errorMessage(err),
      });
      continue;
    }
    if (files.length === 0) {
      statuses.push({
        name: spec.label,
        status: 'missing',
        required,
        findings: 0,
        detail: 'No files matched the configured path.',
      });
      continue;
    }
    let count = 0;
    let problem: ScannerStatus | undefined;
    for (const file of files) {
      try {
        const data = await readJsonArtifact(file, args.roots);
        const parsed = spec.parse(data);
        findings.push(...parsed);
        count += parsed.length;
      } catch (err) {
        problem = {
          name: spec.label,
          status: err instanceof ArtifactError && err.kind === 'missing' ? 'missing' : 'invalid',
          required,
          findings: count,
          detail: errorMessage(err),
        };
        break;
      }
    }
    statuses.push(problem ?? { name: spec.label, status: 'completed', required, findings: count });
  }

  // Only keep upstream findings that point at files changed in this PR (or at no file).
  const changed = new Set(args.files.map((f) => f.path));
  const before = findings.length;
  findings = findings.filter((f) => !f.file || changed.has(f.file));
  return { findings: dedupeFindings(findings), statuses, outsideDiff: before - findings.length };
}
