import { describe, expect, it } from 'vitest';
import { parseInputs, DEFAULT_CONFIG_PATH } from '../../src/config/inputs.js';
import { parseRepoConfig, resolveSettings } from '../../src/config/load.js';
import { ConfigError } from '../../src/utils/errors.js';

const reader = (m: Record<string, string>) => (n: string) => m[n] ?? '';

describe('parseInputs', () => {
  it('applies defaults and leaves policy inputs undefined when unset', () => {
    const i = parseInputs(reader({ 'github-token': 't' }));
    expect(i.configPath).toBe(DEFAULT_CONFIG_PATH);
    expect(i.configPathExplicit).toBe(false);
    expect(i.mode).toBeUndefined();
    expect(i.failOn).toBeUndefined();
    expect(i.dryRun).toBe(false);
    expect(i.provider).toBe('subq');
    expect(i.timeoutSeconds).toBe(60);
    expect(i.sarifFiles).toEqual([]);
  });

  it('parses explicit values', () => {
    const i = parseInputs(
      reader({
        mode: 'Terraform',
        'fail-on': 'high',
        report: 'both',
        'max-files': '50',
        'max-diff-lines': '100',
        'context-files': '0',
        'dry-run': 'true',
        'provider-error-policy': 'warn',
        'sarif-files': 'a.sarif\nb/*.sarif, c.sarif',
      }),
    );
    expect(i).toMatchObject({
      mode: 'terraform',
      failOn: 'high',
      report: 'both',
      maxFiles: 50,
      maxDiffLines: 100,
      contextFiles: 0,
      dryRun: true,
      providerErrorPolicy: 'warn',
      sarifFiles: ['a.sarif', 'b/*.sarif', 'c.sarif'],
    });
  });

  it.each([
    ['mode', 'yolo', /mode/],
    ['fail-on', 'low', /fail-on/],
    ['report', 'email', /report/],
    ['max-files', '-1', /max-files/],
    ['max-files', '0', /between/],
    ['max-diff-lines', '1.5', /whole number/],
    ['context-files', '101', /between/],
    ['dry-run', 'maybe', /dry-run/],
    ['provider-error-policy', 'ignore', /provider-error-policy/],
    ['provider', 'openai', /provider/],
    ['config', '../etc/passwd', /config/],
    ['config', '/abs.yml', /config/],
  ])('rejects invalid %s=%s', (name, value, msg) => {
    expect(() => parseInputs(reader({ [name]: value }))).toThrow(msg);
  });

  it('does not echo long invalid values back', () => {
    try {
      parseInputs(reader({ mode: 'x'.repeat(500) }));
    } catch (e) {
      expect((e as Error).message.length).toBeLessThan(200);
    }
  });
});

describe('repository config', () => {
  const full = `
version: 1
mode: terraform
analysis:
  max_files: 100
  max_diff_lines: 5000
  context_files: 5
  fail_on_incomplete_context: true
risk:
  fail_on: high
  require_review: [critical, high]
policies:
  protected_paths: ["infrastructure/prod/**", ".github/workflows/**"]
  require_review_for: [iam_changes, security_group_changes, database_migrations, destructive_infrastructure_changes]
  critical_findings_always_fail: true
scanners:
  secrets: true
  terraform: true
  sarif: true
  dependencies: false
report:
  destination: both
  include_file_annotations: true
  include_ai_explanation: true
`;

  it('accepts the documented example', () => {
    const c = parseRepoConfig(full, 'x');
    expect(c.mode).toBe('terraform');
    expect(c.policies?.require_review_for).toContain('iam_changes');
  });

  it('rejects unknown keys at any level', () => {
    expect(() => parseRepoConfig('version: 1\nfoo: bar\n', 'x')).toThrow(/invalid/);
    expect(() => parseRepoConfig('version: 1\nrisk:\n  fail_onn: high\n', 'x')).toThrow(
      /fail_onn|Unrecognized/,
    );
  });

  it('rejects invalid values and versions', () => {
    expect(() => parseRepoConfig('version: 2\n', 'x')).toThrow(ConfigError);
    expect(() => parseRepoConfig('version: 1\nrisk:\n  fail_on: low\n', 'x')).toThrow(ConfigError);
    expect(() =>
      parseRepoConfig('version: 1\npolicies:\n  require_review_for: [made_up]\n', 'x'),
    ).toThrow(ConfigError);
    expect(() => parseRepoConfig('', 'x')).toThrow(/empty/);
    expect(() => parseRepoConfig('version: [1\n', 'x')).toThrow(/YAML/);
  });

  it('does not evaluate custom YAML tags as code', () => {
    expect(() => parseRepoConfig('version: 1\nmode: !!js/function "function(){}"\n', 'x')).toThrow(
      ConfigError,
    );
  });

  it('rejects oversized config', () => {
    expect(() => parseRepoConfig('version: 1\n#' + 'x'.repeat(70_000), 'x')).toThrow(/exceeds/);
  });

  it('explicit inputs override repository config which overrides defaults', () => {
    const repo = parseRepoConfig(full, 'x');
    const inputs = parseInputs(reader({ 'fail-on': 'critical' }));
    const s = resolveSettings(inputs, repo);
    expect(s.failOn).toBe('critical'); // input
    expect(s.mode).toBe('terraform'); // repo
    expect(s.report).toBe('both'); // repo
    expect(s.maxFiles).toBe(100);
    expect(s.providerErrorPolicy).toBe('require-review'); // default
    const d = resolveSettings(parseInputs(reader({})), undefined);
    expect(d).toMatchObject({
      mode: 'general',
      failOn: 'never',
      report: 'check',
      maxFiles: 200,
      maxDiffLines: 12000,
      contextFiles: 10,
    });
  });

  it('rejects required scanners that are disabled', () => {
    const repo = parseRepoConfig(
      'version: 1\nscanners:\n  sarif: false\n  required: [sarif]\n',
      'x',
    );
    expect(() => resolveSettings(parseInputs(reader({})), repo)).toThrow(/required/);
  });
});
