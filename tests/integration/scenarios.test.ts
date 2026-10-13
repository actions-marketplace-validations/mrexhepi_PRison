import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { run } from '../../src/main.js';
import {
  BASE_SHA,
  DEFAULT_INPUTS,
  FakeGitHub,
  HEAD_SHA,
  addPatch,
  delPatch,
  deps,
  fakeCore,
  fakeSubQ,
  file,
  rawPr,
  subqProvider,
} from '../helpers.js';

const FIX = join(import.meta.dirname, '..', 'fixtures', 'scanners');

describe('integration scenarios', () => {
  it('1. documentation-only PR passes without calling the model', async () => {
    const gh = new FakeGitHub(rawPr(), [file('docs/guide.md', addPatch(['New docs']))]);
    const core = fakeCore(DEFAULT_INPUTS);
    const fake = fakeSubQ();
    const r = await run(deps(gh, core, subqProvider(fake)));
    expect(fake.requests).toHaveLength(0);
    expect(r.outcome?.decision).toBe('pass');
    expect(core.outputs['assessment-status']).toBe('not_required');
    expect(gh.checkRuns[0]?.conclusion).toBe('success');
    expect(core.failed).toBeUndefined();
  });

  it('2. production Terraform security group change requires review / blocks on fail-on high', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file(
        'infrastructure/prod/security.tf',
        addPatch(
          [
            'resource "aws_security_group_rule" "ssh" {',
            '  type = "ingress"',
            '  cidr_blocks = ["0.0.0.0/0"]',
            '}',
          ],
          20,
        ),
      ),
    ]);
    gh.tree = ['infrastructure/prod/security.tf', 'infrastructure/prod/variables.tf'];
    gh.setContent(
      HEAD_SHA,
      'infrastructure/prod/security.tf',
      'resource "aws_security_group_rule" "ssh" {}',
    );
    gh.setContent(HEAD_SHA, 'infrastructure/prod/variables.tf', 'variable "env" {}');
    gh.setContent(
      BASE_SHA,
      '.github/subq-pr-risk.yml',
      'version: 1\nmode: terraform\nrisk:\n  fail_on: high\npolicies:\n  protected_paths: ["infrastructure/prod/**"]\n  require_review_for: [security_group_changes]\n',
    );
    const core = fakeCore({ ...DEFAULT_INPUTS, report: 'both' });
    const fake = fakeSubQ({ overall: 1.9, noul: { infrastructure_risk: 0.9, human_review: 0.85 } });
    const r = await run(deps(gh, core, subqProvider(fake)));

    expect(r.outcome).toMatchObject({ decision: 'blocked', effectiveLevel: 'high', fail: true });
    expect(core.failed).toMatch(/blocked/);
    const state = fake.requests[0]!.body.state as {
      repository_context: { path: string }[];
      repository_policy: { assessment_mode: string };
    };
    expect(state.repository_policy.assessment_mode).toBe('terraform');
    expect(state.repository_context.map((c) => c.path)).toContain(
      'infrastructure/prod/variables.tf',
    );
    const check = gh.checkRuns[0]!;
    expect(check.conclusion).toBe('failure');
    expect(
      check.output.annotations?.some(
        (a) => a.path === 'infrastructure/prod/security.tf' && a.start_line === 22,
      ),
    ).toBe(true);
    expect(gh.comments).toHaveLength(1);
    expect(core.outputs['decision']).toBe('blocked');
    expect(core.outputs['ai-risk-score']).toBe('63');
  });

  it('3. IAM privilege expansion is reported with review required', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file(
        'iam/policy.tf',
        addPatch([
          'resource "aws_iam_policy" "app" {',
          '  policy = jsonencode({ Statement = [{ "Action": "*", "Resource": "*" }] })',
          '}',
        ]),
      ),
    ]);
    const core = fakeCore(DEFAULT_INPUTS);
    const r = await run(deps(gh, core, subqProvider(fakeSubQ({ overall: 1.9, defaultNoul: 0.8 }))));
    expect(r.outcome?.decision).toBe('review_required');
    expect(r.outcome?.effectiveLevel).toBe('high');
    expect(r.markdown).toContain('IAM policy grants wildcard actions');
    expect(core.failed).toBeUndefined(); // fail-on defaults to never
  });

  it('4. confirmed critical secret blocks even when the AI says low risk', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file('src/config.ts', addPatch(['export const key = "AKIAIOSFODNN7EXAMPLE";'])),
    ]);
    const core = fakeCore(DEFAULT_INPUTS);
    const fake = fakeSubQ({ overall: 0 });
    const r = await run(deps(gh, core, subqProvider(fake)));
    expect(r.outcome).toMatchObject({
      decision: 'blocked',
      effectiveLevel: 'critical',
      aiLevel: 'low',
    });
    expect(core.failed).toBeDefined();
    expect(JSON.stringify(fake.requests)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(r.markdown).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('5. large PR with incomplete context is surfaced and requires review', async () => {
    const files = Array.from({ length: 30 }, (_, i) =>
      file(`src/m${i}.ts`, addPatch(Array(50).fill(`x${i}();`))),
    );
    const gh = new FakeGitHub(rawPr({ changed_files: 30 }), files);
    const core = fakeCore({ ...DEFAULT_INPUTS, 'max-files': '20', 'max-diff-lines': '200' });
    const r = await run(deps(gh, core, subqProvider(fakeSubQ({ overall: 0.3 }))));
    expect(core.outputs['context-complete']).toBe('false');
    expect(r.outcome?.decision).toBe('review_required');
    expect(r.markdown).toContain('Context truncated: Yes');
    expect(r.markdown).toMatch(/Only 20 of 30 changed files/);
    expect(r.markdown).toMatch(/exceeded max-diff-lines/);
  });

  it('6. missing required scanner artifact is not counted as passing', async () => {
    const gh = new FakeGitHub(rawPr(), [file('main.tf', addPatch(['locals { a = 1 }']))]);
    gh.setContent(
      BASE_SHA,
      '.github/subq-pr-risk.yml',
      'version: 1\nscanners:\n  required: [terraform]\n',
    );
    const core = fakeCore(DEFAULT_INPUTS);
    const r = await run(deps(gh, core, subqProvider(fakeSubQ({ overall: 0 }))));
    expect(r.outcome?.decision).toBe('review_required');
    expect(r.markdown).toMatch(/Checkov report \(required\) \| missing/);
  });

  it('7. SubQ timeout yields inconclusive, never pass', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    const core = fakeCore(DEFAULT_INPUTS);
    const r = await run(
      deps(gh, core, subqProvider(fakeSubQ({ delayMs: 200 }), { timeoutMs: 10, retries: 1 })),
    );
    expect(r.ai?.status).toBe('failed');
    expect(r.outcome?.decision).toBe('inconclusive');
    expect(r.outcome?.requiresReview).toBe(true);
    expect(core.failed).toBeUndefined(); // default provider-error-policy require-review
    expect(gh.checkRuns[0]?.conclusion).toBe('neutral');

    const core2 = fakeCore({ ...DEFAULT_INPUTS, 'provider-error-policy': 'fail' });
    await run(
      deps(
        new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]),
        core2,
        subqProvider(fakeSubQ({ delayMs: 200 }), { timeoutMs: 10, retries: 0 }),
      ),
    );
    expect(core2.failed).toMatch(/provider-error-policy/);
  });

  it('8. invalid AI response is rejected and reported as inconclusive', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    const core = fakeCore({ ...DEFAULT_INPUTS, 'provider-error-policy': 'warn' });
    const fake = fakeSubQ({
      mutate: (b) => {
        (b.answers as Record<string, { score: number }>).overall_risk!.score = 99;
      },
    });
    const r = await run(deps(gh, core, subqProvider(fake)));
    expect(r.ai).toMatchObject({ status: 'failed' });
    expect(r.ai?.error).toMatch(/validation/);
    expect(r.outcome?.decision).toBe('inconclusive');
    expect(core.failed).toBeUndefined();
  });

  it('9. forked PR without secrets produces an explicitly skipped AI assessment', async () => {
    const gh = new FakeGitHub(
      rawPr({ head: { ref: 'f', sha: HEAD_SHA, repo: { full_name: 'stranger/app' } } }),
      [file('src/a.ts', addPatch(['a();']))],
    );
    gh.failChecks = true; // fork tokens are read-only
    const core = fakeCore({ 'github-token': 'ghs_x', 'subq-api-key': '' });
    const r = await run(deps(gh, core));
    expect(r.ai?.status).toBe('skipped');
    expect(r.ai?.error).toMatch(/forked PRs/);
    expect(r.outcome?.decision).toBe('inconclusive');
    expect(core.outputs['assessment-status']).toBe('skipped');
    expect(core.logs.join()).toMatch(/Could not create check run/);
    expect(core.summary).toContain('INCONCLUSIVE');
    expect(core.failed).toBeUndefined();
  });

  it('9b. same-repo PR with a missing token fails clearly', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    const core = fakeCore({ 'github-token': 'ghs_x', 'subq-api-key': '' });
    await run(deps(gh, core));
    expect(core.failed).toMatch(/SUBQ_API_KEY/);
    expect(gh.checkRuns[0]?.conclusion).toBe('failure');
  });

  it('10. renamed and deleted files are handled', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file('infra/new-name.tf', undefined, {
        status: 'renamed',
        previous_filename: 'infra/prod/old-name.tf',
        additions: 0,
        deletions: 0,
      }),
      file(
        'infra/network.tf',
        delPatch(['resource "aws_vpc" "main" {', '  cidr_block = "10.0.0.0/16"', '}']),
        { status: 'removed' },
      ),
      file('assets/logo.png', undefined, { additions: 0, deletions: 0, status: 'added' }),
      file('bin/tool', undefined, { additions: 10, deletions: 2 }),
    ]);
    gh.setContent(
      BASE_SHA,
      '.github/subq-pr-risk.yml',
      'version: 1\npolicies:\n  protected_paths: ["infra/prod/**"]\n',
    );
    const core = fakeCore(DEFAULT_INPUTS);
    const fake = fakeSubQ({ overall: 1 });
    const r = await run(deps(gh, core, subqProvider(fake)));
    expect(r.outcome?.protectedPathsTouched).toContain('infra/prod/old-name.tf');
    expect(r.markdown).toMatch(/Terraform resource removed: aws\\_vpc.main|Terraform file deleted/);
    const state = fake.requests[0]!.body.state as {
      changed_files: { path: string; previous_path?: string; patch_unavailable?: string }[];
    };
    expect(state.changed_files.find((f) => f.path === 'infra/new-name.tf')?.previous_path).toBe(
      'infra/prod/old-name.tf',
    );
    expect(state.changed_files.find((f) => f.path === 'bin/tool')?.patch_unavailable).toBe(
      'binary_or_too_large',
    );
    expect(r.markdown).toMatch(/had no textual patch/);
  });
});

describe('end-to-end behaviour', () => {
  it('updates the existing bot comment instead of posting duplicates', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    gh.comments.push({
      id: 1,
      body: '<!-- subq-pr-risk-scanner:report -->\nfake by user',
      userLogin: 'mallory',
      userType: 'User',
    });
    for (let i = 0; i < 3; i++) {
      await run(
        deps(gh, fakeCore({ ...DEFAULT_INPUTS, report: 'comment' }), subqProvider(fakeSubQ())),
      );
    }
    const ours = gh.comments.filter((c) => c.userType === 'Bot');
    expect(ours).toHaveLength(1);
    expect(gh.comments.find((c) => c.id === 1)?.body).toBe(
      '<!-- subq-pr-risk-scanner:report -->\nfake by user',
    );
    expect(gh.checkRuns).toHaveLength(0);
  });

  it('ingests upstream scanner artifacts and writes a JSON report', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file('src/handler.js', addPatch(['ok();', 'const r = eval(req.query.x);'])),
      file('infrastructure/prod/security.tf', addPatch(['# change'])),
    ]);
    const reportDir = mkdtempSync(join(tmpdir(), 'subq-report-'));
    const core = fakeCore({
      ...DEFAULT_INPUTS,
      'sarif-files': 'semgrep.sarif',
      'checkov-report': 'checkov.json',
    });
    const r = await run(
      deps(gh, core, subqProvider(fakeSubQ({ overall: 1.5 })), {
        workspaceRoots: [FIX],
        reportDir,
      }),
    );
    expect(r.markdown).toContain('sarif:Semgrep OSS');
    expect(r.markdown).toContain('checkov');
    const report = JSON.parse(readFileSync(core.outputs['report-path']!, 'utf8')) as {
      findings: { sources: string[] }[];
    };
    const merged = report.findings.find((f) => f.sources.length > 1);
    expect(merged?.sources.sort()).toEqual(['sarif:Semgrep OSS', 'subq-rules']);
  });

  it('skips unsupported events without failing', async () => {
    const gh = new FakeGitHub(rawPr(), []);
    const core = fakeCore(DEFAULT_INPUTS);
    const d = deps(gh, core);
    d.context = { ...d.context, eventName: 'push', payload: {} };
    const r = await run(d);
    expect(r.status).toBe('skipped');
    expect(core.failed).toBeUndefined();
  });

  it('fails clearly on invalid repository configuration', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    gh.setContent(
      BASE_SHA,
      '.github/subq-pr-risk.yml',
      'version: 1\nrisk:\n  fail_on: sometimes\n',
    );
    const core = fakeCore(DEFAULT_INPUTS);
    await run(deps(gh, core, subqProvider(fakeSubQ())));
    expect(core.failed).toMatch(/risk\.fail_on/);
  });

  it('reads policy from the base commit, not the PR head', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file('.github/subq-pr-risk.yml', addPatch(['version: 1', 'risk:', '  fail_on: never'])),
    ]);
    gh.setContent(BASE_SHA, '.github/subq-pr-risk.yml', 'version: 1\nrisk:\n  fail_on: medium\n');
    gh.setContent(HEAD_SHA, '.github/subq-pr-risk.yml', 'version: 1\nrisk:\n  fail_on: never\n');
    const core = fakeCore(DEFAULT_INPUTS);
    const r = await run(deps(gh, core, subqProvider(fakeSubQ({ overall: 1.2 }))));
    expect(r.outcome?.decision).toBe('blocked');
  });

  it('dry-run reports a blocked decision without failing the step', async () => {
    const gh = new FakeGitHub(rawPr(), [
      file('src/config.ts', addPatch(['const k = "AKIAIOSFODNN7EXAMPLE";'])),
    ]);
    const core = fakeCore({ ...DEFAULT_INPUTS, 'dry-run': 'true' });
    const r = await run(deps(gh, core, subqProvider(fakeSubQ())));
    expect(r.outcome?.decision).toBe('blocked');
    expect(core.failed).toBeUndefined();
    expect(r.markdown).toContain('dry-run: not enforced');
  });

  it('mock provider is explicit and labeled', async () => {
    const gh = new FakeGitHub(rawPr(), [file('src/a.ts', addPatch(['a();']))]);
    const core = fakeCore({ 'github-token': 'x', provider: 'mock' });
    const r = await run(deps(gh, core));
    expect(r.ai?.status).toBe('completed');
    expect(r.markdown).toContain('MOCK provider');
  });
});
