import { describe, expect, it } from 'vitest';
import { countPatchLines, parsePatch } from '../../src/context/diff.js';
import { filePriority, isDocsOnly } from '../../src/context/priority.js';
import {
  collectRepositoryContext,
  localModuleSources,
  normalizeRepoPath,
  selectContextCandidates,
} from '../../src/context/select.js';
import { fitToBudget } from '../../src/subq/state.js';
import type { AssessmentInput, ChangedFile } from '../../src/types.js';
import { FakeGitHub, HEAD_SHA, rawPr } from '../helpers.js';

describe('parsePatch', () => {
  it('tracks added, deleted and context line numbers across hunks', () => {
    const patch = [
      '@@ -1,3 +1,4 @@',
      ' a',
      '-b',
      '+B',
      '+C',
      ' d',
      '@@ -10,2 +11,2 @@ fn()',
      ' x',
      '+y',
      '\\ No newline at end of file',
    ].join('\n');
    const p = parsePatch(patch);
    expect(p.addedLines).toEqual([2, 3, 12]);
    expect(p.lines.find((l) => l.kind === 'del')).toMatchObject({ line: 2, text: 'b' });
    expect([...p.newFileLines]).toEqual([1, 2, 3, 4, 11, 12]);
    expect(p.malformed).toBe(false);
    expect(countPatchLines(patch)).toBe(4);
  });

  it('flags malformed patches', () => {
    expect(parsePatch('garbage\n+x').malformed).toBe(true);
  });
});

describe('priority', () => {
  it('prioritizes by mode', () => {
    expect(filePriority('main.tf', 'terraform')).toBeGreaterThan(
      filePriority('src/a.ts', 'terraform'),
    );
    expect(filePriority('src/auth/login.ts', 'security')).toBeGreaterThanOrEqual(95);
    expect(filePriority('package.json', 'dependencies')).toBe(100);
    expect(filePriority('README.md', 'general')).toBeLessThan(10);
  });
  it('detects docs-only changes', () => {
    expect(isDocsOnly(['README.md', 'docs/a.md'])).toBe(true);
    expect(isDocsOnly(['README.md', 'src/a.ts'])).toBe(false);
    expect(isDocsOnly([])).toBe(false);
  });
});

describe('context selection', () => {
  const changed = (path: string, status: ChangedFile['status'] = 'modified'): ChangedFile => ({
    path,
    status,
    additions: 1,
    deletions: 0,
    addedLines: [],
    sensitive: false,
  });

  it('normalizes paths and rejects traversal', () => {
    expect(normalizeRepoPath('a/./b/../c.tf')).toBe('a/c.tf');
    expect(normalizeRepoPath('../x')).toBeUndefined();
    expect(normalizeRepoPath('/etc/passwd')).toBeUndefined();
    expect(normalizeRepoPath('a/../../x')).toBeUndefined();
  });

  it('extracts local module sources only inside the repo', () => {
    const patch =
      '+module "net" {\n+  source = "../modules/net"\n+}\n+  source = "../../../../etc"';
    expect(localModuleSources('infra/prod/main.tf', patch)).toEqual(['infra/modules/net']);
  });

  it('selects Terraform siblings, module interfaces, tests and never sensitive files', () => {
    const tree = [
      'infra/prod/main.tf',
      'infra/prod/variables.tf',
      'infra/prod/providers.tf',
      'infra/prod/secrets.tfvars.env',
      'infra/prod/.env',
      'infra/modules/net/variables.tf',
      'infra/modules/net/main.tf',
      'src/payments.ts',
      'tests/payments.test.ts',
      '.github/CODEOWNERS',
    ];
    const patches = new Map([['infra/prod/main.tf', '@@ -1 +1 @@\n+  source = "../modules/net"']]);
    const c = selectContextCandidates(
      [changed('infra/prod/main.tf'), changed('src/payments.ts')],
      patches,
      tree,
      'terraform',
    );
    const paths = c.map((x) => x.path);
    expect(paths).toContain('infra/prod/variables.tf');
    expect(paths).toContain('infra/prod/providers.tf');
    expect(paths).toContain('infra/modules/net/variables.tf');
    expect(paths).toContain('tests/payments.test.ts');
    expect(paths).toContain('.github/CODEOWNERS');
    expect(paths).not.toContain('infra/prod/.env');
    expect(paths[0]).toBe('infra/prod/main.tf');
  });

  it('enforces file limits and redacts fetched content', async () => {
    const gh = new FakeGitHub(rawPr(), []);
    gh.tree = ['a/main.tf', 'a/variables.tf', 'a/providers.tf', 'a/versions.tf'];
    gh.setContent(HEAD_SHA, 'a/main.tf', 'x');
    gh.setContent(HEAD_SHA, 'a/variables.tf', 'key = "AKIAABCDEFGHIJKLMNOP"');
    gh.setContent(HEAD_SHA, 'a/providers.tf', 'provider "aws" {}');
    const ctx = await collectRepositoryContext(gh, {
      owner: 'acme',
      repo: 'app',
      headSha: HEAD_SHA,
      changed: [changed('a/main.tf')],
      rawPatches: new Map(),
      mode: 'terraform',
      maxFiles: 2,
      tokenBudget: 100_000,
    });
    expect(ctx.files).toHaveLength(2);
    expect(ctx.files.map((f) => f.content).join()).not.toContain('AKIAABCDEFGHIJKLMNOP');
    expect(ctx.omitted.length).toBeGreaterThan(0);
  });

  it('fitToBudget drops context, then low-priority patches, and records it', () => {
    const big = 'x'.repeat(30_000);
    const input: AssessmentInput = {
      pullRequest: {
        owner: 'o',
        repo: 'r',
        number: 1,
        title: 't',
        body: '',
        author: 'a',
        labels: [],
        baseRef: 'main',
        baseSha: 'a',
        headRef: 'f',
        headSha: 'b',
        headRepoFullName: 'o/r',
        isFork: false,
        draft: false,
        changedFilesCount: 2,
        additions: 0,
        deletions: 0,
      },
      changedFiles: [
        { ...changed('README.md'), patch: big },
        { ...changed('main.tf'), patch: '+small' },
      ],
      repositoryContext: {
        files: [{ path: 'ctx.tf', reason: 'r', content: big, truncated: false }],
        omitted: [],
        treeTruncated: false,
      },
      scannerFindings: [],
      policy: { mode: 'terraform', protectedPaths: [], requireReviewFor: [], conventions: [] },
      contextCompleteness: {
        totalFiles: 2,
        filesAnalyzed: 2,
        filesWithoutPatch: 0,
        sensitiveFilesExcluded: 0,
        diffLinesTotal: 2,
        diffLinesIncluded: 2,
        contextFilesIncluded: 1,
        contextFilesOmitted: 0,
        truncated: false,
        limitations: [],
      },
    };
    const out = fitToBudget(input, 5_000);
    expect(out.repositoryContext.files).toHaveLength(0);
    expect(out.changedFiles.find((f) => f.path === 'README.md')?.patch).toBeUndefined();
    expect(out.changedFiles.find((f) => f.path === 'main.tf')?.patch).toBe('+small');
    expect(out.contextCompleteness.truncated).toBe(true);
    expect(out.contextCompleteness.limitations.length).toBe(2);
    // original untouched
    expect(input.repositoryContext.files).toHaveLength(1);
  });
});
