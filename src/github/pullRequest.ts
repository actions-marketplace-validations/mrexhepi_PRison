import { z } from 'zod';
import { GitHubApiError } from '../utils/errors.js';
import { isSensitivePath, redactSecrets } from '../utils/redact.js';
import { countPatchLines, parsePatch } from '../context/diff.js';
import { filePriority } from '../context/priority.js';
import type { ChangedFile, FileStatus, Mode, PullRequestMetadata } from '../types.js';
import type { GitHubApi } from './api.js';

export interface PullRequestRef {
  owner: string;
  repo: string;
  number: number;
}

export const SUPPORTED_EVENTS = ['pull_request', 'pull_request_target'] as const;

export interface EventContext {
  eventName: string;
  repo: { owner: string; repo: string };
  payload: { pull_request?: { number?: unknown } };
}

/** Returns a PR reference for supported events, or a reason the event is unsupported. */
export function resolvePullRequestRef(ctx: EventContext): PullRequestRef | { unsupported: string } {
  if (!(SUPPORTED_EVENTS as readonly string[]).includes(ctx.eventName)) {
    return {
      unsupported: `Event '${ctx.eventName}' is not supported. Use a 'pull_request' trigger.`,
    };
  }
  const n = ctx.payload.pull_request?.number;
  if (typeof n !== 'number' || !Number.isInteger(n) || n <= 0) {
    return { unsupported: 'The event payload does not contain a pull request number.' };
  }
  return { owner: ctx.repo.owner, repo: ctx.repo.repo, number: n };
}

const prSchema = z.object({
  number: z.number().int().positive(),
  title: z.string(),
  body: z.string().nullable().optional(),
  draft: z.boolean().optional(),
  user: z.object({ login: z.string() }).nullable().optional(),
  labels: z
    .array(z.object({ name: z.string().optional() }).loose())
    .optional()
    .default([]),
  base: z.object({
    ref: z.string(),
    sha: z.string().regex(/^[0-9a-f]{40}$/i),
    repo: z.object({ full_name: z.string() }).loose(),
  }),
  head: z.object({
    ref: z.string(),
    sha: z.string().regex(/^[0-9a-f]{40}$/i),
    repo: z.object({ full_name: z.string() }).loose().nullable(),
  }),
  changed_files: z.number().int().nonnegative().optional(),
  additions: z.number().int().nonnegative().optional(),
  deletions: z.number().int().nonnegative().optional(),
});

const fileSchema = z.object({
  filename: z.string().min(1).max(4096),
  previous_filename: z.string().optional(),
  status: z.string(),
  additions: z.number().int().nonnegative(),
  deletions: z.number().int().nonnegative(),
  patch: z.string().optional(),
});

const KNOWN_STATUSES: FileStatus[] = [
  'added',
  'removed',
  'modified',
  'renamed',
  'copied',
  'changed',
  'unchanged',
];

export interface CollectedPullRequest {
  metadata: PullRequestMetadata;
  files: ChangedFile[];
  /** Unredacted patches, kept in-process only for deterministic scanners. Never sent out. */
  rawPatches: Map<string, string>;
  /** Valid annotation lines per file (new-file line numbers covered by the diff). */
  annotatableLines: Map<string, Set<number>>;
  totalFiles: number;
  filesTruncated: boolean;
  diffLinesTotal: number;
  diffLinesIncluded: number;
  malformedPatches: string[];
}

export async function collectPullRequest(
  api: GitHubApi,
  ref: PullRequestRef,
  opts: { maxFiles: number; maxDiffLines: number; mode: Mode },
): Promise<CollectedPullRequest> {
  const rawPr = await api.getPullRequest(ref.owner, ref.repo, ref.number);
  const prParsed = prSchema.safeParse(rawPr);
  if (!prParsed.success) {
    throw new GitHubApiError(
      `Unexpected pull request response from GitHub: ${prParsed.error.issues[0]?.message ?? 'invalid'}`,
    );
  }
  const pr = prParsed.data;
  const baseFull = pr.base.repo.full_name;
  const headFull = pr.head.repo?.full_name ?? '(deleted fork)';
  const metadata: PullRequestMetadata = {
    owner: ref.owner,
    repo: ref.repo,
    number: pr.number,
    title: pr.title,
    body: pr.body ?? '',
    author: pr.user?.login ?? 'unknown',
    labels: pr.labels.map((l) => l.name).filter((n): n is string => typeof n === 'string'),
    baseRef: pr.base.ref,
    baseSha: pr.base.sha,
    headRef: pr.head.ref,
    headSha: pr.head.sha,
    headRepoFullName: headFull,
    isFork: headFull.toLowerCase() !== baseFull.toLowerCase(),
    draft: pr.draft ?? false,
    changedFilesCount: pr.changed_files ?? 0,
    additions: pr.additions ?? 0,
    deletions: pr.deletions ?? 0,
  };

  const listed = await api.listPullRequestFiles(ref.owner, ref.repo, ref.number, opts.maxFiles);
  const rawPatches = new Map<string, string>();
  const annotatableLines = new Map<string, Set<number>>();
  const malformedPatches: string[] = [];
  const parsedFiles: ChangedFile[] = [];

  for (const raw of listed.files) {
    const parsed = fileSchema.safeParse(raw);
    if (!parsed.success) {
      throw new GitHubApiError('Unexpected pull request file entry from GitHub API.');
    }
    const f = parsed.data;
    const status = (KNOWN_STATUSES as string[]).includes(f.status)
      ? (f.status as FileStatus)
      : 'changed';
    const sensitive = isSensitivePath(f.filename);
    const file: ChangedFile = {
      path: f.filename,
      ...(f.previous_filename ? { previousPath: f.previous_filename } : {}),
      status,
      additions: f.additions,
      deletions: f.deletions,
      addedLines: [],
      sensitive,
    };
    if (f.patch !== undefined) {
      rawPatches.set(f.filename, f.patch);
      const p = parsePatch(f.patch);
      if (p.malformed) malformedPatches.push(f.filename);
      file.addedLines = p.addedLines;
      annotatableLines.set(f.filename, p.newFileLines);
    } else if (f.additions + f.deletions > 0) {
      // GitHub omits patches for binary files and very large diffs.
      file.patchOmittedReason = 'binary_or_too_large';
    }
    if (sensitive) file.patchOmittedReason = 'sensitive_file';
    parsedFiles.push(file);
  }

  // Allocate the diff budget to the highest-priority files first.
  const diffLinesTotal = [...rawPatches.values()].reduce((n, p) => n + countPatchLines(p), 0);
  let budget = opts.maxDiffLines;
  let included = 0;
  const order = [...parsedFiles].sort(
    (a, b) => filePriority(b.path, opts.mode) - filePriority(a.path, opts.mode),
  );
  for (const file of order) {
    const raw = rawPatches.get(file.path);
    if (raw === undefined || file.sensitive) continue;
    const n = countPatchLines(raw);
    if (n <= budget) {
      file.patch = redactSecrets(raw);
      budget -= n;
      included += n;
    } else {
      file.patchOmittedReason = 'diff_budget_exceeded';
    }
  }

  const totalFiles = Math.max(metadata.changedFilesCount, parsedFiles.length);
  return {
    metadata,
    files: parsedFiles,
    rawPatches,
    annotatableLines,
    totalFiles,
    filesTruncated: listed.hasMore || totalFiles > parsedFiles.length,
    diffLinesTotal,
    diffLinesIncluded: included,
    malformedPatches,
  };
}
