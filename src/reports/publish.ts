import type { CheckAnnotation, CheckConclusion, GitHubApi } from '../github/api.js';
import { errorMessage } from '../utils/errors.js';
import { redactForOutput } from '../utils/redact.js';
import { COMMENT_MARKER, REPORT_TITLE } from './render.js';

export interface PublishResult {
  checkRunId?: number;
  commentId?: number;
  warnings: string[];
}

/** Publish a completed check run. Failures (e.g. read-only fork tokens) become warnings. */
export async function publishCheckRun(
  api: GitHubApi,
  args: {
    owner: string;
    repo: string;
    headSha: string;
    conclusion: CheckConclusion;
    title: string;
    summary: string;
    annotations: CheckAnnotation[];
    detailsUrl?: string;
  },
): Promise<{ id?: number; warning?: string }> {
  try {
    const id = await api.createCheckRun({
      owner: args.owner,
      repo: args.repo,
      name: REPORT_TITLE,
      headSha: args.headSha,
      status: 'completed',
      conclusion: args.conclusion,
      ...(args.detailsUrl ? { detailsUrl: args.detailsUrl } : {}),
      output: {
        title: args.title,
        summary: redactForOutput(args.summary),
        annotations: args.annotations,
      },
    });
    return { id };
  } catch (err) {
    return {
      warning: `Could not create check run (needs 'checks: write'; unavailable to fork PRs): ${redactForOutput(errorMessage(err))}`,
    };
  }
}

/**
 * Create or update the single report comment. Only comments authored by a bot and
 * carrying our marker are updated, so user comments are never touched.
 */
export async function upsertReportComment(
  api: GitHubApi,
  args: { owner: string; repo: string; number: number; body: string },
): Promise<{ id?: number; warning?: string }> {
  const body = `${COMMENT_MARKER}\n${redactForOutput(args.body)}`;
  try {
    const comments = await api.listIssueComments(args.owner, args.repo, args.number);
    const existing = comments.find(
      (c) => c.userType === 'Bot' && c.body.startsWith(COMMENT_MARKER),
    );
    if (existing) {
      await api.updateIssueComment(args.owner, args.repo, existing.id, body);
      return { id: existing.id };
    }
    const id = await api.createIssueComment(args.owner, args.repo, args.number, body);
    return { id };
  } catch (err) {
    return {
      warning: `Could not publish PR comment (needs 'pull-requests: write'): ${redactForOutput(errorMessage(err))}`,
    };
  }
}
