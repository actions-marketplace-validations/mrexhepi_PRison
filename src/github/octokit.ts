import { getOctokit } from '@actions/github';
import { GitHubApiError } from '../utils/errors.js';
import { parseRetryAfter, withRetry } from '../utils/retry.js';
import type {
  FileContent,
  GitHubApi,
  IssueComment,
  RawPullRequest,
  RawPullRequestFile,
} from './api.js';

type Octokit = ReturnType<typeof getOctokit>;

interface HttpLikeError {
  status?: number;
  response?: { headers?: Record<string, string | undefined> };
  message?: string;
}

function asHttpError(err: unknown): HttpLikeError {
  return typeof err === 'object' && err !== null ? (err as HttpLikeError) : {};
}

export function isRetryableGitHubError(err: unknown): boolean {
  const e = asHttpError(err);
  if (e.status === undefined) return true; // network-level failure
  if (e.status >= 500 || e.status === 429) return true;
  if (e.status === 403) {
    const h = e.response?.headers ?? {};
    return h['retry-after'] !== undefined || h['x-ratelimit-remaining'] === '0';
  }
  return false;
}

function retryDelay(err: unknown): number | undefined {
  const h = asHttpError(err).response?.headers ?? {};
  const ra = parseRetryAfter(h['retry-after']);
  if (ra !== undefined) return ra;
  const reset = Number(h['x-ratelimit-reset']);
  if (h['x-ratelimit-remaining'] === '0' && Number.isFinite(reset)) {
    return Math.max(0, reset * 1000 - Date.now());
  }
  return undefined;
}

const MAX_CONTENT_BYTES = 512 * 1024;

export class OctokitGitHubApi implements GitHubApi {
  private readonly octokit: Octokit;

  constructor(
    token: string,
    private readonly log: (msg: string) => void = () => {},
    private readonly testing: { fetch?: typeof fetch; sleep?: (ms: number) => Promise<void> } = {},
  ) {
    this.octokit = getOctokit(token, testing.fetch ? { request: { fetch: testing.fetch } } : {});
  }

  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await withRetry(() => fn(), {
        retries: 3,
        baseDelayMs: 1000,
        maxDelayMs: 30_000,
        isRetryable: isRetryableGitHubError,
        delayFor: retryDelay,
        ...(this.testing.sleep ? { sleep: this.testing.sleep } : {}),
        onRetry: (err, attempt, delay) =>
          this.log(
            `GitHub API ${what} failed (status ${asHttpError(err).status ?? 'network'}); retry ${attempt} in ${delay}ms`,
          ),
      });
    } catch (err) {
      const e = asHttpError(err);
      throw new GitHubApiError(
        `GitHub API ${what} failed${e.status ? ` with status ${e.status}` : ''}: ${e.message ?? 'unknown error'}`,
        e.status,
      );
    }
  }

  async getPullRequest(owner: string, repo: string, number: number): Promise<RawPullRequest> {
    const res = await this.call('pulls.get', () =>
      this.octokit.rest.pulls.get({ owner, repo, pull_number: number }),
    );
    return res.data as unknown as RawPullRequest;
  }

  async listPullRequestFiles(
    owner: string,
    repo: string,
    number: number,
    limit: number,
  ): Promise<{ files: RawPullRequestFile[]; hasMore: boolean }> {
    const files: RawPullRequestFile[] = [];
    let hasMore = false;
    // GitHub returns at most 3000 files for this endpoint, 100 per page.
    for (let page = 1; page <= 30; page++) {
      const res = await this.call('pulls.listFiles', () =>
        this.octokit.rest.pulls.listFiles({
          owner,
          repo,
          pull_number: number,
          per_page: 100,
          page,
        }),
      );
      const data = res.data as unknown as RawPullRequestFile[];
      for (const f of data) {
        if (files.length >= limit) {
          hasMore = true;
          break;
        }
        files.push(f);
      }
      if (hasMore || data.length < 100) break;
      if (page === 30) hasMore = true;
    }
    return { files, hasMore };
  }

  async getTree(
    owner: string,
    repo: string,
    sha: string,
  ): Promise<{ paths: string[]; truncated: boolean }> {
    const res = await this.call('git.getTree', () =>
      this.octokit.rest.git.getTree({ owner, repo, tree_sha: sha, recursive: 'true' }),
    );
    const paths = res.data.tree
      .filter((t) => t.type === 'blob' && typeof t.path === 'string')
      .map((t) => t.path as string);
    return { paths, truncated: Boolean(res.data.truncated) };
  }

  async getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string,
  ): Promise<FileContent | null> {
    try {
      const res = await this.call('repos.getContent', () =>
        this.octokit.rest.repos.getContent({ owner, repo, path, ref }),
      );
      const data = res.data as unknown;
      if (Array.isArray(data) || typeof data !== 'object' || data === null) return null;
      const d = data as { type?: string; size?: number; content?: string; encoding?: string };
      if (d.type !== 'file') return null;
      const size = typeof d.size === 'number' ? d.size : 0;
      if (size > MAX_CONTENT_BYTES || d.encoding !== 'base64' || typeof d.content !== 'string') {
        return { text: null, size };
      }
      const buf = Buffer.from(d.content, 'base64');
      if (buf.includes(0)) return { text: null, size };
      return { text: buf.toString('utf8'), size };
    } catch (err) {
      if (err instanceof GitHubApiError && err.status === 404) return null;
      throw err;
    }
  }

  async createCheckRun(p: Parameters<GitHubApi['createCheckRun']>[0]): Promise<number> {
    const res = await this.call('checks.create', () =>
      this.octokit.rest.checks.create({
        owner: p.owner,
        repo: p.repo,
        name: p.name,
        head_sha: p.headSha,
        status: p.status,
        ...(p.conclusion ? { conclusion: p.conclusion } : {}),
        ...(p.detailsUrl ? { details_url: p.detailsUrl } : {}),
        output: p.output,
      }),
    );
    return res.data.id;
  }

  async updateCheckRun(p: Parameters<GitHubApi['updateCheckRun']>[0]): Promise<void> {
    await this.call('checks.update', () =>
      this.octokit.rest.checks.update({
        owner: p.owner,
        repo: p.repo,
        check_run_id: p.checkRunId,
        status: p.status,
        ...(p.conclusion ? { conclusion: p.conclusion } : {}),
        output: p.output,
      }),
    );
  }

  async listIssueComments(owner: string, repo: string, number: number): Promise<IssueComment[]> {
    const data = await this.call('issues.listComments', () =>
      this.octokit.paginate(this.octokit.rest.issues.listComments, {
        owner,
        repo,
        issue_number: number,
        per_page: 100,
      }),
    );
    return data.map((c) => ({
      id: c.id,
      body: c.body ?? '',
      userLogin: c.user?.login ?? '',
      userType: c.user?.type ?? '',
    }));
  }

  async createIssueComment(
    owner: string,
    repo: string,
    number: number,
    body: string,
  ): Promise<number> {
    const res = await this.call('issues.createComment', () =>
      this.octokit.rest.issues.createComment({ owner, repo, issue_number: number, body }),
    );
    return res.data.id;
  }

  async updateIssueComment(
    owner: string,
    repo: string,
    commentId: number,
    body: string,
  ): Promise<void> {
    await this.call('issues.updateComment', () =>
      this.octokit.rest.issues.updateComment({ owner, repo, comment_id: commentId, body }),
    );
  }
}
