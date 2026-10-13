/**
 * Narrow port over the GitHub REST API. The rest of the application depends only on this
 * interface so it can be tested with in-memory fakes.
 */

export interface RawPullRequest {
  number: number;
  title: string;
  body: string | null;
  draft?: boolean;
  user: { login: string } | null;
  labels: { name?: string }[];
  base: { ref: string; sha: string; repo: { full_name: string } };
  head: { ref: string; sha: string; repo: { full_name: string } | null };
  changed_files?: number;
  additions?: number;
  deletions?: number;
}

export interface RawPullRequestFile {
  filename: string;
  previous_filename?: string;
  status: string;
  additions: number;
  deletions: number;
  changes?: number;
  patch?: string;
}

export interface FileContent {
  /** Decoded UTF-8 text, or null for binary/oversized/non-file entries. */
  text: string | null;
  size: number;
}

export interface CheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: 'notice' | 'warning' | 'failure';
  title: string;
  message: string;
}

export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
  annotations?: CheckAnnotation[];
}

export type CheckConclusion = 'success' | 'failure' | 'neutral' | 'action_required';

export interface IssueComment {
  id: number;
  body: string;
  userLogin: string;
  userType: string;
}

export interface GitHubApi {
  getPullRequest(owner: string, repo: string, number: number): Promise<RawPullRequest>;
  /** Returns at most `limit` files plus whether more existed. */
  listPullRequestFiles(
    owner: string,
    repo: string,
    number: number,
    limit: number,
  ): Promise<{ files: RawPullRequestFile[]; hasMore: boolean }>;
  getTree(
    owner: string,
    repo: string,
    sha: string,
  ): Promise<{ paths: string[]; truncated: boolean }>;
  /** Returns null when the path does not exist at that ref. */
  getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string,
  ): Promise<FileContent | null>;
  createCheckRun(params: {
    owner: string;
    repo: string;
    name: string;
    headSha: string;
    status: 'in_progress' | 'completed';
    conclusion?: CheckConclusion;
    output: CheckRunOutput;
    detailsUrl?: string;
  }): Promise<number>;
  updateCheckRun(params: {
    owner: string;
    repo: string;
    checkRunId: number;
    status: 'in_progress' | 'completed';
    conclusion?: CheckConclusion;
    output: CheckRunOutput;
  }): Promise<void>;
  listIssueComments(owner: string, repo: string, number: number): Promise<IssueComment[]>;
  createIssueComment(owner: string, repo: string, number: number, body: string): Promise<number>;
  updateIssueComment(owner: string, repo: string, commentId: number, body: string): Promise<void>;
}
