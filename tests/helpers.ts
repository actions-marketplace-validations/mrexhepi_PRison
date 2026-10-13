import type { FetchLike } from '../src/subq/client.js';
import { SubQClient } from '../src/subq/client.js';
import { SubQDecisionProvider } from '../src/subq/provider.js';
import type { Question } from '../src/subq/api.js';
import type {
  CheckRunOutput,
  FileContent,
  GitHubApi,
  IssueComment,
  RawPullRequest,
  RawPullRequestFile,
} from '../src/github/api.js';
import type { CoreLike, RunDeps } from '../src/main.js';
import type { DecisionProvider } from '../src/types.js';

export const BASE_SHA = 'a'.repeat(40);
export const HEAD_SHA = 'b'.repeat(40);

export function rawPr(overrides: Partial<RawPullRequest> = {}): RawPullRequest {
  return {
    number: 7,
    title: 'Update service',
    body: 'Routine change.',
    draft: false,
    user: { login: 'dev' },
    labels: [],
    base: { ref: 'main', sha: BASE_SHA, repo: { full_name: 'acme/app' } },
    head: { ref: 'feature', sha: HEAD_SHA, repo: { full_name: 'acme/app' } },
    changed_files: undefined,
    additions: 0,
    deletions: 0,
    ...overrides,
  };
}

export function file(
  filename: string,
  patch: string | undefined,
  extra: Partial<RawPullRequestFile> = {},
): RawPullRequestFile {
  const lines = patch?.split('\n') ?? [];
  return {
    filename,
    status: 'modified',
    additions: lines.filter((l) => l.startsWith('+')).length,
    deletions: lines.filter((l) => l.startsWith('-')).length,
    ...(patch !== undefined ? { patch } : {}),
    ...extra,
  };
}

/** Build a patch that adds the given lines at the top of a file. */
export function addPatch(lines: string[], start = 1): string {
  return [`@@ -${start},0 +${start},${lines.length} @@`, ...lines.map((l) => `+${l}`)].join('\n');
}

export function delPatch(lines: string[], start = 1): string {
  return [`@@ -${start},${lines.length} +${start},0 @@`, ...lines.map((l) => `-${l}`)].join('\n');
}

export class FakeGitHub implements GitHubApi {
  pr: RawPullRequest;
  files: RawPullRequestFile[];
  tree: string[] = [];
  treeTruncated = false;
  contents = new Map<string, string>();
  checkRuns: { conclusion?: string; output: CheckRunOutput; name: string }[] = [];
  comments: IssueComment[] = [];
  failChecks = false;
  failComments = false;
  calls: string[] = [];

  constructor(pr: RawPullRequest, files: RawPullRequestFile[]) {
    this.pr = pr;
    this.files = files;
  }

  setContent(ref: string, path: string, text: string): this {
    this.contents.set(`${ref}:${path}`, text);
    return this;
  }

  async getPullRequest(): Promise<RawPullRequest> {
    this.calls.push('getPullRequest');
    return this.pr;
  }
  async listPullRequestFiles(_o: string, _r: string, _n: number, limit: number) {
    this.calls.push('listPullRequestFiles');
    return { files: this.files.slice(0, limit), hasMore: this.files.length > limit };
  }
  async getTree() {
    this.calls.push('getTree');
    return { paths: this.tree, truncated: this.treeTruncated };
  }
  async getFileContent(
    _o: string,
    _r: string,
    path: string,
    ref: string,
  ): Promise<FileContent | null> {
    this.calls.push(`getFileContent:${ref.slice(0, 1)}:${path}`);
    const text = this.contents.get(`${ref}:${path}`);
    return text === undefined ? null : { text, size: text.length };
  }
  async createCheckRun(p: Parameters<GitHubApi['createCheckRun']>[0]): Promise<number> {
    if (this.failChecks)
      throw Object.assign(new Error('Resource not accessible by integration'), { status: 403 });
    this.checkRuns.push({
      name: p.name,
      ...(p.conclusion ? { conclusion: p.conclusion } : {}),
      output: p.output,
    });
    return 100 + this.checkRuns.length;
  }
  async updateCheckRun(): Promise<void> {}
  async listIssueComments(): Promise<IssueComment[]> {
    if (this.failComments) throw Object.assign(new Error('forbidden'), { status: 403 });
    return this.comments;
  }
  async createIssueComment(_o: string, _r: string, _n: number, body: string): Promise<number> {
    const id = 500 + this.comments.length;
    this.comments.push({ id, body, userLogin: 'github-actions[bot]', userType: 'Bot' });
    return id;
  }
  async updateIssueComment(_o: string, _r: string, id: number, body: string): Promise<void> {
    const c = this.comments.find((x) => x.id === id);
    if (c) c.body = body;
  }
}

export interface FakeCore extends CoreLike {
  outputs: Record<string, string>;
  failed?: string;
  logs: string[];
  summary: string;
  secrets: string[];
}

export function fakeCore(inputs: Record<string, string>): FakeCore {
  const c: FakeCore = {
    outputs: {},
    logs: [],
    summary: '',
    secrets: [],
    getInput: (name) => inputs[name] ?? '',
    setOutput: (name, value) => {
      c.outputs[name] = String(value);
    },
    setFailed: (m) => {
      c.failed = m;
      c.logs.push(`error: ${m}`);
    },
    setSecret: (s) => {
      c.secrets.push(s);
    },
    info: (m) => {
      c.logs.push(`info: ${m}`);
    },
    warning: (m) => {
      c.logs.push(`warning: ${m}`);
    },
    notice: (m) => {
      c.logs.push(`notice: ${m}`);
    },
    writeSummary: async (md) => {
      c.summary += md;
    },
  };
  return c;
}

export function deps(
  gh: FakeGitHub,
  core: FakeCore,
  provider?: DecisionProvider,
  extra: Partial<RunDeps> = {},
): RunDeps {
  return {
    core,
    context: {
      eventName: 'pull_request',
      repo: { owner: 'acme', repo: 'app' },
      payload: { pull_request: { number: gh.pr.number, base: { sha: BASE_SHA } } as never },
      runId: 1,
      serverUrl: 'https://github.com',
    },
    createGitHubApi: () => gh,
    ...(provider ? { createProvider: () => provider } : {}),
    workspaceRoots: [process.cwd()],
    ...extra,
  };
}

export const DEFAULT_INPUTS = {
  'subq-api-key': 'sk-test-0123456789abcdef0123456789abcdef',
  'github-token': 'ghs_faketoken',
  provider: 'subq',
};

// ---------------------------------------------------------------- Fake SubQ HTTP

export interface FakeSubQOptions {
  overall?: number;
  noul?: Record<string, number>;
  defaultNoul?: number;
  action?: string;
  status?: number;
  errorBody?: unknown;
  rawBody?: string;
  mutate?: (body: Record<string, unknown>) => void;
  delayMs?: number;
}

export interface FakeSubQ {
  fetch: FetchLike;
  requests: { url: string; headers: Record<string, string>; body: Record<string, unknown> }[];
}

/** A fake of the documented SubQ Decisions API (POST /v1/systemone). */
export function fakeSubQ(opts: FakeSubQOptions = {}): FakeSubQ {
  const requests: FakeSubQ['requests'] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const body = JSON.parse(String(init.body)) as { questions: Record<string, Question> };
    requests.push({ url, headers: init.headers as Record<string, string>, body: body as never });
    if (opts.delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, opts.delayMs);
        init.signal?.addEventListener('abort', () => {
          clearTimeout(t);
          reject(
            Object.assign(new Error('The operation was aborted due to timeout'), {
              name: 'TimeoutError',
            }),
          );
        });
      });
    }
    if (opts.status && opts.status !== 200) {
      return new Response(
        JSON.stringify(opts.errorBody ?? { detail: { error_type: 'error', message: 'nope' } }),
        {
          status: opts.status,
        },
      );
    }
    if (opts.rawBody !== undefined) return new Response(opts.rawBody, { status: 200 });
    const answers: Record<string, unknown> = {};
    for (const [name, q] of Object.entries(body.questions)) {
      if (q.type === 'score') {
        const score = opts.overall ?? 0;
        answers[name] = {
          type: 'score',
          score,
          legend: Object.fromEntries(q.criteria.map((c, i) => [String(i), c])),
          probabilities: Object.fromEntries(
            q.criteria.map((_c, i) => [String(i), i === Math.round(score) ? 1 : 0]),
          ),
          confidence: 0.8,
        };
      } else if (q.type === 'choice') {
        const choice = opts.action ?? Object.keys(q.criteria)[0]!;
        answers[name] = {
          type: 'choice',
          choice,
          probabilities: Object.fromEntries(
            Object.keys(q.criteria).map((k) => [k, k === choice ? 1 : 0]),
          ),
          confidence: 0.9,
        };
      } else {
        answers[name] = { type: 'noul', noul: opts.noul?.[name] ?? opts.defaultNoul ?? 0.1 };
      }
    }
    const res: Record<string, unknown> = {
      model: 'subq-snap-preview',
      answers,
      usage: { input_tokens: 12345, output_tokens: 0 },
    };
    opts.mutate?.(res);
    return new Response(JSON.stringify(res), { status: 200 });
  };
  return { fetch: fetchImpl, requests };
}

export function subqProvider(fake: FakeSubQ, extra: { timeoutMs?: number; retries?: number } = {}) {
  return new SubQDecisionProvider(
    new SubQClient({
      apiKey: DEFAULT_INPUTS['subq-api-key'],
      fetch: fake.fetch,
      sleep: async () => {},
      timeoutMs: extra.timeoutMs ?? 5000,
      retries: extra.retries ?? 2,
    }),
  );
}
