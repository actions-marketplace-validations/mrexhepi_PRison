import { describe, expect, it } from 'vitest';
import { OctokitGitHubApi, isRetryableGitHubError } from '../../src/github/octokit.js';

type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

function api(handler: Handler) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
    );
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}${url.search}`);
    return handler(url, init ?? {});
  }) as typeof fetch;
  return {
    gh: new OctokitGitHubApi('t', () => {}, { fetch: fetchImpl, sleep: async () => {} }),
    calls,
  };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

describe('OctokitGitHubApi', () => {
  it('paginates PR files and respects the limit', async () => {
    const page = (n: number) =>
      Array.from({ length: 100 }, (_, i) => ({
        filename: `f${n}-${i}`,
        status: 'modified',
        additions: 1,
        deletions: 0,
      }));
    const { gh, calls } = api((url) => json(page(Number(url.searchParams.get('page')))));
    const r = await gh.listPullRequestFiles('o', 'r', 1, 150);
    expect(r.files).toHaveLength(150);
    expect(r.hasMore).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('returns null for missing files and binary/oversized content', async () => {
    const { gh } = api((url) => {
      if (url.pathname.endsWith('/missing')) return json({ message: 'Not Found' }, 404);
      if (url.pathname.endsWith('/bin'))
        return json({
          type: 'file',
          size: 3,
          encoding: 'base64',
          content: Buffer.from([0, 1, 2]).toString('base64'),
        });
      if (url.pathname.endsWith('/dir')) return json([]);
      return json({
        type: 'file',
        size: 5,
        encoding: 'base64',
        content: Buffer.from('hello').toString('base64'),
      });
    });
    expect(await gh.getFileContent('o', 'r', 'missing', 'sha')).toBeNull();
    expect(await gh.getFileContent('o', 'r', 'bin', 'sha')).toEqual({ text: null, size: 3 });
    expect(await gh.getFileContent('o', 'r', 'dir', 'sha')).toBeNull();
    expect(await gh.getFileContent('o', 'r', 'ok', 'sha')).toEqual({ text: 'hello', size: 5 });
  });

  it('retries transient errors and gives up on permission errors', async () => {
    let n = 0;
    const flaky = api(() =>
      ++n < 3
        ? json({ message: 'bad gateway' }, 502)
        : json({ tree: [{ type: 'blob', path: 'a' }], truncated: false }),
    );
    expect(await flaky.gh.getTree('o', 'r', 'sha')).toEqual({ paths: ['a'], truncated: false });
    expect(n).toBe(3);

    const denied = api(() => json({ message: 'Resource not accessible by integration' }, 403));
    await expect(
      denied.gh.createCheckRun({
        owner: 'o',
        repo: 'r',
        name: 'n',
        headSha: 's',
        status: 'completed',
        conclusion: 'success',
        output: { title: 't', summary: 's' },
      }),
    ).rejects.toMatchObject({ status: 403 });
    expect(denied.calls).toHaveLength(1);
  });

  it('classifies retryable errors', () => {
    expect(isRetryableGitHubError({ status: 500 })).toBe(true);
    expect(isRetryableGitHubError({ status: 429 })).toBe(true);
    expect(
      isRetryableGitHubError({
        status: 403,
        response: { headers: { 'x-ratelimit-remaining': '0' } },
      }),
    ).toBe(true);
    expect(isRetryableGitHubError({ status: 403, response: { headers: {} } })).toBe(false);
    expect(isRetryableGitHubError({ status: 404 })).toBe(false);
    expect(isRetryableGitHubError(new Error('socket hang up'))).toBe(true);
  });

  it('maps comments and creates/updates them', async () => {
    const { gh, calls } = api((url, init) => {
      if (init.method === 'POST') return json({ id: 9 }, 201);
      if (init.method === 'PATCH') return json({ id: 9 });
      return json([{ id: 1, body: 'x', user: { login: 'github-actions[bot]', type: 'Bot' } }]);
    });
    expect(await gh.listIssueComments('o', 'r', 1)).toEqual([
      { id: 1, body: 'x', userLogin: 'github-actions[bot]', userType: 'Bot' },
    ]);
    expect(await gh.createIssueComment('o', 'r', 1, 'b')).toBe(9);
    await gh.updateIssueComment('o', 'r', 9, 'b');
    expect(calls.some((c) => c.startsWith('PATCH /repos/o/r/issues/comments/9'))).toBe(true);
  });
});
