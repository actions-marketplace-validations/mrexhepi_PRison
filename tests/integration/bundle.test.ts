import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BASE_SHA, HEAD_SHA, addPatch } from '../helpers.js';

const root = join(import.meta.dirname, '..', '..');
const bundle = join(root, 'dist', 'index.js');

/**
 * Runs the committed bundle as a separate Node process, exactly like the Actions runner
 * does (`node dist/index.js`), against a local fake of the GitHub REST API. Proves the
 * artifact is self-contained and that inputs/outputs/check publishing work end to end.
 */
describe.skipIf(!existsSync(bundle))('dist/index.js end to end', () => {
  const requests: { method: string; url: string; body: string }[] = [];
  let baseUrl = '';
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => {
      requests.push({ method: req.method ?? '', url: req.url ?? '', body });
      const send = (status: number, data: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(data));
      };
      const url = req.url ?? '';
      if (url.startsWith('/repos/acme/app/pulls/7/files')) {
        return send(200, [
          {
            filename: 'infra/prod/sg.tf',
            status: 'modified',
            additions: 1,
            deletions: 0,
            patch: addPatch(['  cidr_blocks = ["0.0.0.0/0"]'], 5),
          },
        ]);
      }
      if (url.startsWith('/repos/acme/app/pulls/7')) {
        return send(200, {
          number: 7,
          title: 'Open SSH',
          body: '',
          user: { login: 'dev' },
          labels: [],
          base: { ref: 'main', sha: BASE_SHA, repo: { full_name: 'acme/app' } },
          head: { ref: 'f', sha: HEAD_SHA, repo: { full_name: 'acme/app' } },
          changed_files: 1,
        });
      }
      if (url.startsWith('/repos/acme/app/git/trees/'))
        return send(200, { tree: [], truncated: false });
      if (url.startsWith('/repos/acme/app/contents/')) return send(404, { message: 'Not Found' });
      if (url.startsWith('/repos/acme/app/check-runs') && req.method === 'POST')
        return send(201, { id: 42 });
      return send(404, { message: `unhandled ${url}` });
    });
  });

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('runs without node_modules and publishes a check', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'subq-bundle-'));
    const event = join(dir, 'event.json');
    const output = join(dir, 'output.txt');
    const summary = join(dir, 'summary.md');
    writeFileSync(event, JSON.stringify({ pull_request: { number: 7, base: { sha: BASE_SHA } } }));
    writeFileSync(output, '');
    writeFileSync(summary, '');

    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_EVENT_PATH: event,
      GITHUB_REPOSITORY: 'acme/app',
      GITHUB_API_URL: baseUrl,
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_RUN_ID: '1',
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_WORKSPACE: dir,
      RUNNER_TEMP: dir,
      'INPUT_GITHUB-TOKEN': 'ghs_local_test_token',
      INPUT_PROVIDER: 'mock',
      'INPUT_FAIL-ON': 'high',
      'INPUT_DRY-RUN': 'false',
    };
    // Run from a directory without node_modules.
    const result = await new Promise<{ code: number | null; stdout: string }>((resolve) => {
      execFile(process.execPath, [bundle], { env, cwd: dir, timeout: 30_000 }, (err, stdout) => {
        resolve({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout });
      });
    });

    const outputs = readFileSync(output, 'utf8');
    expect(outputs).toMatch(/decision<<[\s\S]*blocked/);
    expect(outputs).toMatch(/assessment-status<<[\s\S]*completed/);
    expect(result.code).toBe(1); // fail-on: high and the finding is high
    expect(result.stdout).toContain('::error::Pull request blocked by risk policy.');
    expect(result.stdout).not.toContain('ghs_local_test_token');
    const check = requests.find((r) => r.method === 'POST' && r.url.includes('check-runs'));
    expect(check).toBeDefined();
    const payload = JSON.parse(check!.body) as {
      conclusion: string;
      output: { annotations: { path: string; start_line: number }[] };
    };
    expect(payload.conclusion).toBe('failure');
    expect(payload.output.annotations.length).toBeGreaterThan(0);
    for (const a of payload.output.annotations) {
      expect(a).toMatchObject({ path: 'infra/prod/sg.tf', start_line: 5 });
    }
    expect(readFileSync(summary, 'utf8')).toContain('MOCK provider');
    expect(
      requests.some(
        (r) =>
          r.url.includes(`/contents/.github%2Fsubq-pr-risk.yml?ref=${BASE_SHA}`) ||
          r.url.includes(`/contents/.github/subq-pr-risk.yml?ref=${BASE_SHA}`),
      ),
    ).toBe(true);
  });
});
