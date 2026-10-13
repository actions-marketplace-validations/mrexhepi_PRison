import * as core from '@actions/core';
import { context } from '@actions/github';
import { OctokitGitHubApi } from './github/octokit.js';
import { run } from './main.js';
import { redactForOutput } from './utils/redact.js';

const roots = [process.env.GITHUB_WORKSPACE, process.env.RUNNER_TEMP].filter(
  (r): r is string => typeof r === 'string' && r.length > 0,
);

run({
  core: {
    getInput: (name) => core.getInput(name),
    setOutput: (name, value) => core.setOutput(name, value),
    setFailed: (message) => core.setFailed(message),
    setSecret: (secret) => core.setSecret(secret),
    info: (message) => core.info(redactForOutput(message)),
    warning: (message) => core.warning(redactForOutput(message)),
    notice: (message) => core.notice(redactForOutput(message)),
    writeSummary: async (markdown) => {
      await core.summary.addRaw(markdown).write();
    },
  },
  context: {
    eventName: context.eventName,
    repo: context.repo,
    payload: context.payload,
    runId: context.runId,
    serverUrl: context.serverUrl,
  },
  createGitHubApi: (token) => new OctokitGitHubApi(token, (m) => core.info(redactForOutput(m))),
  workspaceRoots: roots.length > 0 ? roots : [process.cwd()],
  ...(process.env.RUNNER_TEMP ? { reportDir: process.env.RUNNER_TEMP } : {}),
}).catch((err: unknown) => {
  core.setFailed(redactForOutput(err instanceof Error ? err.message : String(err)));
});
