import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseInputs, type ActionInputs } from './config/inputs.js';
import { parseRepoConfig, resolveSettings } from './config/load.js';
import type { Settings } from './config/schema.js';
import { isDocsOnly } from './context/priority.js';
import { collectRepositoryContext } from './context/select.js';
import type { GitHubApi } from './github/api.js';
import {
  collectPullRequest,
  resolvePullRequestRef,
  type EventContext,
  type PullRequestRef,
} from './github/pullRequest.js';
import {
  buildAnnotations,
  checkConclusion,
  checkTitle,
  renderMarkdown,
  type ReportModel,
} from './reports/render.js';
import { publishCheckRun, upsertReportComment } from './reports/publish.js';
import { evaluatePolicy, type PolicyOutcome } from './risk/policy.js';
import { runScanners } from './scanners/index.js';
import { MockDecisionProvider } from './subq/mock.js';
import { SubQClient } from './subq/client.js';
import { SubQDecisionProvider } from './subq/provider.js';
import { fitToBudget } from './subq/state.js';
import type {
  AssessmentInput,
  AssessmentResult,
  AssessmentStatus,
  ContextCompleteness,
  DecisionProvider,
} from './types.js';
import { ConfigError, ProviderError, errorMessage } from './utils/errors.js';
import { redactForOutput, registerSecret } from './utils/redact.js';
import { estimateTokens } from './utils/text.js';

/** Subset of @actions/core used by the Action, injectable for tests. */
export interface CoreLike {
  getInput(name: string): string;
  setOutput(name: string, value: string | number | boolean): void;
  setFailed(message: string): void;
  setSecret(secret: string): void;
  info(message: string): void;
  warning(message: string): void;
  notice(message: string): void;
  writeSummary(markdown: string): Promise<void>;
}

export interface RunContext extends EventContext {
  runId?: number;
  serverUrl?: string;
}

export interface RunDeps {
  core: CoreLike;
  context: RunContext;
  createGitHubApi: (token: string) => GitHubApi;
  /** Override provider construction (tests). Defaults to SubQ or mock per input. */
  createProvider?: (inputs: ActionInputs) => DecisionProvider;
  workspaceRoots: string[];
  reportDir?: string;
}

export interface RunResult {
  status: 'completed' | 'skipped' | 'error';
  outcome?: PolicyOutcome;
  ai?: { status: AssessmentStatus; result?: AssessmentResult; error?: string };
  markdown?: string;
  failed: boolean;
  failMessage?: string;
}

async function loadSettings(
  api: GitHubApi,
  ref: PullRequestRef,
  baseSha: string,
  inputs: ActionInputs,
  core: CoreLike,
): Promise<Settings> {
  // Configuration is read from the PR *base* commit, so a PR cannot weaken its own policy.
  const file = await api.getFileContent(ref.owner, ref.repo, inputs.configPath, baseSha);
  if (!file || file.text === null) {
    if (inputs.configPathExplicit) {
      throw new ConfigError(
        `Configuration file '${inputs.configPath}' was not found on the base branch.`,
      );
    }
    core.info(`No ${inputs.configPath} on the base branch; using defaults and inputs.`);
    return resolveSettings(inputs, undefined);
  }
  return resolveSettings(inputs, parseRepoConfig(file.text, inputs.configPath));
}

function defaultProvider(inputs: ActionInputs, log: (m: string) => void): DecisionProvider {
  if (inputs.provider === 'mock') return new MockDecisionProvider();
  return new SubQDecisionProvider(
    new SubQClient({ apiKey: inputs.subqApiKey, timeoutMs: inputs.timeoutSeconds * 1000, log }),
  );
}

export async function run(deps: RunDeps): Promise<RunResult> {
  const { core } = deps;
  const fail = (message: string): RunResult => {
    const safe = redactForOutput(message);
    core.setOutput('assessment-status', 'failed');
    core.setOutput('decision', 'inconclusive');
    core.setFailed(safe);
    return { status: 'error', failed: true, failMessage: safe };
  };

  let inputs: ActionInputs;
  try {
    inputs = parseInputs((n) => core.getInput(n));
  } catch (err) {
    return fail(errorMessage(err));
  }
  if (inputs.subqApiKey) {
    core.setSecret(inputs.subqApiKey);
    registerSecret(inputs.subqApiKey);
  }
  if (inputs.githubToken) registerSecret(inputs.githubToken);

  const ref = resolvePullRequestRef(deps.context);
  if ('unsupported' in ref) {
    core.warning(`SubQ PR Risk Scanner skipped: ${ref.unsupported}`);
    core.setOutput('assessment-status', 'skipped');
    core.setOutput('decision', 'inconclusive');
    return { status: 'skipped', failed: false };
  }
  if (!inputs.githubToken) return fail("Input 'github-token' is empty.");

  try {
    return await assess(deps, inputs, ref);
  } catch (err) {
    return fail(`SubQ PR Risk Scanner failed: ${errorMessage(err)}`);
  }
}

async function assess(
  deps: RunDeps,
  inputs: ActionInputs,
  ref: PullRequestRef,
): Promise<RunResult> {
  const { core } = deps;
  const api = deps.createGitHubApi(inputs.githubToken);

  const payloadBase = (
    deps.context.payload.pull_request as { base?: { sha?: unknown } } | undefined
  )?.base?.sha;
  const baseSha =
    typeof payloadBase === 'string' && /^[0-9a-f]{40}$/i.test(payloadBase)
      ? payloadBase
      : (await api.getPullRequest(ref.owner, ref.repo, ref.number)).base.sha;
  const settings = await loadSettings(api, ref, baseSha, inputs, core);
  core.info(
    `Mode ${settings.mode}, fail-on ${settings.failOn}, report ${settings.report}, dry-run ${settings.dryRun}, provider ${inputs.provider}.`,
  );

  const pr = await collectPullRequest(api, ref, {
    maxFiles: settings.maxFiles,
    maxDiffLines: settings.maxDiffLines,
    mode: settings.mode,
  });
  const meta = pr.metadata;
  core.info(`PR #${meta.number}: ${pr.files.length}/${pr.totalFiles} files, fork=${meta.isFork}.`);

  const scan = await runScanners({
    settings,
    artifacts: inputs,
    files: pr.files,
    rawPatches: pr.rawPatches,
    prTitle: meta.title,
    prBody: meta.body,
    roots: deps.workspaceRoots,
  });

  const patchTokens = pr.files.reduce((n, f) => n + (f.patch ? estimateTokens(f.patch) : 0), 0);
  const repoContext = await collectRepositoryContext(api, {
    owner: ref.owner,
    repo: ref.repo,
    headSha: meta.headSha,
    changed: pr.files,
    rawPatches: pr.rawPatches,
    mode: settings.mode,
    maxFiles: settings.contextFiles,
    tokenBudget: Math.max(0, settings.maxContextTokens - patchTokens),
    log: (m) => core.info(m),
  });

  const limitations: string[] = [];
  const withoutPatch = pr.files.filter(
    (f) => f.patch === undefined && f.additions + f.deletions > 0,
  );
  const sensitive = pr.files.filter((f) => f.sensitive).length;
  if (pr.filesTruncated) {
    limitations.push(
      `Only ${pr.files.length} of ${pr.totalFiles} changed files were retrieved (max-files or GitHub API limit).`,
    );
  }
  const budgetDropped = pr.files.filter(
    (f) => f.patchOmittedReason === 'diff_budget_exceeded',
  ).length;
  if (budgetDropped)
    limitations.push(
      `${budgetDropped} file patch(es) exceeded max-diff-lines and were not sent to the model.`,
    );
  const binary = pr.files.filter((f) => f.patchOmittedReason === 'binary_or_too_large').length;
  if (binary)
    limitations.push(
      `${binary} file(s) had no textual patch (binary or too large); they were not analyzed.`,
    );
  if (sensitive)
    limitations.push(
      `${sensitive} sensitive file(s) were scanned locally but excluded from the model context.`,
    );
  if (pr.malformedPatches.length)
    limitations.push(`${pr.malformedPatches.length} patch(es) could not be fully parsed.`);
  if (repoContext.treeTruncated)
    limitations.push('Repository tree listing was truncated; context selection may be incomplete.');
  if (repoContext.omitted.length)
    limitations.push(
      `${repoContext.omitted.length} candidate context file(s) were omitted (limits or availability).`,
    );

  let completeness: ContextCompleteness = {
    totalFiles: pr.totalFiles,
    filesAnalyzed: pr.files.filter((f) => f.patch !== undefined || f.additions + f.deletions === 0)
      .length,
    filesWithoutPatch: withoutPatch.length,
    sensitiveFilesExcluded: sensitive,
    diffLinesTotal: pr.diffLinesTotal,
    diffLinesIncluded: pr.diffLinesIncluded,
    contextFilesIncluded: repoContext.files.length,
    contextFilesOmitted: repoContext.omitted.length,
    truncated: pr.filesTruncated || budgetDropped > 0,
    limitations,
  };

  let assessmentInput: AssessmentInput = {
    pullRequest: meta,
    changedFiles: pr.files,
    repositoryContext: repoContext,
    scannerFindings: scan.findings,
    policy: {
      mode: settings.mode,
      protectedPaths: settings.protectedPaths,
      requireReviewFor: settings.requireReviewFor,
      conventions: settings.conventions,
    },
    contextCompleteness: completeness,
  };
  assessmentInput = fitToBudget(assessmentInput);
  completeness = assessmentInput.contextCompleteness;

  // ---- AI assessment
  let ai: { status: AssessmentStatus; result?: AssessmentResult; error?: string };
  let missingTokenFailure: string | undefined;
  const provider = deps.createProvider ?? ((i) => defaultProvider(i, (m) => core.info(m)));
  const paths = pr.files.map((f) => f.path);
  if (pr.files.length === 0) {
    ai = { status: 'not_required', error: 'no changed files' };
  } else if (isDocsOnly(paths) && scan.findings.length === 0 && !completeness.truncated) {
    ai = { status: 'not_required', error: 'documentation-only change with no findings' };
  } else if (inputs.provider === 'subq' && !inputs.subqApiKey) {
    if (meta.isFork) {
      ai = {
        status: 'skipped',
        error:
          'SubQ API key unavailable: GitHub does not pass secrets to workflows triggered by forked PRs',
      };
    } else {
      ai = { status: 'failed', error: 'subq-api-key is empty' };
      missingTokenFailure =
        "Input 'subq-api-key' is empty. Store your SubQ token as the repository secret SUBQ_API_KEY and pass `subq-api-key: ${{ secrets.SUBQ_API_KEY }}`.";
    }
  } else {
    try {
      const result = await provider(inputs).assess(assessmentInput);
      ai = { status: 'completed', result };
      core.info(
        `AI assessment: ${result.riskLevel} (${result.riskScore}/100) in ${result.latencyMs}ms.`,
      );
    } catch (err) {
      const msg =
        err instanceof ProviderError
          ? err.message
          : `unexpected provider error: ${errorMessage(err)}`;
      ai = { status: 'failed', error: redactForOutput(msg) };
      core.warning(`AI assessment failed: ${ai.error}`);
    }
  }

  const outcome = evaluatePolicy({
    settings,
    findings: scan.findings,
    files: pr.files,
    completeness,
    scannerStatuses: scan.statuses,
    ai,
  });
  if (missingTokenFailure) {
    outcome.fail = true;
    outcome.failReason = missingTokenFailure;
  }

  // ---- Reporting
  const runUrl =
    deps.context.serverUrl && deps.context.runId
      ? `${deps.context.serverUrl}/${ref.owner}/${ref.repo}/actions/runs/${deps.context.runId}`
      : undefined;
  const model: ReportModel = {
    outcome,
    ai: { ...ai, provider: inputs.provider },
    findings: scan.findings,
    scannerStatuses: scan.statuses,
    completeness,
    includeAiExplanation: settings.includeAiExplanation,
    dryRun: settings.dryRun,
    outsideDiffFindings: scan.outsideDiff,
    ...(runUrl ? { runUrl } : {}),
  };
  const markdown = renderMarkdown(model);
  try {
    await core.writeSummary(markdown);
  } catch (err) {
    core.warning(`Could not write job summary: ${errorMessage(err)}`);
  }

  if (settings.report === 'check' || settings.report === 'both') {
    const res = await publishCheckRun(api, {
      owner: ref.owner,
      repo: ref.repo,
      headSha: meta.headSha,
      conclusion: checkConclusion(outcome),
      title: checkTitle(model),
      summary: markdown,
      annotations: settings.includeFileAnnotations
        ? buildAnnotations(scan.findings, pr.annotatableLines)
        : [],
      ...(runUrl ? { detailsUrl: runUrl } : {}),
    });
    if (res.id) core.setOutput('check-run-id', res.id);
    if (res.warning) core.warning(res.warning);
  }
  if (settings.report === 'comment' || settings.report === 'both') {
    const res = await upsertReportComment(api, {
      owner: ref.owner,
      repo: ref.repo,
      number: meta.number,
      body: markdown,
    });
    if (res.id) core.setOutput('comment-id', res.id);
    if (res.warning) core.warning(res.warning);
  }

  // ---- Outputs
  core.setOutput('decision', outcome.decision);
  core.setOutput('effective-risk-level', outcome.effectiveLevel);
  core.setOutput('ai-risk-score', ai.result ? String(ai.result.riskScore) : '');
  core.setOutput('ai-risk-level', ai.result?.riskLevel ?? '');
  core.setOutput('assessment-status', ai.status);
  core.setOutput('findings-count', scan.findings.length);
  core.setOutput('requires-review', outcome.requiresReview);
  core.setOutput('context-complete', !completeness.truncated);

  if (deps.reportDir) {
    const reportPath = join(deps.reportDir, `subq-pr-risk-report-${meta.number}.json`);
    const json = {
      decision: outcome.decision,
      effectiveRiskLevel: outcome.effectiveLevel,
      deterministicRiskLevel: outcome.deterministicLevel,
      ai: { status: ai.status, provider: inputs.provider, error: ai.error, result: ai.result },
      reasons: outcome.reasons,
      findings: scan.findings,
      scanners: scan.statuses,
      completeness,
      dryRun: settings.dryRun,
    };
    try {
      await writeFile(reportPath, redactForOutput(JSON.stringify(json, null, 2)), 'utf8');
      core.setOutput('report-path', reportPath);
    } catch (err) {
      core.warning(`Could not write JSON report: ${errorMessage(err)}`);
    }
  }

  if (outcome.fail) {
    core.setFailed(redactForOutput(outcome.failReason ?? 'SubQ PR Risk Assessment failed.'));
  } else if (outcome.dryRunSuppressed) {
    core.notice('dry-run: the pull request would have been blocked by policy.');
  }

  return {
    status: 'completed',
    outcome,
    ai,
    markdown,
    failed: outcome.fail,
    ...(outcome.failReason ? { failMessage: outcome.failReason } : {}),
  };
}
