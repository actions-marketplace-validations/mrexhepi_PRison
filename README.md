# SubQ PR Risk Scanner

A GitHub Action that decides which pull requests deserve extra scrutiny. It combines
deterministic change rules, your existing scanner results (Gitleaks, Checkov, SARIF, npm
audit) and structured decisions from **SubQ Snap** (`subq-snap-preview`), then publishes a
GitHub Check with evidence, recommended actions and an enforceable decision.

```yaml
- uses: mrexhepi/PRison@v1
  with:
    subq-api-key: ${{ secrets.SUBQ_API_KEY }}
```

> **Status:** v1, early release. The SubQ integration follows the published SubQ
> Decisions API contract, but it has **not yet been exercised against the live SubQ API**
> by this project (no API key was available during development). All tests use a fake of
> the documented contract. See [Known limitations](#known-limitations).

> **Background:** PRison started as an experimental project for trying out
> [SubQ](https://subq.ai) and its Snap Decisions API on a real use case: pull request risk
> review. It is a personal side project, not an official SubQ product.

## Contents

1. [Overview](#overview)
2. [Features and limitations](#features-and-limitations)
3. [Architecture](#architecture)
4. [Requirements](#requirements)
5. [Get a SubQ API key](#get-a-subq-api-key)
6. [Store the key as a GitHub secret](#store-the-key-as-a-github-secret)
7. [Quick start](#quick-start)
8. [Inputs and outputs](#inputs-and-outputs)
9. [Repository configuration](#repository-configuration)
10. [Risk score and policy semantics](#risk-score-and-policy-semantics)
11. [Terraform and security examples](#terraform-and-security-examples)
12. [SARIF and scanner integration](#sarif-and-scanner-integration)
13. [Permissions and forked pull requests](#permissions-and-forked-pull-requests)
14. [Privacy and data handling](#privacy-and-data-handling)
15. [Trust model](#trust-model)
16. [Troubleshooting](#troubleshooting)
17. [Local development and testing](#local-development-and-testing)
18. [Build and release](#build-and-release)
19. [Version pinning](#version-pinning)
20. [Contributing](#contributing)
21. [License](#license)

## Overview

Most AI review tools generate prose about a diff. This Action instead asks a fast decision
model a fixed set of typed questions (overall risk level, per-category risk, whether a
human must review, and whether each flagged change is a real risk in context) and combines
the answers with deterministic evidence under a policy the model cannot override.

For every pull request it:

1. Reads PR metadata and the diff through the GitHub API (no checkout, no PR code executed).
2. Runs built-in change rules and a secret detector on the raw diff, locally.
3. Ingests optional scanner artifacts produced by trusted earlier steps.
4. Selects a bounded, redacted set of repository context (for Terraform: sibling module
   files, local module interfaces; related tests; dependency manifests; CODEOWNERS).
5. Calls SubQ Snap once with the redacted diff, context and findings.
6. Applies the deterministic policy from `.github/subq-pr-risk.yml` (read from the **base**
   commit) and inputs.
7. Publishes a Check Run (with inline annotations), optionally a single PR comment that is
   updated in place, a job summary and a JSON report.

## Features and limitations

### Implemented

| Area                                                                                                                                                                                                                                                                                                                                                                  | Status                                                        |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| SubQ Snap Decisions API adapter (`POST /v1/systemone`) with timeouts, bounded retries, strict response validation                                                                                                                                                                                                                                                     | Implemented, tested against a fake of the documented contract |
| Mock provider (`provider: mock`), always labeled in reports                                                                                                                                                                                                                                                                                                           | Implemented                                                   |
| Built-in change rules: IAM, security groups / open CIDR, public access, encryption, TLS, IMDSv1, destructive Terraform, removed resources, migrations / destructive SQL, workflow risks, auth code, injection sinks, health checks, availability, timeouts, monitoring, audit logging, dependency changes, exported API removal, missing tests, prompt-injection text | Implemented                                                   |
| Built-in secret detector (AWS, GitHub, Slack, Stripe, Google keys, private keys, JWTs, URL credentials, secret assignments)                                                                                                                                                                                                                                           | Implemented                                                   |
| Gitleaks JSON, Checkov JSON, SARIF 2.1.0 (CodeQL, Semgrep, Trivy, ...), `npm audit --json` ingestion                                                                                                                                                                                                                                                                  | Implemented                                                   |
| Finding normalization and cross-source deduplication                                                                                                                                                                                                                                                                                                                  | Implemented                                                   |
| Context selection with mode-aware prioritization, token budgeting and omission reporting                                                                                                                                                                                                                                                                              | Implemented                                                   |
| Redaction of secrets and exclusion of sensitive files before any API call                                                                                                                                                                                                                                                                                             | Implemented                                                   |
| Deterministic policy engine, `fail-on`, `dry-run`, `provider-error-policy`, protected paths, review triggers                                                                                                                                                                                                                                                          | Implemented                                                   |
| Check Run with annotations, single updatable PR comment, job summary, JSON report                                                                                                                                                                                                                                                                                     | Implemented                                                   |
| Labeled evaluation dataset and metrics script                                                                                                                                                                                                                                                                                                                         | Implemented (synthetic fixtures)                              |

### Not implemented (planned)

- Running scanners inside the Action. The Action only **consumes** artifacts.
- Dependency formats other than `npm audit` (use SARIF from Trivy/Grype/OSV instead).
- Reading other CI check results for the head commit.
- Terraform plan JSON ingestion.
- Additional decision providers (the `DecisionProvider` interface is ready for them).

### Known limitations

- **Live API not yet verified.** The request/response handling follows
  [docs.subq.ai/endpoints/decisions-api](https://docs.subq.ai/endpoints/decisions-api/)
  as published on 2026-10-13. SubQ Snap is in **public preview**; the contract may change.
  Rate-limit values and a `Retry-After` header are not documented; the client honors
  `Retry-After` if present and otherwise uses exponential backoff.
- SubQ Snap returns probabilities, not prose. The report summary is generated
  deterministically from those probabilities; the Action never shows model-written text.
- Built-in rules are pattern based. They produce `plausible` findings that need a human;
  only high-precision secret formats produce `confirmed` findings.
- Evaluation numbers in this repository come from synthetic fixtures written alongside the
  rules. They are a regression signal, **not** evidence of real-world accuracy.

## Architecture

```text
src/
  index.ts              entry point: wires @actions/core and @actions/github into main.run()
  main.ts               orchestration
  config/               input parsing, strict YAML config schema, precedence rules
  github/               narrow GitHubApi port, Octokit adapter (retry/rate-limit), PR collection
  context/              diff parsing, file prioritization, bounded context selection
  scanners/             built-in rules, artifact readers (path-safe), parsers, dedupe
  subq/                 Decisions API schema, HTTP client, questions, state, provider, mock
  risk/                 score bands and the deterministic policy engine
  reports/              markdown escaping, report rendering, check/comment publishing
  utils/                redaction, retry, errors
```

Data flow:

```text
GitHub API ──> PR metadata + patches ──> rules + secret detector (raw diff, local only)
                     │                            │
                     ▼                            ▼
             redaction + budget          scanner artifacts (trusted steps)
                     │                            │
                     └──────> SubQ Snap <─────────┘  (redacted state, 1 request)
                                  │
                                  ▼
                     deterministic policy engine ──> Check Run / comment / summary / outputs
```

## Requirements

- GitHub-hosted or self-hosted runners that support `node24` JavaScript actions.
- A SubQ account with API access to `subq-snap-preview`, and credits.
- Workflow permissions: `contents: read`, `checks: write` (for the Check Run) and
  `pull-requests: write` only if you enable comments.

## Get a SubQ API key

1. Sign in to the SubQ console at [console.subq.ai](https://console.subq.ai).
2. Create an API key. Keys are shown **once** at creation and cannot be retrieved later.
3. Make sure the key's organization has access to `subq-snap-preview` and has credits
   (a request without credits returns HTTP 402).

Each consumer uses **their own** key. Requests go directly from your runner to
`https://api.subq.ai/v1`; there is no proxy and the maintainer's key is never used.

## Store the key as a GitHub secret

1. Open your repository on GitHub.
2. Go to **Settings -> Secrets and variables -> Actions**.
3. Click **New repository secret**.
4. Name: `SUBQ_API_KEY`. Value: your SubQ API key.
5. Save. (Organization secrets work too.)
6. Add the workflow below.
7. Open a test pull request and look for the **SubQ PR Risk Assessment** check.

Never paste the key into workflow YAML. Reference it as `${{ secrets.SUBQ_API_KEY }}`.

**Rotation and revocation:** create a new key in the SubQ console, update the
`SUBQ_API_KEY` secret, then revoke the old key in the console. If a key may have leaked,
revoke it immediately; workflows will fail clearly with `SubQ rejected the API key (401)`
until the secret is updated.

## Quick start

`.github/workflows/subq-pr-risk.yml`:

```yaml
name: SubQ PR Risk Assessment

on:
  pull_request:
    types:
      - opened
      - synchronize
      - reopened
      - ready_for_review

permissions:
  contents: read
  checks: write
  pull-requests: write # only needed for report: comment or both

jobs:
  risk-assessment:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Assess pull request risk
        uses: mrexhepi/PRison@v1
        with:
          subq-api-key: ${{ secrets.SUBQ_API_KEY }}
          mode: terraform
          fail-on: high
          report: both
```

No `actions/checkout` step is required: the Action reads the PR through the API. More
examples live in [`examples/`](examples/).

## Inputs and outputs

### Inputs

| Input                   | Default                    | Description                                                                                                        |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `subq-api-key`          | empty                      | Your SubQ API key from a secret. Required for real assessments (see fork behavior).                                |
| `github-token`          | `github.token`             | Token for reading the PR and publishing checks/comments.                                                           |
| `config`                | `.github/subq-pr-risk.yml` | Policy file path, read from the PR base commit. Missing default file is fine; a missing explicit path is an error. |
| `mode`                  | `general`                  | `general`, `terraform`, `security` or `dependencies`. Changes prioritization and context selection.                |
| `fail-on`               | `never`                    | `never`, `medium`, `high` or `critical`. Fail the step when the effective risk reaches this level.                 |
| `ai-mode`               | `decide`                   | `decide`: SubQ can raise risk and request review. `advisory`: SubQ is reported only; rules and scanners decide.    |
| `report`                | `check`                    | `check`, `comment` or `both`. A job summary is always written.                                                     |
| `max-files`             | `200`                      | Maximum changed files to retrieve (1-3000).                                                                        |
| `max-diff-lines`        | `12000`                    | Maximum changed lines sent to the model.                                                                           |
| `context-files`         | `10`                       | Maximum additional repository files sent as context (0-100).                                                       |
| `dry-run`               | `false`                    | Report decisions without failing the step on risk.                                                                 |
| `provider-error-policy` | `require-review`           | `fail`, `warn` or `require-review` when the AI assessment cannot complete.                                         |
| `provider`              | `subq`                     | `subq` or `mock`. `mock` is for testing; every report is labeled.                                                  |
| `timeout-seconds`       | `60`                       | Timeout per SubQ request (5-600). Up to 2 retries for 429/5xx/timeouts.                                            |
| `gitleaks-report`       | empty                      | Gitleaks JSON report path.                                                                                         |
| `checkov-report`        | empty                      | Checkov JSON report path.                                                                                          |
| `sarif-files`           | empty                      | SARIF file paths or globs, newline or comma separated.                                                             |
| `dependency-report`     | empty                      | `npm audit --json` output path.                                                                                    |

Defaults shown for `mode`, `fail-on`, `ai-mode`, `report`, `max-files`, `max-diff-lines`,
`context-files` and `provider-error-policy` are applied by the Action (the `action.yml`
defaults are empty) so the repository configuration can supply them.

**Precedence:** explicit Action input > `.github/subq-pr-risk.yml` (from the base commit) >
built-in default. Nothing returned by the model can change any setting.

### Outputs

| Output                       | Description                                                                       |
| ---------------------------- | --------------------------------------------------------------------------------- |
| `decision`                   | `pass`, `review_required`, `blocked` or `inconclusive`                            |
| `go`                         | GO / NO GO: `true` only when `decision` is `pass`                                 |
| `effective-risk-level`       | `low`, `medium`, `high`, `critical` (see Effective risk below)                    |
| `ai-risk-level`              | SubQ's most likely overall level, empty if not completed                          |
| `ai-uncertain`               | `true` when no level reached 50% probability                                      |
| `ai-risk-score`              | SubQ's blended score rescaled to 0-100; prefer `ai-risk-level`                    |
| `assessment-status`          | `completed`, `not_required`, `skipped` or `failed`                                |
| `findings-count`             | Deterministic findings in changed files                                           |
| `requires-review`            | `true` when policy requires human review                                          |
| `context-complete`           | `false` if the diff or context was truncated                                      |
| `check-run-id`, `comment-id` | IDs of published reports                                                          |
| `report-path`                | JSON report in `RUNNER_TEMP` (upload it with `actions/upload-artifact` if needed) |

## Repository configuration

Create `.github/subq-pr-risk.yml` on your default branch. The schema is strict: unknown keys
and invalid values fail the run with a precise message. A full example is in
[`examples/subq-pr-risk.yml`](examples/subq-pr-risk.yml).

| Key                                                         | Type / values                                          | Default                    |
| ----------------------------------------------------------- | ------------------------------------------------------ | -------------------------- |
| `version`                                                   | `1` (required)                                         |                            |
| `mode`                                                      | `general` `terraform` `security` `dependencies`        | `general`                  |
| `analysis.max_files`                                        | 1-3000                                                 | 200                        |
| `analysis.max_diff_lines`                                   | 1-200000                                               | 12000                      |
| `analysis.context_files`                                    | 0-100                                                  | 10                         |
| `analysis.max_context_tokens`                               | 10000-350000 (estimated)                               | 250000                     |
| `analysis.fail_on_incomplete_context`                       | boolean                                                | false                      |
| `risk.fail_on`                                              | `never` `medium` `high` `critical`                     | `never`                    |
| `risk.require_review`                                       | list of levels                                         | `[critical, high]`         |
| `policies.protected_paths`                                  | list of globs (matched against new and previous paths) | `[".github/workflows/**"]` |
| `policies.require_review_for`                               | list of tags (below)                                   | `[]`                       |
| `policies.critical_findings_always_fail`                    | boolean                                                | true                       |
| `policies.conventions`                                      | list of strings shown to the model as policy context   | `[]`                       |
| `scanners.secrets` / `terraform` / `sarif` / `dependencies` | boolean                                                | true                       |
| `scanners.required`                                         | list of scanner names whose artifacts must be present  | `[]`                       |
| `report.destination`                                        | `check` `comment` `both`                               | `check`                    |
| `report.include_file_annotations`                           | boolean                                                | true                       |
| `report.include_ai_explanation`                             | boolean                                                | true                       |

Review tags: `iam_changes`, `security_group_changes`, `database_migrations`,
`destructive_infrastructure_changes`, `public_exposure`, `encryption_changes`,
`tls_changes`, `auth_changes`, `secrets`, `workflow_changes`, `dependency_changes`,
`production_infrastructure`, `reliability_settings`, `missing_tests`, `prompt_injection`.

The file is read from the **base** commit of the PR. A pull request that edits the policy
file is evaluated with the old policy; the new policy applies after merge.

## Risk score and policy semantics

**AI verdict.** SubQ Snap answers a 4-level `score` question (low, medium, high,
critical) with a probability for each level. The report shows all four probabilities, and
the AI level is the **most likely** one (ties go to the higher level):

| Low | Medium  | High | Critical |
| --- | ------- | ---- | -------- |
| 10% | **45%** | 40%  | 5%       |

If no level reaches **50%**, the answer is marked **uncertain** and never raises risk. SubQ
also returns a blended score and a `confidence` value; both are shown and kept in the JSON
report (with the raw answer) but do not drive the decision. If a response ever lacks
per-level probabilities, the blended score is mapped to the nearest level (0-16 low, 17-49
medium, 50-83 high, 84-100 critical). These are SubQ's judgments, **not** calibrated
incident probabilities.

**Deterministic findings** carry an evidence status set by the scanner, never by the model:

- `confirmed`: high-precision evidence (structured credential formats, private keys).
- `plausible`: a pattern or upstream-scanner signal that needs review.
- `insufficient_evidence`: a weak signal (for example "code without tests"); shown, but it
  does not raise the risk level.

The model's per-finding probability is displayed next to the finding as context only.

**Effective risk** = the highest deterministic severity, raised to the AI level only when
`ai-mode` is `decide` and the AI answer is not uncertain. The model can raise risk; it can
never lower it. With `ai-mode: advisory`, SubQ's verdict, review flag and failures are
reported but do not affect the decision.

**GO / NO GO.** The `go` output and the Check title (`GO - PASS: ...` or `NO GO - ...`)
give a binary result: GO only when the decision is `pass`. For a GO / NO GO gate decided by
objective evidence (secrets, scanner findings, protected rules) rather than by the model:

```yaml
# .github/subq-pr-risk.yml
version: 1
risk:
  ai_mode: advisory # SubQ explains; rules and scanners decide
  fail_on: high # high or critical deterministic findings: NO GO
  require_review: [] # no "review required" middle state
policies:
  protected_paths: [] # or keep paths that must always get a human
```

Then mark the Check as required in branch protection so NO GO blocks merging.

**Decision**, evaluated in order:

1. `blocked` if a `confirmed` critical finding exists and `critical_findings_always_fail` is
   true, or if the effective risk reaches `fail-on`.
2. If the AI assessment `failed` or was `skipped` (in `decide` mode): `inconclusive` (unless step 1 already
   blocked). `provider-error-policy` then decides: `fail` fails the step, `warn` continues,
   `require-review` (default) continues and marks review as required.
3. `review_required` if the effective level is in `require_review`, a protected path
   changed, a `require_review_for` tag fired, SubQ indicated close human review (`decide`
   mode only), a scanner
   artifact was invalid or a required one was missing, or the analysis was truncated.
4. Otherwise `pass`.

**Step outcome and Check conclusion**

| Situation                                                 | Step                                          | Check conclusion       |
| --------------------------------------------------------- | --------------------------------------------- | ---------------------- |
| `pass`                                                    | success                                       | `success`              |
| `review_required`                                         | success                                       | `neutral`              |
| `blocked`                                                 | **failed**                                    | `failure`              |
| `blocked` with `dry-run: true`                            | success (notice)                              | `neutral`              |
| `inconclusive`                                            | success, unless `provider-error-policy: fail` | `neutral` or `failure` |
| Missing `subq-api-key` on a same-repository PR            | **failed**                                    | `failure`              |
| Invalid input or configuration                            | **failed**                                    | none                   |
| Truncated context with `fail_on_incomplete_context: true` | **failed**                                    | `failure`              |

`dry-run` only suppresses **risk-based** failures. Operational failures (missing key,
invalid configuration, `provider-error-policy: fail`, incomplete context when configured)
still fail, and every report states what was not analyzed.

A **successful assessment that finds risk** reports `review_required` or `blocked`. A
**failed assessment** (timeout, auth error, invalid model response) reports `inconclusive`
and never `pass`.

Documentation-only PRs with no findings skip the model call (`assessment-status:
not_required`) to save cost.

## Terraform and security examples

- [`examples/basic.yml`](examples/basic.yml): minimal, report-only.
- [`examples/terraform.yml`](examples/terraform.yml): `mode: terraform`, Checkov findings,
  `fail-on: high`, check and comment.
- [`examples/security.yml`](examples/security.yml): `mode: security`, Gitleaks JSON and
  Semgrep SARIF from pinned container images, `fail-on: critical`.

## SARIF and scanner integration

The Action **does not run scanners**. Run them in earlier steps (or download artifacts from
a trusted upstream workflow) and pass the file paths:

| Input               | Format                  | Produce with                                                               |
| ------------------- | ----------------------- | -------------------------------------------------------------------------- |
| `gitleaks-report`   | Gitleaks JSON           | `gitleaks dir . --report-format json --report-path gitleaks.json --redact` |
| `checkov-report`    | Checkov JSON            | `checkov -d . -o json` (Checkov Action writes `results_json.json`)         |
| `sarif-files`       | SARIF 2.1.0             | CodeQL, Semgrep `--sarif`, Trivy `--format sarif`, tfsec, Grype ...        |
| `dependency-report` | `npm audit --json` (v2) | `npm audit --json > npm-audit.json`                                        |

Rules:

- Paths must resolve inside `GITHUB_WORKSPACE` or `RUNNER_TEMP`; symlinks escaping them are
  rejected. Files over 20 MiB are rejected. At most 500 findings per artifact are read.
- Gitleaks `Secret`/`Match` values are never read into reports or model requests.
- SARIF suppressed results are skipped; `security-severity` maps to severity using GitHub's
  thresholds (>= 9 critical, >= 7 high, >= 4 medium).
- Findings for files the PR did not change are dropped (and counted in the report).
- Findings at the same file, line and category from different sources are merged; all
  sources are listed.
- Scanner status is reported per scanner: `completed`, `not_configured`, `missing`,
  `invalid` or `disabled`. Missing required or invalid artifacts never count as a pass.

## Permissions and forked pull requests

| Permission             | Needed for                                                          |
| ---------------------- | ------------------------------------------------------------------- |
| `contents: read`       | Reading PR files, repository tree, file content and the policy file |
| `checks: write`        | Creating the Check Run (`report: check` or `both`)                  |
| `pull-requests: write` | Creating/updating the PR comment (`report: comment` or `both`)      |
| `pull-requests: read`  | Enough when you only use `report: check`                            |

If a permission is missing, the Action logs a warning and still writes the job summary.

**Forked PRs.** With the `pull_request` trigger, GitHub does not pass secrets to workflows
from forks and gives a read-only token. The Action then:

- runs deterministic rules and scanner ingestion,
- does **not** call SubQ and reports `assessment-status: skipped` and
  `decision: inconclusive` (never `pass`),
- writes the job summary (the Check Run may fail to publish with a read-only token).

**Do not** use `pull_request_target` to check out or run PR code. The Action itself never
checks out or executes PR code, and it works without any checkout. If you add a checkout
for scanners, set `persist-credentials: false` and only run static analyzers that do not
execute repository code. Running this Action under `pull_request_target` would spend your
SubQ credits on untrusted PRs; prefer `pull_request`.

## Privacy and data handling

Sent to `https://api.subq.ai/v1/systemone` in one request per PR run:

- PR title, description, author login, labels, branch names, fork/draft flags, totals.
- For each changed file: path, previous path, status, line counts and the **redacted** patch
  (subject to `max-diff-lines`).
- Up to `context-files` **redacted** repository files selected by deterministic rules.
- Deterministic findings (titles, files, lines, redacted evidence).
- Your policy settings (mode, protected paths, review triggers, conventions).

Never sent:

- The SubQ key (only in the `Authorization` header), the GitHub token, or other secrets.
- Values matching the secret detector (replaced with `[REDACTED:<rule>]`).
- Content of sensitive files (`.env*` except examples, `*.pem`, `*.key`, `id_rsa*`,
  `.npmrc`, `*.tfstate`, `secrets.yml`, service-account JSON, kubeconfig, and similar);
  only their path and status.

SubQ's [data retention](https://docs.subq.ai/using-the-api/data-retention/) is set per
SubQ organization. **The SubQ default is to retain requests indefinitely.** Zero data
retention can be requested from SubQ and does not affect the Decisions API. Evaluate this
against your code-confidentiality requirements before enabling the Action on private
repositories.

Cost: SubQ Snap bills input tokens only ($0.05 per 1M input tokens per SubQ's Models page
on 2026-10-13). A 100K-token assessment costs about $0.005. The report and the JSON output
include the token count and estimated cost.

## Trust model

Adding this Action to a workflow means trusting three parties:

| Party          | What you trust it with                                                        |
| -------------- | ----------------------------------------------------------------------------- |
| The maintainer | The code that runs is whatever the ref you use points to.                     |
| GitHub         | Runs the Action and stores your secrets.                                      |
| SubQ           | Receives redacted PR content; retains it indefinitely unless you request ZDR. |

What the Action can access in your run:

- **SubQ key:** sent only in the `Authorization` header to `https://api.subq.ai`. The API
  host is fixed in code and cannot be changed by inputs or repository config.
- **GitHub token:** reads the PR and repository files, writes the Check Run and (optionally)
  one PR comment.
- **PR content:** the diff, metadata and selected files, with secrets redacted and sensitive
  files excluded (see [Privacy and data handling](#privacy-and-data-handling)).

The Action sends no telemetry, contacts no host other than the GitHub API and SubQ, and
never executes code from the pull request.

To reduce what you need to trust:

- **Pin to a full commit SHA** instead of `@v1`. A tag can be moved; a SHA cannot. Release
  tags (`v1.0.1` and later) are protected from being moved or deleted, but `v1` moves by
  design.
  ```yaml
  uses: mrexhepi/PRison@28f05bb3b9cbc1335eb31e4a5d7679eeaa41400e # v1.0.1
  ```
- **Grant minimal permissions:** `contents: read`, `checks: write`, and `pull-requests: write`
  only if you enable comments.
- **Use a dedicated SubQ key** for this Action so it can be revoked on its own.
- **Request zero data retention** from SubQ before enabling the Action on private
  repositories.
- **Review `dist/index.js` at the pinned SHA** if you need to audit exactly what runs; CI
  verifies it matches a fresh build of `src/`.

## Troubleshooting

| Symptom                                | Cause and fix                                                                                                          |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Input 'subq-api-key' is empty`        | The secret is missing or misnamed. Create `SUBQ_API_KEY` and pass `${{ secrets.SUBQ_API_KEY }}`.                       |
| `SubQ rejected the API key (401)`      | Key revoked or mistyped. Rotate it and update the secret.                                                              |
| `insufficient credits (402)`           | Add credits in the SubQ console.                                                                                       |
| `cannot use the requested model (403)` | The key's organization lacks access to `subq-snap-preview`.                                                            |
| `rejected the request (400)`           | Request too large for the 384K-token window. Lower `max-diff-lines`, `context-files` or `analysis.max_context_tokens`. |
| `rate limit exceeded (429)`            | Retried automatically twice. Reduce concurrency or set `provider-error-policy: warn`.                                  |
| `Could not create check run`           | Add `checks: write`, or this is a fork PR with a read-only token. See the job summary.                                 |
| `Configuration ... is invalid`         | The message lists the offending keys. Unknown keys are rejected.                                                       |
| Decision `inconclusive` on forks       | Expected: secrets are unavailable to fork PRs.                                                                         |
| `context-complete: false`              | The PR exceeded `max-files` or `max-diff-lines`; the report lists what was skipped.                                    |

## Local development and testing

```bash
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test              # unit, integration, security and evaluation tests
npm run test:coverage
npm run build         # bundles to dist/index.js
npm run verify:dist   # checks action.yml, bundle self-containment and freshness
npm run all           # everything above
```

Evaluation:

```bash
npm run eval                                        # deterministic layer, mock provider
SUBQ_API_KEY=... npm run eval -- --provider subq    # real SubQ Snap calls (uses credits)
```

The dataset (`tests/fixtures/eval/cases.json`) covers low-risk, high-risk, ambiguous and
incomplete-context PRs and reports precision/recall for high-risk PRs, false-positive rate,
false-negative rate for critical issues, agreement with expert decisions, latency, cost per
PR and the inconclusive rate. Results are written to `eval-results/`.

To exercise the Action against a fake event locally:

```bash
GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH=/dev/null GITHUB_REPOSITORY=o/r node dist/index.js
```

## Build and release

`dist/index.js` is a self-contained esbuild bundle and is committed. CI fails if it is out
of date. Consumers never install dependencies or build.

### Automated release

1. Update `version` in `package.json` (for example `1.0.1`), run `npm run all`, commit
   including `dist/`.
2. Tag and push: `git tag -a v1.0.1 -m v1.0.1 && git push origin v1.0.1`.
3. `release.yml` re-runs all checks, verifies the tag matches `package.json` and `dist/` is
   fresh, then publishes a GitHub Release with generated notes.
4. The `major-tag` job runs in the protected `release` environment and moves `v1` to the
   new release after approval. Configure required reviewers under
   **Settings -> Environments -> release**.

### Manual release (fallback)

```bash
npm ci && npm run all
git tag -a v1.0.1 -m "v1.0.1" && git push origin v1.0.1
gh release create v1.0.1 --verify-tag --generate-notes --title v1.0.1
git tag -fa v1 -m "Update v1 to v1.0.1" v1.0.1^{commit} && git push origin refs/tags/v1 --force
```

### Publishing to the GitHub Marketplace

Open the release on GitHub, tick **Publish this Action to the GitHub Marketplace**, accept
the agreement and choose categories (Security, Code quality). The action name in
`action.yml` must be unique on the Marketplace.

## Version pinning

- `@v1`: receives compatible fixes and features. Convenient, trusts the maintainer.
- `@v1.0.1`: a fixed release tag (do not use v1.0.0; it fails to load).
- `@<full commit SHA>`: immutable and recommended for security-sensitive repositories.
  Use Dependabot (`package-ecosystem: github-actions`) to receive update PRs.

Breaking changes only ship in a new major version.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). SubQ and SubQ Snap are products of Subquadratic; this project is not
affiliated with or endorsed by Subquadratic.
