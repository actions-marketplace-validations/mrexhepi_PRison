# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/mrexhepi/PRison/security/advisories/new).
Do not open public issues for security problems. Expect an acknowledgement within 5
business days.

## Scope

In scope: secret leakage (logs, reports, model requests), prompt injection that changes
decisions beyond what the policy engine allows, path traversal in artifact handling, unsafe
Markdown in reports, and anything that causes PR code to execute.

## Design guarantees

- PR code is never checked out or executed by the Action.
- Repository configuration is parsed as data and read from the PR base commit.
- Secrets are redacted from model requests, logs, check runs, comments and outputs.
- Model output can raise but never lower deterministic risk, and cannot change policy.
