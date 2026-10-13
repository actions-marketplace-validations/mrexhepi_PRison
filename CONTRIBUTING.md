# Contributing

Thanks for helping improve SubQ PR Risk Scanner.

## Setup

```bash
npm ci
npm run all   # format check, lint, type check, tests, build, dist verification
```

Node 24 matches the Action runtime; Node 22 also works for development.

## Pull requests

- Keep changes focused and covered by tests (`tests/unit`, `tests/integration`,
  `tests/security`). New rules need a positive and a negative test and, where useful, an
  evaluation case in `tests/fixtures/eval/cases.json`.
- Run `npm run build` and commit `dist/index.js`. CI rejects stale bundles.
- Never commit real credentials. Fixtures may only use documented example values
  (for example `AKIAIOSFODNN7EXAMPLE`).
- Do not add code paths that execute repository content, evaluate configuration as code,
  or interpolate PR-controlled text into model instructions or shell commands.
- Do not claim accuracy improvements without evaluation results.
- Pin third-party actions in workflows and examples to full commit SHAs.

## Adding a decision provider

Implement `DecisionProvider` from `src/types.ts`, validate every response strictly, map
errors to `ProviderError`, and add tests that exercise timeouts, error statuses and invalid
responses with a fake transport.
