# Changelog

This project started as an experiment in testing SubQ (subq.ai) on pull request risk review.

## 1.0.1

- Fix: the action failed to load because an input description in `action.yml` contained a
  `${{ secrets... }}` expression, which the runner evaluates. 1.0.0 is unusable; use 1.0.1.
- Self-test now loads the action on every push to `main`.
- Dependabot ignores major updates of `@types/node` and `typescript`.

## 1.0.0

- Initial release: SubQ Snap Decisions API provider, deterministic change rules and secret
  detector, Gitleaks/Checkov/SARIF/npm-audit ingestion, bounded context selection,
  deterministic policy engine, Check Run with annotations, PR comment, job summary,
  JSON report, evaluation harness.
