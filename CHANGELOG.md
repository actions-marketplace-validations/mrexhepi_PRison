# Changelog

This project started as an experiment in testing SubQ (subq.ai) on pull request risk review.

## 1.0.2

- The AI verdict is SubQ's most likely overall level with its probability, and the report
  shows all four level probabilities. Previously the blended score was banded, so a 1.47
  answer (nearest to medium) was reported as "49/100 high".
- Answers where no level reaches 50% are marked uncertain and never raise risk.
- Fallback score bands now map to the nearest level (0-16, 17-49, 50-83, 84-100).
- New `ai-mode` input and `risk.ai_mode` config: `decide` (default) or `advisory`.
- New outputs `go` and `ai-uncertain`; the Check title starts with GO or NO GO.
- The JSON report includes the raw overall answer, `go` and `aiMode`.

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
