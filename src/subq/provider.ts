import { UNCERTAIN_BELOW, scoreToLevel } from '../risk/scoring.js';
import {
  RISK_LEVELS,
  type AssessmentInput,
  type AssessmentResult,
  type CategoryJudgment,
  type DecisionProvider,
  type RiskCategory,
  type RiskLevel,
} from '../types.js';
import { ProviderError } from '../utils/errors.js';
import { SUBQ_INPUT_PRICE_PER_MTOK_USD, SUBQ_SNAP_MODEL, type DecisionResponse } from './api.js';
import type { SubQClient } from './client.js';
import {
  CATEGORY_QUESTIONS,
  RECOMMENDED_ACTIONS,
  buildQuestions,
  type BuiltQuestions,
} from './questions.js';
import { buildState } from './state.js';

/** Convert validated Decisions API answers into the internal AssessmentResult. */
export function interpretAnswers(
  built: BuiltQuestions,
  response: DecisionResponse,
  meta: { provider: string; latencyMs: number },
): AssessmentResult {
  const a = response.answers;
  const overall = a.overall_risk;
  if (!overall || overall.type !== 'score') {
    throw new ProviderError('overall_risk answer missing', 'invalid_response');
  }
  const levels = Object.keys(
    built.questions.overall_risk?.type === 'score' ? built.questions.overall_risk.criteria : [],
  ).length;
  const maxLevel = Math.max(1, levels - 1);
  const riskScore = Math.round((overall.score / maxLevel) * 100);
  if (!Number.isFinite(riskScore) || riskScore < 0 || riskScore > 100) {
    throw new ProviderError('overall_risk score outside 0-100', 'invalid_response');
  }

  const categories: CategoryJudgment[] = [];
  for (const [category, { name }] of Object.entries(CATEGORY_QUESTIONS)) {
    const ans = a[name];
    if (ans?.type === 'noul')
      categories.push({ category: category as RiskCategory, probability: ans.noul });
  }

  const review = a.human_review;
  const humanReviewProbability = review?.type === 'noul' ? review.noul : 1;

  const action = a.recommended_action;
  const recommendedAction =
    action?.type === 'choice'
      ? (RECOMMENDED_ACTIONS[action.choice] ?? action.choice)
      : 'Proceed with standard code review';

  const findingJudgments = [...built.findingQuestions.entries()].flatMap(([q, findingId]) => {
    const ans = a[q];
    return ans?.type === 'noul' ? [{ findingId, probability: ans.noul }] : [];
  });

  // SubQ returns a probability per level, keyed by level index ("0".."3"). Use the most likely
  // level rather than banding the blended score: a blend of 1.47 can mean "torn between medium
  // and high" or "spread across all four", and only the probabilities tell those apart.
  const probs = RISK_LEVELS.map((_, i) => overall.probabilities[String(i)]);
  const haveProbs = levels === RISK_LEVELS.length && probs.every((p) => typeof p === 'number');
  let riskLevel = scoreToLevel(riskScore);
  let levelProbabilities: Record<RiskLevel, number> | undefined;
  let levelProbability: number | undefined;
  if (haveProbs) {
    levelProbabilities = Object.fromEntries(
      RISK_LEVELS.map((l, i) => [l, probs[i] as number]),
    ) as Record<RiskLevel, number>;
    // Ties go to the higher level.
    let best = 0;
    probs.forEach((p, i) => {
      if ((p as number) >= (probs[best] as number)) best = i;
    });
    riskLevel = RISK_LEVELS[best] as RiskLevel;
    levelProbability = probs[best] as number;
  }
  const uncertain = levelProbability !== undefined && levelProbability < UNCERTAIN_BELOW;
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const verdict = levelProbabilities
    ? `SubQ Snap's most likely overall risk is ${riskLevel.toUpperCase()} (${pct(levelProbability as number)}; ` +
      RISK_LEVELS.map((l) => `${l} ${pct(levelProbabilities[l])}`).join(', ') +
      `). ${uncertain ? `No level reached ${pct(UNCERTAIN_BELOW)}, so this answer is uncertain and is not used to raise risk. ` : ''}`
    : `SubQ Snap rated merge risk ${riskLevel.toUpperCase()} (${riskScore}/100). `;
  const elevated = categories
    .filter((c) => c.probability >= 0.5)
    .sort((x, y) => y.probability - x.probability)
    .map((c) => `${c.category} (${Math.round(c.probability * 100)}%)`);
  const summary =
    verdict +
    `SubQ confidence ${pct(overall.confidence)}. ` +
    (elevated.length
      ? `Elevated categories: ${elevated.join(', ')}.`
      : 'No risk category exceeded 50% probability.') +
    ` Probability that close human review is needed: ${Math.round(humanReviewProbability * 100)}%.`;

  const inputTokens = response.usage?.input_tokens;
  return {
    provider: meta.provider,
    model: response.model,
    riskLevel,
    riskScore,
    ...(levelProbabilities ? { levelProbabilities, levelProbability } : {}),
    uncertain,
    confidence: overall.confidence,
    rawOverall: {
      score: overall.score,
      probabilities: overall.probabilities,
      confidence: overall.confidence,
    },
    summary,
    categories,
    findingJudgments,
    recommendedAction,
    requiresHumanReview: humanReviewProbability >= 0.5,
    humanReviewProbability,
    ...(inputTokens !== undefined
      ? {
          usage: {
            inputTokens,
            estimatedCostUsd: (inputTokens / 1_000_000) * SUBQ_INPUT_PRICE_PER_MTOK_USD,
          },
        }
      : {}),
    latencyMs: meta.latencyMs,
  };
}

/** DecisionProvider backed by the SubQ Snap Decisions API. */
export class SubQDecisionProvider implements DecisionProvider {
  readonly name = 'subq';

  constructor(
    private readonly client: SubQClient,
    private readonly model = SUBQ_SNAP_MODEL,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async assess(input: AssessmentInput): Promise<AssessmentResult> {
    const built = buildQuestions(input);
    const started = this.now();
    const response = await this.client.decide({
      model: this.model,
      state: buildState(input),
      questions: built.questions,
    });
    return interpretAnswers(built, response, {
      provider: this.name,
      latencyMs: this.now() - started,
    });
  }
}
