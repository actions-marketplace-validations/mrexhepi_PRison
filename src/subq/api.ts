/**
 * SubQ Decisions API contract, verified against https://docs.subq.ai/endpoints/decisions-api/
 * (fetched 2026-10-13):
 *
 *   POST https://api.subq.ai/v1/systemone
 *   Authorization: Bearer <SUBQ_API_KEY>
 *   { model: "subq-snap-preview", state, questions: { <name>: noul | choice | score } }
 *
 * - 1-16 questions, names up to 100 characters.
 * - noul:   yes/no gate. criteria {true?, false?}. Answer: { type, noul: P(yes) }.
 * - choice: 2-255 named options (description may be null).
 *           Answer: { type, choice, probabilities, confidence }.
 * - score:  2-10 ordered levels. Answer: { type, score (probability-weighted, may fall
 *           between levels), legend, probabilities, confidence }.
 * - Context window 393,216 tokens; oversize requests fail with 400.
 * - Errors: { detail: { error_type, message } }; 400, 401, 402, 403, 422, 429, 5xx (503).
 * - Billing: input tokens only ($0.05 / 1M tokens per the Models page); output_tokens is 0.
 */
import { z } from 'zod';

export const SUBQ_BASE_URL = 'https://api.subq.ai/v1';
export const SUBQ_DECISIONS_PATH = '/systemone';
export const SUBQ_SNAP_MODEL = 'subq-snap-preview';
export const SUBQ_CONTEXT_WINDOW_TOKENS = 393_216;
export const SUBQ_INPUT_PRICE_PER_MTOK_USD = 0.05;
export const SUBQ_MAX_QUESTIONS = 16;

export type NoulQuestion = {
  type: 'noul';
  instructions: string;
  criteria?: { true?: string; false?: string };
};
export type ChoiceQuestion = {
  type: 'choice';
  instructions: string;
  criteria: Record<string, string | null>;
};
export type ScoreQuestion = {
  type: 'score';
  instructions: string;
  criteria: string[];
};
export type Question = NoulQuestion | ChoiceQuestion | ScoreQuestion;

export interface DecisionRequest {
  model: string;
  state: unknown;
  questions: Record<string, Question>;
}

const prob = z.number().min(0).max(1);

export const noulAnswerSchema = z.object({ type: z.literal('noul'), noul: prob }).loose();
export const choiceAnswerSchema = z
  .object({
    type: z.literal('choice'),
    choice: z.string(),
    probabilities: z.record(z.string(), prob),
    confidence: prob,
  })
  .loose();
export const scoreAnswerSchema = z
  .object({
    type: z.literal('score'),
    score: z.number().finite(),
    legend: z.record(z.string(), z.string()),
    probabilities: z.record(z.string(), prob),
    confidence: prob,
  })
  .loose();

export const answerSchema = z.discriminatedUnion('type', [
  noulAnswerSchema,
  choiceAnswerSchema,
  scoreAnswerSchema,
]);

export const decisionResponseSchema = z
  .object({
    model: z.string(),
    answers: z.record(z.string(), answerSchema),
    usage: z
      .object({
        input_tokens: z.number().int().nonnegative(),
        output_tokens: z.number().int().nonnegative(),
      })
      .loose()
      .optional(),
  })
  .loose();

export type DecisionResponse = z.infer<typeof decisionResponseSchema>;
export type Answer = z.infer<typeof answerSchema>;

export const errorBodySchema = z
  .object({
    detail: z.object({ error_type: z.string().optional(), message: z.string().optional() }).loose(),
  })
  .loose();

/**
 * Validate a response semantically against the questions that were asked: every question
 * must be answered with the matching type, choices must be one of the offered options and
 * scores must lie within the level range. Throws on any violation.
 */
export function validateAnswers(
  questions: Record<string, Question>,
  response: DecisionResponse,
): void {
  for (const [name, q] of Object.entries(questions)) {
    const a = response.answers[name];
    if (!a) throw new Error(`answer '${name}' is missing`);
    if (a.type !== q.type)
      throw new Error(`answer '${name}' has type ${a.type}, expected ${q.type}`);
    if (a.type === 'choice' && q.type === 'choice') {
      const options = Object.keys(q.criteria);
      if (!options.includes(a.choice)) throw new Error(`answer '${name}' chose an unknown option`);
      for (const k of Object.keys(a.probabilities)) {
        if (!options.includes(k))
          throw new Error(`answer '${name}' has an unknown option probability`);
      }
    }
    if (a.type === 'score' && q.type === 'score') {
      const max = q.criteria.length - 1;
      if (a.score < 0 || a.score > max) throw new Error(`answer '${name}' score is out of range`);
    }
  }
}
