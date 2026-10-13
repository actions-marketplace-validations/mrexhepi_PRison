import { SEVERITY_RANK } from '../scanners/finding.js';
import type { AssessmentInput, AssessmentResult, DecisionProvider } from '../types.js';
import type { Answer, DecisionResponse } from './api.js';
import { CATEGORY_QUESTIONS, buildQuestions } from './questions.js';
import { interpretAnswers } from './provider.js';

/**
 * Deterministic stand-in for SubQ, for tests, local development and the self-test
 * workflow. It derives answers from deterministic findings only. Results are always
 * labeled with provider "mock" and are never a real assessment.
 */
export class MockDecisionProvider implements DecisionProvider {
  readonly name = 'mock';

  constructor(
    private readonly override?: (input: AssessmentInput) => Partial<Record<string, Answer>>,
  ) {}

  async assess(input: AssessmentInput): Promise<AssessmentResult> {
    const built = buildQuestions(input);
    const maxRank = input.scannerFindings.reduce(
      (m, f) => Math.max(m, SEVERITY_RANK[f.severity]),
      0,
    );
    const score = Math.max(0, Math.min(3, maxRank - 1));
    const answers: Record<string, Answer> = {
      overall_risk: {
        type: 'score',
        score,
        legend: { '0': 'Low', '1': 'Medium', '2': 'High', '3': 'Critical' },
        probabilities: {
          '0': score === 0 ? 1 : 0,
          '1': score === 1 ? 1 : 0,
          '2': score === 2 ? 1 : 0,
          '3': score === 3 ? 1 : 0,
        },
        confidence: 0.5,
      },
      human_review: { type: 'noul', noul: score >= 2 ? 0.8 : 0.2 },
      recommended_action: {
        type: 'choice',
        choice: score >= 2 ? 'security_review' : 'standard_review',
        probabilities: {},
        confidence: 0.5,
      },
    };
    for (const [category, { name }] of Object.entries(CATEGORY_QUESTIONS)) {
      const hit = input.scannerFindings.some(
        (f) => f.category === category && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium,
      );
      answers[name] = { type: 'noul', noul: hit ? 0.7 : 0.1 };
    }
    for (const q of built.findingQuestions.keys()) answers[q] = { type: 'noul', noul: 0.6 };
    Object.assign(answers, this.override?.(input) ?? {});
    const response: DecisionResponse = {
      model: 'mock',
      answers,
      usage: { input_tokens: 0, output_tokens: 0 },
    };
    return interpretAnswers(built, response, { provider: this.name, latencyMs: 0 });
  }
}
