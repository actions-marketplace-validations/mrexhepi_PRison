import { ProviderError } from '../utils/errors.js';
import { redactForOutput } from '../utils/redact.js';
import { parseRetryAfter, withRetry } from '../utils/retry.js';
import {
  SUBQ_BASE_URL,
  SUBQ_DECISIONS_PATH,
  decisionResponseSchema,
  errorBodySchema,
  validateAnswers,
  type DecisionRequest,
  type DecisionResponse,
} from './api.js';

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface SubQClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  retries?: number;
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  log?: (msg: string) => void;
}

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_REQUEST_BYTES = 12 * 1024 * 1024; // documented body limit is 13 MiB

class RetryAfterError extends ProviderError {
  constructor(
    base: ProviderError,
    readonly retryAfterMs: number | undefined,
  ) {
    super(base.message, base.kind, base.status, base.retryable);
  }
}

/** Minimal HTTP client for the SubQ Decisions API (`POST /v1/systemone`). */
export class SubQClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(private readonly opts: SubQClientOptions) {
    if (!opts.apiKey) throw new ProviderError('SubQ API key is missing.', 'missing_token');
    this.baseUrl = (opts.baseUrl ?? SUBQ_BASE_URL).replace(/\/+$/, '');
    if (!/^https:\/\//.test(this.baseUrl)) {
      throw new ProviderError('SubQ base URL must use https.', 'bad_request');
    }
    this.fetchImpl = opts.fetch ?? ((url, init) => fetch(url, init));
  }

  async decide(request: DecisionRequest): Promise<DecisionResponse> {
    const body = JSON.stringify(request);
    if (Buffer.byteLength(body, 'utf8') > MAX_REQUEST_BYTES) {
      throw new ProviderError('Decision request body exceeds the size limit.', 'bad_request');
    }
    return withRetry(() => this.once(body, request), {
      retries: this.opts.retries ?? 2,
      baseDelayMs: 2000,
      maxDelayMs: 30_000,
      isRetryable: (err) => err instanceof ProviderError && err.retryable,
      delayFor: (err) => (err instanceof RetryAfterError ? err.retryAfterMs : undefined),
      ...(this.opts.sleep ? { sleep: this.opts.sleep } : {}),
      onRetry: (err, attempt, delay) =>
        this.opts.log?.(
          `SubQ request failed (${err instanceof ProviderError ? err.kind : 'error'}); retry ${attempt} in ${delay}ms`,
        ),
    });
  }

  private async once(body: string, request: DecisionRequest): Promise<DecisionResponse> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${SUBQ_DECISIONS_PATH}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.opts.apiKey}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'subq-pr-risk-scanner',
        },
        body,
        signal: AbortSignal.timeout(this.opts.timeoutMs ?? 60_000),
      });
    } catch (err) {
      const name = err instanceof Error ? err.name : '';
      if (name === 'TimeoutError' || name === 'AbortError') {
        throw new ProviderError('SubQ request timed out.', 'timeout', undefined, true);
      }
      throw new ProviderError(
        `SubQ request failed: ${redactForOutput(err instanceof Error ? err.message : String(err))}`,
        'network',
        undefined,
        true,
      );
    }

    const text = await readBounded(res);
    if (!res.ok) {
      const base = mapError(res.status, text);
      throw new RetryAfterError(base, parseRetryAfter(res.headers.get('retry-after')));
    }

    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new ProviderError('SubQ returned a non-JSON response.', 'invalid_response', res.status);
    }
    const parsed = decisionResponseSchema.safeParse(json);
    if (!parsed.success) {
      throw new ProviderError(
        `SubQ response failed schema validation: ${parsed.error.issues[0]?.path.join('.') ?? ''} ${parsed.error.issues[0]?.message ?? ''}`.trim(),
        'invalid_response',
        res.status,
      );
    }
    try {
      validateAnswers(request.questions, parsed.data);
    } catch (err) {
      throw new ProviderError(
        `SubQ response failed validation: ${err instanceof Error ? err.message : err}`,
        'invalid_response',
        res.status,
      );
    }
    return parsed.data;
  }
}

async function readBounded(res: Response): Promise<string> {
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new ProviderError(
      'SubQ response exceeded the size limit.',
      'invalid_response',
      res.status,
    );
  }
  return text;
}

function mapError(status: number, text: string): ProviderError {
  let detail = '';
  try {
    const parsed = errorBodySchema.safeParse(JSON.parse(text));
    if (parsed.success) {
      detail = [parsed.data.detail.error_type, parsed.data.detail.message]
        .filter(Boolean)
        .join(': ');
    }
  } catch {
    // Non-JSON error body; ignore its content.
  }
  const suffix = detail ? ` (${redactForOutput(detail).slice(0, 300)})` : '';
  switch (status) {
    case 401:
      return new ProviderError(`SubQ rejected the API key (401)${suffix}.`, 'auth', status);
    case 402:
      return new ProviderError(
        `SubQ account has insufficient credits (402)${suffix}.`,
        'credits',
        status,
      );
    case 403:
      return new ProviderError(
        `SubQ API key cannot use the requested model (403)${suffix}.`,
        'forbidden',
        status,
      );
    case 429:
      return new ProviderError(
        `SubQ rate limit exceeded (429)${suffix}.`,
        'rate_limited',
        status,
        true,
      );
    case 400:
    case 422:
      return new ProviderError(
        `SubQ rejected the request (${status})${suffix}.`,
        'bad_request',
        status,
      );
    default:
      if (status >= 500) {
        return new ProviderError(`SubQ server error (${status})${suffix}.`, 'server', status, true);
      }
      return new ProviderError(
        `SubQ returned unexpected status ${status}${suffix}.`,
        'server',
        status,
      );
  }
}
