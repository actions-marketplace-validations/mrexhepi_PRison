export interface RetryOptions {
  retries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Return a delay override in ms (e.g. from Retry-After), or undefined for backoff. */
  delayFor?: (err: unknown, attempt: number) => number | undefined;
  isRetryable: (err: unknown) => boolean;
  sleep?: (ms: number) => Promise<void>;
  onRetry?: (err: unknown, attempt: number, delayMs: number) => void;
}

export const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Bounded retry with exponential backoff and full jitter. */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  opts: RetryOptions,
): Promise<T> {
  const sleep = opts.sleep ?? defaultSleep;
  let attempt = 0;
  for (;;) {
    try {
      return await fn(attempt);
    } catch (err) {
      if (attempt >= opts.retries || !opts.isRetryable(err)) throw err;
      const backoff = Math.min(opts.maxDelayMs, opts.baseDelayMs * 2 ** attempt);
      const override = opts.delayFor?.(err, attempt);
      const delay =
        override !== undefined
          ? Math.min(opts.maxDelayMs, Math.max(0, override))
          : Math.round(backoff / 2 + Math.random() * (backoff / 2));
      opts.onRetry?.(err, attempt + 1, delay);
      await sleep(delay);
      attempt++;
    }
  }
}

/** Parse an HTTP Retry-After header (seconds or HTTP date) into milliseconds. */
export function parseRetryAfter(
  value: string | null | undefined,
  now = Date.now(),
): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, date - now);
  return undefined;
}
