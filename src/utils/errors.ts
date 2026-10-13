/** A user-facing configuration or input error. Messages must never contain secrets. */
export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

/** The decision provider could not produce a valid assessment. */
export class ProviderError extends Error {
  override readonly name = 'ProviderError';
  constructor(
    message: string,
    readonly kind:
      | 'missing_token'
      | 'auth'
      | 'credits'
      | 'forbidden'
      | 'rate_limited'
      | 'timeout'
      | 'network'
      | 'server'
      | 'bad_request'
      | 'invalid_response',
    readonly status?: number,
    readonly retryable = false,
  ) {
    super(message);
  }
}

/** A GitHub API call failed in a way the run cannot recover from. */
export class GitHubApiError extends Error {
  override readonly name = 'GitHubApiError';
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
