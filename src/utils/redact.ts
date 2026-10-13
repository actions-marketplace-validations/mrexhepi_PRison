/**
 * Secret detection and redaction. Used for three things:
 *  1. Producing deterministic `secrets` findings from added lines.
 *  2. Redacting every string before it is sent to the model.
 *  3. Redacting every string before it is written to logs, checks or comments.
 */

export interface SecretPattern {
  id: string;
  title: string;
  regex: RegExp;
  /** confirmed = very low false-positive rate (structured key formats). */
  confidence: 'confirmed' | 'plausible';
  severity: 'high' | 'critical';
}

// Patterns are intentionally anchored on structured formats. All are global so they
// can be used with String.replace; callers must reset lastIndex when using exec/test.
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'private-key',
    title: 'Private key material',
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|$)/g,
    confidence: 'confirmed',
    severity: 'critical',
  },
  {
    id: 'aws-access-key-id',
    title: 'AWS access key ID',
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    confidence: 'confirmed',
    severity: 'critical',
  },
  {
    id: 'github-token',
    title: 'GitHub token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g,
    confidence: 'confirmed',
    severity: 'critical',
  },
  {
    id: 'slack-token',
    title: 'Slack token',
    regex: /\bxox[abposr]-[A-Za-z0-9-]{10,200}\b/g,
    confidence: 'confirmed',
    severity: 'critical',
  },
  {
    id: 'stripe-secret-key',
    title: 'Stripe secret key',
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b/g,
    confidence: 'confirmed',
    severity: 'critical',
  },
  {
    id: 'google-api-key',
    title: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    confidence: 'confirmed',
    severity: 'high',
  },
  {
    id: 'openai-style-key',
    title: 'API secret key (sk- prefix)',
    regex: /\bsk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{32,200}\b/g,
    confidence: 'plausible',
    severity: 'high',
  },
  {
    id: 'jwt',
    title: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    confidence: 'plausible',
    severity: 'high',
  },
  {
    id: 'url-credentials',
    title: 'Credentials embedded in URL',
    regex: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`]{1,100}:[^\s@/'"`]{3,200}@[^\s'"`]+/gi,
    confidence: 'plausible',
    severity: 'high',
  },
  {
    id: 'generic-secret-assignment',
    title: 'Hardcoded secret-like assignment',
    // key = "value" where key looks secret-ish and value is a long opaque literal.
    regex:
      /\b[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*["']?\s*[:=]\s*["']([^"'\s$<>{}]{12,200})["']/gi,
    confidence: 'plausible',
    severity: 'high',
  },
];

const PLACEHOLDER_VALUES =
  /^(?:x+|\*+|changeme|change_me|example|placeholder|dummy|test|fake|redacted|your[_-].*|<.*>|\.\.\.)$/i;

export interface SecretMatch {
  patternId: string;
  title: string;
  confidence: 'confirmed' | 'plausible';
  severity: 'high' | 'critical';
  index: number;
  length: number;
}

export function findSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(text)) !== null) {
      if (m[0].length === 0) {
        p.regex.lastIndex++;
        continue;
      }
      const captured = m[1];
      if (captured !== undefined && PLACEHOLDER_VALUES.test(captured)) continue;
      matches.push({
        patternId: p.id,
        title: p.title,
        confidence: p.confidence,
        severity: p.severity,
        index: m.index,
        length: m[0].length,
      });
    }
  }
  return matches;
}

/** Replace every detected secret with a fixed marker. Idempotent. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    out = out.replace(p.regex, (match, captured: unknown) => {
      if (typeof captured === 'string' && PLACEHOLDER_VALUES.test(captured)) return match;
      return `[REDACTED:${p.id}]`;
    });
  }
  return out;
}

const extraSecrets = new Set<string>();

/** Register runtime secrets (e.g. the SubQ token) so they are scrubbed from any output. */
export function registerSecret(value: string): void {
  if (value && value.length >= 4) extraSecrets.add(value);
}

export function clearRegisteredSecrets(): void {
  extraSecrets.clear();
}

/** Redact registered secrets, bearer headers and detected secrets. Use on all diagnostics. */
export function redactForOutput(text: string): string {
  let out = text;
  for (const s of extraSecrets) out = out.split(s).join('[REDACTED]');
  out = out.replace(
    /(authorization\s*[:=]\s*)(?:bearer|token|basic)?\s*[^\s,;'"}]+/gi,
    '$1[REDACTED]',
  );
  out = out.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, 'Bearer [REDACTED]');
  return redactSecrets(out);
}

/** Paths whose content must never be sent to the model or quoted in reports. */
const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /(^|\/)\.env(\.[^/]*)?$/i,
  /(^|\/)[^/]*\.env$/i,
  /\.(pem|key|p12|pfx|jks|keystore|ppk|asc|gpg|kdbx)$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
  /(^|\/)\.(npmrc|pypirc|netrc|git-credentials|htpasswd|pgpass)$/i,
  /(^|\/)credentials(\.[a-z]+)?$/i,
  /(^|\/)\.aws\/(credentials|config)$/i,
  /(^|\/)\.docker\/config\.json$/i,
  /(^|\/)kubeconfig$|(^|\/)\.kube\/config$/i,
  /\.tfstate(\.backup)?$/i,
  /(^|\/)secrets?\.(ya?ml|json|toml|ini)$/i,
  /(^|\/)[^/]*service[-_]?account[^/]*\.json$/i,
];

export function isSensitivePath(path: string): boolean {
  if (/\.env\.(example|sample|template|dist)$/i.test(path)) return false;
  return SENSITIVE_PATH_PATTERNS.some((r) => r.test(path));
}
