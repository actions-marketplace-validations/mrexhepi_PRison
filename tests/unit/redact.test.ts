import { afterEach, describe, expect, it } from 'vitest';
import {
  clearRegisteredSecrets,
  findSecrets,
  isSensitivePath,
  redactForOutput,
  redactSecrets,
  registerSecret,
} from '../../src/utils/redact.js';

const PRIVATE_KEY =
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';

describe('secret detection', () => {
  it.each([
    ['AKIAIOSFODNN7EXAMPLE', 'aws-access-key-id'],
    ['ghp_' + 'a'.repeat(36), 'github-token'],
    ['github_pat_' + 'A'.repeat(60), 'github-token'],
    ['xoxb-1234567890-abcdefghij', 'slack-token'],
    ['sk_live_' + 'a'.repeat(24), 'stripe-secret-key'],
    ['AIza' + 'a'.repeat(35), 'google-api-key'],
    [PRIVATE_KEY, 'private-key'],
    ['postgres://admin:hunter2pass@db.internal:5432/x', 'url-credentials'],
    ['DB_PASSWORD = "s3cr3tValue1234"', 'generic-secret-assignment'],
  ])('detects %s', (text, id) => {
    expect(findSecrets(text).map((m) => m.patternId)).toContain(id);
    expect(redactSecrets(text)).toContain(`[REDACTED:${id}]`);
  });

  it('ignores placeholders and ordinary text', () => {
    expect(findSecrets('password = "changeme"')).toHaveLength(0);
    expect(findSecrets('password = "<your-password>"')).toHaveLength(0);
    expect(findSecrets('const total = computeTotal(items);')).toHaveLength(0);
  });

  it('is idempotent', () => {
    const once = redactSecrets('AKIAIOSFODNN7EXAMPLE');
    expect(redactSecrets(once)).toBe(once);
  });
});

describe('output redaction', () => {
  afterEach(() => clearRegisteredSecrets());

  it('removes registered secrets and authorization headers', () => {
    registerSecret('my-subq-token-value');
    const s = redactForOutput(
      'failed with my-subq-token-value; Authorization: Bearer abcdefghijklmnop; header authorization=xyz123',
    );
    expect(s).not.toContain('my-subq-token-value');
    expect(s).not.toContain('abcdefghijklmnop');
    expect(s).not.toContain('xyz123');
  });
});

describe('sensitive paths', () => {
  it.each([
    '.env',
    'app/.env.production',
    'id_rsa',
    'certs/server.key',
    'tls.pem',
    'terraform.tfstate',
    '.npmrc',
    'config/secrets.yml',
    'gcp-service-account.json',
    '.aws/credentials',
  ])('flags %s', (p) => expect(isSensitivePath(p)).toBe(true));
  it.each(['.env.example', 'src/env.ts', 'main.tf', 'README.md', 'variables.tfvars'])(
    'allows %s',
    (p) => expect(isSensitivePath(p)).toBe(false),
  );
});
