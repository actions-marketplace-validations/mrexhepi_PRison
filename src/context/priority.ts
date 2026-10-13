import type { Mode } from '../types.js';

const TERRAFORM = /\.(tf|tfvars|hcl)$|(^|\/)\.terraform\.lock\.hcl$|terragrunt\.hcl$/i;
const SECURITY_PATH =
  /(auth|iam|security|policy|policies|permission|rbac|acl|firewall|network|ingress|egress|tls|ssl|cert|crypto|secret|token|session|oauth|saml|jwt|cors|csp)/i;
const WORKFLOW = /^\.github\/workflows\/.+\.ya?ml$/i;
const DEPENDENCY_MANIFEST =
  /(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|go\.mod|Cargo\.toml|Gemfile|pom\.xml|build\.gradle(\.kts)?|composer\.json|\.csproj)$/i;
const LOCKFILE =
  /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|poetry\.lock|go\.sum|Cargo\.lock|Gemfile\.lock|composer\.lock)$/i;
const INFRA_CONFIG =
  /(Dockerfile|docker-compose[^/]*\.ya?ml|\.ya?ml$|helm|k8s|kubernetes|charts\/|cloudformation|\.bicep$|serverless\.ya?ml)/i;
const MIGRATION = /(^|\/)(migrations?|migrate|db\/schema|alembic|flyway|liquibase)(\/|$)|\.sql$/i;
const DOCS = /\.(md|mdx|rst|txt|adoc)$|(^|\/)docs?\//i;
const TEST = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[a-z]+$|_test\.(go|py)$/i;

export const patterns = {
  TERRAFORM,
  SECURITY_PATH,
  WORKFLOW,
  DEPENDENCY_MANIFEST,
  LOCKFILE,
  INFRA_CONFIG,
  MIGRATION,
  DOCS,
  TEST,
};

/**
 * Deterministic priority for a changed or context file. Higher is more important.
 * Used to decide which patches fit the diff budget and which context files to fetch.
 */
export function filePriority(path: string, mode: Mode): number {
  let score: number;
  if (WORKFLOW.test(path)) score = 80;
  else if (TERRAFORM.test(path)) score = mode === 'terraform' ? 100 : 70;
  else if (MIGRATION.test(path)) score = 70;
  else if (DEPENDENCY_MANIFEST.test(path)) score = mode === 'dependencies' ? 100 : 55;
  else if (LOCKFILE.test(path)) score = mode === 'dependencies' ? 60 : 5;
  else if (SECURITY_PATH.test(path)) score = mode === 'security' ? 100 : 65;
  else if (INFRA_CONFIG.test(path)) score = mode === 'terraform' ? 75 : 50;
  else if (TEST.test(path)) score = 30;
  else if (DOCS.test(path)) score = 3;
  else score = 40;
  if (mode === 'security' && SECURITY_PATH.test(path)) score = Math.max(score, 95);
  return score;
}

export function isDocsOnly(paths: string[]): boolean {
  return paths.length > 0 && paths.every((p) => DOCS.test(p) && !WORKFLOW.test(p));
}
