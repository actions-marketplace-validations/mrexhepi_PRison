import { parsePatch, type DiffLine } from '../context/diff.js';
import { patterns } from '../context/priority.js';
import { findSecrets, isSensitivePath } from '../utils/redact.js';
import type { ChangedFile, PolicyTag, ScannerFinding, Severity } from '../types.js';
import { makeFinding } from './finding.js';

export const RULES_SOURCE = 'subq-rules';
export const SECRETS_SOURCE = 'subq-secret-detector';

interface LineRule {
  id: string;
  title: string;
  description: string;
  category: 'security' | 'infrastructure' | 'reliability' | 'compatibility' | 'testing';
  severity: Severity;
  tags: PolicyTag[];
  /** Which diff lines to test. */
  on: 'add' | 'del';
  regex: RegExp;
  /** Restrict to matching file paths. */
  files?: RegExp;
  group: 'terraform' | 'general';
}

const TF_OR_INFRA = /\.(tf|tfvars|hcl|ya?ml|json|bicep)$|Dockerfile/i;
const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|java|kt|cs|php|rs|scala|swift)$/i;

export const LINE_RULES: LineRule[] = [
  {
    id: 'iam-wildcard-action',
    title: 'IAM policy grants wildcard actions',
    description:
      'An added IAM statement allows all actions ("*"), which is a broad privilege expansion.',
    category: 'security',
    severity: 'high',
    tags: ['iam_changes'],
    on: 'add',
    regex:
      /"Action"\s*:\s*\[?\s*"\*"|\bactions\s*=\s*\[\s*"\*"|^\s*-?\s*Action:\s*['"]?\*['"]?\s*$|"[a-z0-9-]+:\*"/i,
    files: TF_OR_INFRA,
    group: 'terraform',
  },
  {
    id: 'iam-admin-role',
    title: 'Administrative role or policy attached',
    description: 'An added line references an administrative role or managed policy.',
    category: 'security',
    severity: 'high',
    tags: ['iam_changes'],
    on: 'add',
    regex:
      /AdministratorAccess|IAMFullAccess|roles\/(owner|editor)\b|\bcluster-admin\b|"Owner"\s*(,|$)/,
    group: 'general',
  },
  {
    id: 'iam-resource-change',
    title: 'IAM or RBAC resource changed',
    description: 'The change adds or edits identity, role or permission resources.',
    category: 'security',
    severity: 'medium',
    tags: ['iam_changes'],
    on: 'add',
    regex:
      /resource\s+"(aws_iam_[a-z_]+|google_[a-z_]*iam_[a-z_]+|azurerm_role_[a-z_]+|kubernetes_(cluster_)?role(_binding)?)"|^\s*kind:\s*(Cluster)?Role(Binding)?\s*$/,
    group: 'terraform',
  },
  {
    id: 'network-open-cidr',
    title: 'Network rule open to the internet',
    description: 'An added network rule references 0.0.0.0/0 or ::/0.',
    category: 'infrastructure',
    severity: 'high',
    tags: ['security_group_changes', 'public_exposure'],
    on: 'add',
    regex: /["'\s[=]0\.0\.0\.0\/0\b|["'\s[=]::\/0\b/,
    files: TF_OR_INFRA,
    group: 'terraform',
  },
  {
    id: 'security-group-change',
    title: 'Security group, firewall or network ACL changed',
    description: 'The change edits network access control resources.',
    category: 'infrastructure',
    severity: 'medium',
    tags: ['security_group_changes'],
    on: 'add',
    regex:
      /resource\s+"(aws_security_group(_rule)?|aws_vpc_security_group_(ingress|egress)_rule|aws_network_acl(_rule)?|google_compute_firewall|azurerm_network_security_(group|rule))"|^\s*(ingress|egress)\s*\{|^\s*(from_port|to_port|cidr_blocks|ipv6_cidr_blocks)\s*=/,
    files: /\.(tf|hcl)$/i,
    group: 'terraform',
  },
  {
    id: 'public-access',
    title: 'Resource made publicly accessible',
    description: 'An added setting enables public access or a wildcard principal.',
    category: 'infrastructure',
    severity: 'high',
    tags: ['public_exposure'],
    on: 'add',
    regex:
      /publicly_accessible\s*=\s*true|\bacl\s*=\s*"public-read(-write)?"|(block_public_acls|block_public_policy|restrict_public_buckets|ignore_public_acls)\s*=\s*false|associate_public_ip_address\s*=\s*true|"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"|\ballUsers\b|\ballAuthenticatedUsers\b/,
    group: 'terraform',
  },
  {
    id: 'encryption-disabled',
    title: 'Encryption disabled',
    description: 'An added setting turns encryption off.',
    category: 'security',
    severity: 'high',
    tags: ['encryption_changes'],
    on: 'add',
    regex:
      /\b(encrypted|storage_encrypted|encryption_enabled|enable_encryption|encrypt_at_rest|at_rest_encryption_enabled|transit_encryption_enabled)\s*[=:]\s*false\b/i,
    group: 'terraform',
  },
  {
    id: 'encryption-removed',
    title: 'Encryption configuration removed',
    description: 'A line configuring encryption or a KMS key was removed.',
    category: 'security',
    severity: 'medium',
    tags: ['encryption_changes'],
    on: 'del',
    regex:
      /\bkms_key_(id|arn)\b|server_side_encryption_configuration|\b(encrypted|storage_encrypted|encryption_enabled)\s*=\s*true/,
    files: /\.(tf|hcl)$/i,
    group: 'terraform',
  },
  {
    id: 'tls-verification-disabled',
    title: 'TLS verification disabled or weakened',
    description: 'An added line disables certificate verification or allows legacy TLS.',
    category: 'security',
    severity: 'high',
    tags: ['tls_changes'],
    on: 'add',
    regex:
      /verify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|ssl_verify\s*[=:]\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|min(imum)?_tls_version\s*=\s*"?(1\.0|1\.1|TLS1_0|TLS1_1|TLSv1(\.1)?)"?|ssl_policy\s*=\s*"ELBSecurityPolicy-(2015|2016)|\bcurl\b[^\n]*\s(-k|--insecure)\b/,
    group: 'general',
  },
  {
    id: 'imds-v1',
    title: 'Instance metadata service v1 allowed',
    description:
      'http_tokens = "optional" permits IMDSv1, which is vulnerable to SSRF credential theft.',
    category: 'security',
    severity: 'medium',
    tags: ['public_exposure'],
    on: 'add',
    regex: /http_tokens\s*=\s*"optional"/,
    files: /\.(tf|hcl)$/i,
    group: 'terraform',
  },
  {
    id: 'destructive-setting',
    title: 'Destructive infrastructure setting',
    description: 'An added setting allows data loss on destroy or disables deletion protection.',
    category: 'infrastructure',
    severity: 'high',
    tags: ['destructive_infrastructure_changes'],
    on: 'add',
    regex:
      /force_destroy\s*=\s*true|prevent_destroy\s*=\s*false|skip_final_snapshot\s*=\s*true|deletion_protection\s*=\s*false|backup_retention_period\s*=\s*0\b/,
    group: 'terraform',
  },
  {
    id: 'protection-removed',
    title: 'Deletion protection removed',
    description: 'A line enabling deletion protection or prevent_destroy was removed.',
    category: 'infrastructure',
    severity: 'high',
    tags: ['destructive_infrastructure_changes'],
    on: 'del',
    regex: /prevent_destroy\s*=\s*true|deletion_protection\s*=\s*true/,
    group: 'terraform',
  },
  {
    id: 'destructive-sql',
    title: 'Destructive database statement',
    description: 'An added statement drops, truncates or rewrites database objects.',
    category: 'compatibility',
    severity: 'high',
    tags: ['database_migrations', 'destructive_infrastructure_changes'],
    on: 'add',
    regex:
      /\b(DROP\s+(TABLE|COLUMN|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|ALTER\s+TABLE\s+\S+\s+(DROP|RENAME)\b)|\b(remove_column|drop_table|drop_column|op\.drop_(table|column))\b/i,
    group: 'general',
  },
  {
    id: 'workflow-pull-request-target',
    title: 'Workflow uses pull_request_target',
    description:
      'pull_request_target runs with write permissions and secrets in the context of the base repository; checking out PR code there is dangerous.',
    category: 'security',
    severity: 'high',
    tags: ['workflow_changes'],
    on: 'add',
    regex: /\bpull_request_target\b/,
    files: patterns.WORKFLOW,
    group: 'general',
  },
  {
    id: 'workflow-broad-permissions',
    title: 'Workflow grants broad token permissions',
    description: 'The workflow requests write-all permissions or inherits all secrets.',
    category: 'security',
    severity: 'high',
    tags: ['workflow_changes'],
    on: 'add',
    regex: /permissions:\s*write-all|secrets:\s*inherit/,
    files: patterns.WORKFLOW,
    group: 'general',
  },
  {
    id: 'workflow-script-injection',
    title: 'Untrusted event data interpolated in workflow',
    description:
      'PR-controlled values interpolated with ${{ }} inside a workflow can lead to script injection.',
    category: 'security',
    severity: 'high',
    tags: ['workflow_changes'],
    on: 'add',
    regex:
      /\$\{\{\s*github\.(event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body|review\.body|head_commit\.message)|head_ref)\s*\}\}/,
    files: patterns.WORKFLOW,
    group: 'general',
  },
  {
    id: 'injection-sink',
    title: 'Potential injection sink',
    description: 'An added line uses a dynamic code, shell, HTML or SQL execution sink.',
    category: 'security',
    severity: 'medium',
    tags: [],
    on: 'add',
    regex:
      /\beval\s*\(|new Function\s*\(|child_process[^\n]*\bexec(Sync)?\s*\(|\bos\.system\s*\(|subprocess\.[a-z_]+\([^)]*shell\s*=\s*True|dangerouslySetInnerHTML|\.innerHTML\s*=|\.(query|execute|raw)\(\s*(f["']|`[^`]*\$\{)/,
    files: CODE,
    group: 'general',
  },
  {
    id: 'probe-removed',
    title: 'Health check or probe removed',
    description: 'A liveness, readiness or health check configuration line was removed.',
    category: 'reliability',
    severity: 'medium',
    tags: ['reliability_settings'],
    on: 'del',
    regex: /livenessProbe|readinessProbe|startupProbe|health_check|healthcheck|HEALTHCHECK/i,
    group: 'general',
  },
  {
    id: 'availability-reduced',
    title: 'Availability or redundancy reduced',
    description: 'An added setting configures a single instance, replica or availability zone.',
    category: 'reliability',
    severity: 'medium',
    tags: ['reliability_settings'],
    on: 'add',
    regex:
      /\b(min_size|desired_count|min_capacity|desired_capacity)\s*=\s*[01]\b|^\s*replicas:\s*[01]\s*$|multi_az\s*=\s*false/,
    group: 'terraform',
  },
  {
    id: 'timeout-retry-change',
    title: 'Timeout or retry setting changed',
    description: 'An added line changes a timeout, retry or backoff value.',
    category: 'reliability',
    severity: 'low',
    tags: ['reliability_settings'],
    on: 'add',
    regex:
      /\b[a-z_]*(timeout|retries|max_retries|max_attempts|retry_count|backoff)[a-z_]*\s*[:=]\s*["']?\d/i,
    group: 'general',
  },
  {
    id: 'resource-limits-change',
    title: 'Resource limits changed',
    description: 'An added line changes CPU or memory limits or requests.',
    category: 'reliability',
    severity: 'low',
    tags: ['reliability_settings'],
    on: 'add',
    regex: /^\s*(cpu|memory)\s*[:=]\s*["']?\d|\b(memory_size|reserved_concurrent_executions)\s*=/,
    files: TF_OR_INFRA,
    group: 'general',
  },
  {
    id: 'monitoring-removed',
    title: 'Monitoring or alerting removed',
    description: 'A monitoring, alarm or logging resource line was removed.',
    category: 'reliability',
    severity: 'medium',
    tags: ['reliability_settings'],
    on: 'del',
    regex:
      /resource\s+"(aws_cloudwatch_metric_alarm|aws_cloudtrail|google_monitoring_alert_policy|azurerm_monitor_[a-z_]+|datadog_monitor)"|enable_logging\s*=\s*true|logging\s*\{/,
    group: 'terraform',
  },
  {
    id: 'audit-logging-disabled',
    title: 'Audit logging disabled',
    description: 'An added setting disables audit or access logging.',
    category: 'security',
    severity: 'high',
    tags: [],
    on: 'add',
    regex:
      /\b(enable_logging|enable_log_file_validation|is_multi_region_trail|access_logs_enabled|audit_log(ging)?_enabled)\s*=\s*false/,
    group: 'terraform',
  },
  {
    id: 'swallowed-error',
    title: 'Error silently swallowed',
    description: 'An added error handler ignores the error.',
    category: 'reliability',
    severity: 'low',
    tags: [],
    on: 'add',
    regex:
      /catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}|except(\s+\w+(\s+as\s+\w+)?)?:\s*pass\b|if err != nil \{\s*\}/,
    files: CODE,
    group: 'general',
  },
  {
    id: 'export-removed',
    title: 'Exported symbol removed or changed',
    description: 'A public export was removed or its signature changed, which may break consumers.',
    category: 'compatibility',
    severity: 'medium',
    tags: [],
    on: 'del',
    regex: /^\s*export\s+(default\s+)?(async\s+)?(function|class|const|interface|type|enum)\s+\w+/,
    files: /\.(ts|tsx|js|mjs)$/i,
    group: 'general',
  },
];

const PROMPT_INJECTION =
  /ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)|disregard\s+(the\s+)?(system|previous|above)|you\s+are\s+now\s+an?\b|\bsystem\s+prompt\b|(mark|rate|classify|score)\s+(this|the)\s+(pr|pull request|change)\s+as\s+(safe|low[\s-]risk|approved)|\brisk[_\s-]?(level|score)\s*[:=]\s*(low|0)\b|\b(auto-?)?approve\s+this\s+(pr|pull request)\b/i;

const PROD_PATH = /(^|\/)(prod|production|prd|live)(\/|[-_.]|$)/i;

export interface RuleScanInput {
  files: ChangedFile[];
  rawPatches: Map<string, string>;
  prTitle: string;
  prBody: string;
  scanSecrets: boolean;
  scanTerraform: boolean;
}

/** Evidence text for a diff line; never quote lines from credential-bearing files. */
function evidenceFor(file: string, line: DiffLine): { evidence?: string } {
  if (isSensitivePath(file)) return {};
  return { evidence: `${line.kind === 'add' ? '+' : '-'} ${line.text}` };
}

function lineFinding(rule: LineRule, file: string, line: DiffLine): ScannerFinding {
  return makeFinding({
    source: RULES_SOURCE,
    category: rule.category,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    file,
    ...(line.kind === 'add' ? { startLine: line.line, endLine: line.line } : {}),
    ruleId: rule.id,
    ...evidenceFor(file, line),
    tags: rule.tags,
    status: 'plausible',
  });
}

/** Run deterministic changed-file rules. Pure: no I/O, no code execution. */
export function runChangedFileRules(input: RuleScanInput): ScannerFinding[] {
  const out: ScannerFinding[] = [];
  const removedTfResources = new Map<string, string>();
  const addedTfResources = new Set<string>();
  let codeAdded = 0;
  let testsTouched = false;

  for (const file of input.files) {
    const path = file.path;
    const raw = input.rawPatches.get(path);
    const parsed = raw ? parsePatch(raw) : undefined;

    if (patterns.TEST.test(path)) testsTouched = true;
    else if (CODE.test(path)) codeAdded += file.additions;

    if (isSensitivePath(path) && file.status !== 'removed' && input.scanSecrets) {
      out.push(
        makeFinding({
          source: SECRETS_SOURCE,
          category: 'security',
          severity: /\.tfstate/i.test(path) ? 'critical' : 'high',
          title: 'Sensitive file added or modified',
          description:
            'The PR touches a file type that commonly holds credentials or state. Its content was not sent to the model.',
          file: path,
          ruleId: 'sensitive-file',
          tags: ['secrets'],
          status: 'plausible',
        }),
      );
    }

    if (input.scanTerraform && file.status === 'removed' && /\.(tf|hcl)$/i.test(path)) {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'infrastructure',
          severity: 'high',
          title: 'Terraform file deleted',
          description: 'Deleting a Terraform file may destroy every resource it declares.',
          file: path,
          ruleId: 'terraform-file-deleted',
          tags: ['destructive_infrastructure_changes'],
          status: 'plausible',
        }),
      );
    }

    if (patterns.MIGRATION.test(path) && file.status !== 'removed') {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'compatibility',
          severity: 'medium',
          title: 'Database migration changed',
          description:
            'Schema migrations can break running services or lose data if not backward compatible.',
          file: path,
          ruleId: 'database-migration',
          tags: ['database_migrations'],
          status: 'plausible',
        }),
      );
    }

    if (patterns.WORKFLOW.test(path)) {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'security',
          severity: 'medium',
          title: 'CI/CD workflow changed',
          description:
            'Workflow changes can alter permissions, secrets exposure and release controls.',
          file: path,
          ruleId: 'workflow-changed',
          tags: ['workflow_changes'],
          status: 'plausible',
        }),
      );
    }

    if (
      PROD_PATH.test(path) &&
      (patterns.TERRAFORM.test(path) || patterns.INFRA_CONFIG.test(path))
    ) {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'infrastructure',
          severity: 'medium',
          title: 'Production infrastructure changed',
          description:
            'The file path indicates production infrastructure or deployment configuration.',
          file: path,
          ruleId: 'production-infrastructure',
          tags: ['production_infrastructure'],
          status: 'plausible',
        }),
      );
    }

    if (
      patterns.DEPENDENCY_MANIFEST.test(path) ||
      (patterns.LOCKFILE.test(path) && file.status !== 'removed')
    ) {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'compatibility',
          severity: 'low',
          title: 'Dependencies changed',
          description:
            'Dependency manifests or lockfiles changed; verify upgrades and new packages.',
          file: path,
          ruleId: 'dependency-change',
          tags: ['dependency_changes'],
          status: 'plausible',
        }),
      );
    }

    if (
      /(^|\/)[^/]*(auth|login|session|oauth|saml|jwt|permission|rbac|acl)[^/]*$/i.test(path) &&
      CODE.test(path)
    ) {
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'security',
          severity: 'medium',
          title: 'Authentication or authorization code changed',
          description: 'Changes to authentication or authorization logic warrant security review.',
          file: path,
          ruleId: 'auth-change',
          tags: ['auth_changes'],
          status: 'plausible',
        }),
      );
    }

    if (!parsed) continue;

    for (const line of parsed.lines) {
      if (line.kind === 'context') continue;

      if (input.scanSecrets && line.kind === 'add') {
        for (const s of findSecrets(line.text)) {
          out.push(
            makeFinding({
              source: SECRETS_SOURCE,
              category: 'security',
              severity: s.severity,
              title: `${s.title} added`,
              description:
                s.confidence === 'confirmed'
                  ? 'A credential with a well-known structured format was added. Rotate it even if the PR is closed.'
                  : 'A value that looks like a hardcoded credential was added.',
              file: path,
              startLine: line.line,
              endLine: line.line,
              ruleId: s.patternId,
              ...evidenceFor(path, line),
              tags: ['secrets'],
              status: s.confidence,
            }),
          );
        }
      }

      if (PROMPT_INJECTION.test(line.text) && line.kind === 'add') {
        out.push(
          makeFinding({
            source: RULES_SOURCE,
            category: 'security',
            severity: 'medium',
            title: 'Possible prompt-injection text in change',
            description:
              'Added content contains instructions aimed at automated reviewers. It is treated as data and cannot change policy.',
            file: path,
            startLine: line.line,
            endLine: line.line,
            ruleId: 'prompt-injection',
            ...evidenceFor(path, line),
            tags: ['prompt_injection'],
            status: 'plausible',
          }),
        );
      }

      if (/\.(tf|hcl)$/i.test(path)) {
        const header = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"/.exec(line.text);
        if (header) {
          const key = `${header[1]}.${header[2]}`;
          if (line.kind === 'del') removedTfResources.set(key, path);
          else addedTfResources.add(key);
        }
      }

      for (const rule of LINE_RULES) {
        if (rule.on !== line.kind) continue;
        if (rule.group === 'terraform' && !input.scanTerraform) continue;
        if (rule.files && !rule.files.test(path)) continue;
        if (rule.regex.test(line.text)) out.push(lineFinding(rule, path, line));
      }
    }
  }

  if (input.scanTerraform) {
    for (const [key, path] of removedTfResources) {
      if (addedTfResources.has(key)) continue;
      out.push(
        makeFinding({
          source: RULES_SOURCE,
          category: 'infrastructure',
          severity: 'high',
          title: `Terraform resource removed: ${key}`,
          description:
            'A resource block was removed and not re-added elsewhere in this PR; applying may destroy it unless a moved/removed block or state operation handles it.',
          file: path,
          ruleId: 'terraform-resource-removed',
          tags: ['destructive_infrastructure_changes'],
          status: 'plausible',
        }),
      );
    }
  }

  if (PROMPT_INJECTION.test(`${input.prTitle}\n${input.prBody}`)) {
    out.push(
      makeFinding({
        source: RULES_SOURCE,
        category: 'security',
        severity: 'medium',
        title: 'Possible prompt-injection text in PR description',
        description:
          'The PR title or description contains instructions aimed at automated reviewers. It is treated as data and cannot change policy.',
        ruleId: 'prompt-injection-description',
        tags: ['prompt_injection'],
        status: 'plausible',
      }),
    );
  }

  if (codeAdded >= 20 && !testsTouched) {
    out.push(
      makeFinding({
        source: RULES_SOURCE,
        category: 'testing',
        severity: 'low',
        title: 'Code changes without test changes',
        description: `${codeAdded} lines of code were added but no test files changed.`,
        ruleId: 'missing-tests',
        tags: ['missing_tests'],
        status: 'insufficient_evidence',
      }),
    );
  }

  return out;
}
