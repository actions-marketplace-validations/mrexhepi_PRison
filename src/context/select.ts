import { posix } from 'node:path';
import { isSensitivePath, redactSecrets } from '../utils/redact.js';
import { estimateTokens } from '../utils/text.js';
import type { GitHubApi } from '../github/api.js';
import type { ChangedFile, ContextFile, Mode, RepositoryContext } from '../types.js';
import { filePriority, patterns } from './priority.js';

export interface Candidate {
  path: string;
  reason: string;
  priority: number;
}

const MAX_FILE_CHARS = 40_000;
const TF_SUPPORT = /(^|\/)(variables|providers?|versions|main|outputs|backend|locals|data)\.tf$/i;

/** Normalize a repository-relative path; returns undefined if it escapes the repo root. */
export function normalizeRepoPath(p: string): string | undefined {
  if (p.includes('\0') || p.startsWith('/')) return undefined;
  const n = posix.normalize(p);
  if (n === '..' || n.startsWith('../') || n === '.' || n === '') return undefined;
  return n;
}

/** Extract local Terraform module sources (`source = "./modules/x"`) from patch text. */
export function localModuleSources(fromFile: string, patch: string): string[] {
  const out = new Set<string>();
  const re = /^[+ ]\s*source\s*=\s*"(\.{1,2}\/[^"]+)"/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(patch)) !== null) {
    const target = normalizeRepoPath(posix.join(posix.dirname(fromFile), m[1] ?? ''));
    if (target) out.add(target);
  }
  return [...out];
}

/**
 * Deterministically choose which additional repository files are worth sending as
 * context. Pure function so it can be unit tested without GitHub.
 */
export function selectContextCandidates(
  changed: ChangedFile[],
  rawPatches: Map<string, string>,
  treePaths: string[],
  mode: Mode,
): Candidate[] {
  const tree = new Set(treePaths);
  const changedSet = new Set(changed.map((c) => c.path));
  const candidates = new Map<string, Candidate>();
  const add = (path: string, reason: string, priority: number) => {
    if (isSensitivePath(path) || !tree.has(path)) return;
    const prev = candidates.get(path);
    if (!prev || prev.priority < priority) candidates.set(path, { path, reason, priority });
  };

  for (const file of changed) {
    if (file.status === 'removed' || file.sensitive) continue;
    const dir = posix.dirname(file.path);
    const base = posix.basename(file.path);
    const prio = filePriority(file.path, mode);

    // Full head version of modified high-impact files gives surrounding code.
    if (file.status !== 'added' && prio >= 50 && !patterns.LOCKFILE.test(file.path)) {
      add(file.path, 'full version of changed file (surrounding code)', prio);
    }

    if (patterns.TERRAFORM.test(file.path)) {
      const bonus = mode === 'terraform' ? 20 : 0;
      for (const p of treePaths) {
        if (posix.dirname(p) === dir && !changedSet.has(p) && TF_SUPPORT.test(p)) {
          add(p, `Terraform configuration in the same module as ${file.path}`, 60 + bonus);
        }
      }
      const patch = rawPatches.get(file.path);
      if (patch) {
        for (const mod of localModuleSources(file.path, patch)) {
          for (const p of treePaths) {
            if (posix.dirname(p) === mod && /(variables|main|outputs)\.tf$/.test(p)) {
              add(p, `interface of local module ${mod} referenced by ${file.path}`, 55 + bonus);
            }
          }
        }
      }
    }

    if (patterns.LOCKFILE.test(file.path) || patterns.DEPENDENCY_MANIFEST.test(file.path)) {
      for (const p of treePaths) {
        if (
          posix.dirname(p) === dir &&
          patterns.DEPENDENCY_MANIFEST.test(p) &&
          !changedSet.has(p)
        ) {
          add(p, `dependency manifest next to ${file.path}`, mode === 'dependencies' ? 80 : 40);
        }
      }
    }

    // Related tests: test files whose name contains the changed file's stem.
    if (!patterns.TEST.test(file.path) && !patterns.DOCS.test(file.path)) {
      const stem = base.replace(/\.[^.]+$/, '');
      if (stem.length >= 3) {
        for (const p of treePaths) {
          if (patterns.TEST.test(p) && posix.basename(p).startsWith(stem + '.')) {
            add(p, `existing tests related to ${file.path}`, 35);
          } else if (patterns.TEST.test(p) && posix.basename(p).startsWith(stem + '_test')) {
            add(p, `existing tests related to ${file.path}`, 35);
          }
        }
      }
    }

    if (mode === 'security' && patterns.SECURITY_PATH.test(file.path)) {
      for (const p of treePaths) {
        if (posix.dirname(p) === dir && patterns.SECURITY_PATH.test(p) && !changedSet.has(p)) {
          add(p, `security configuration next to ${file.path}`, 50);
        }
      }
    }
  }

  for (const owners of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    add(owners, 'code ownership rules', 20);
  }

  return [...candidates.values()].sort(
    (a, b) => b.priority - a.priority || a.path.localeCompare(b.path),
  );
}

export async function collectRepositoryContext(
  api: GitHubApi,
  args: {
    owner: string;
    repo: string;
    headSha: string;
    changed: ChangedFile[];
    rawPatches: Map<string, string>;
    mode: Mode;
    maxFiles: number;
    tokenBudget: number;
    log?: (msg: string) => void;
  },
): Promise<RepositoryContext> {
  const files: ContextFile[] = [];
  const omitted: { path: string; reason: string }[] = [];
  if (args.maxFiles === 0) return { files, omitted, treeTruncated: false };

  let tree: { paths: string[]; truncated: boolean };
  try {
    tree = await api.getTree(args.owner, args.repo, args.headSha);
  } catch (err) {
    args.log?.(`Could not list repository tree: ${err instanceof Error ? err.message : err}`);
    return {
      files,
      omitted: [{ path: '(repository tree)', reason: 'tree listing failed' }],
      treeTruncated: true,
    };
  }

  const candidates = selectContextCandidates(args.changed, args.rawPatches, tree.paths, args.mode);
  let budget = args.tokenBudget;
  for (const c of candidates) {
    if (files.length >= args.maxFiles) {
      omitted.push({ path: c.path, reason: 'context-files limit reached' });
      continue;
    }
    if (budget <= 0) {
      omitted.push({ path: c.path, reason: 'context token budget exhausted' });
      continue;
    }
    let content;
    try {
      content = await api.getFileContent(args.owner, args.repo, c.path, args.headSha);
    } catch {
      omitted.push({ path: c.path, reason: 'fetch failed' });
      continue;
    }
    if (!content || content.text === null) {
      omitted.push({ path: c.path, reason: 'binary, missing or larger than 512 KiB' });
      continue;
    }
    let text = redactSecrets(content.text);
    let truncated = false;
    const maxChars = Math.min(MAX_FILE_CHARS, budget * 3);
    if (text.length > maxChars) {
      text = text.slice(0, maxChars);
      truncated = true;
    }
    budget -= estimateTokens(text);
    files.push({ path: c.path, reason: c.reason, content: text, truncated });
  }
  return { files, omitted, treeTruncated: tree.truncated };
}
