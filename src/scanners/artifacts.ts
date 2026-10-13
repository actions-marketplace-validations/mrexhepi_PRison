import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import picomatch from 'picomatch';

export const MAX_ARTIFACT_BYTES = 20 * 1024 * 1024;

export class ArtifactError extends Error {
  override readonly name = 'ArtifactError';
  constructor(
    message: string,
    readonly kind: 'missing' | 'invalid',
  ) {
    super(message);
  }
}

function within(root: string, target: string): boolean {
  const rel = relative(root, target);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel) && !rel.startsWith(`..${sep}`));
}

/**
 * Resolve an artifact path that must live inside one of the allowed roots
 * (the workspace or the runner temp dir). Symlinks escaping the roots are rejected.
 */
export async function resolveArtifactPath(p: string, roots: string[]): Promise<string> {
  if (p.includes('\0')) throw new ArtifactError('Artifact path contains a NUL byte.', 'invalid');
  const base = roots[0] ?? process.cwd();
  const abs = isAbsolute(p) ? resolve(p) : resolve(base, p);
  const realRoots = await Promise.all(roots.map((r) => realpath(r).catch(() => resolve(r))));
  if (!roots.some((r) => within(resolve(r), abs))) {
    throw new ArtifactError(`Artifact path '${p}' is outside the workspace.`, 'invalid');
  }
  let real: string;
  try {
    real = await realpath(abs);
  } catch {
    throw new ArtifactError(`Artifact '${p}' was not found.`, 'missing');
  }
  if (!realRoots.some((r) => within(r, real))) {
    throw new ArtifactError(`Artifact path '${p}' resolves outside the workspace.`, 'invalid');
  }
  return real;
}

export async function readArtifact(p: string, roots: string[]): Promise<string> {
  const real = await resolveArtifactPath(p, roots);
  const st = await lstat(real);
  if (!st.isFile()) throw new ArtifactError(`Artifact '${p}' is not a regular file.`, 'invalid');
  if (st.size > MAX_ARTIFACT_BYTES) {
    throw new ArtifactError(`Artifact '${p}' exceeds ${MAX_ARTIFACT_BYTES} bytes.`, 'invalid');
  }
  return readFile(real, 'utf8');
}

export async function readJsonArtifact(p: string, roots: string[]): Promise<unknown> {
  const text = await readArtifact(p, roots);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ArtifactError(`Artifact '${p}' is not valid JSON.`, 'invalid');
  }
}

/** Expand simple glob patterns (relative to the first root) into files; bounded. */
export async function expandArtifactGlobs(
  patternsIn: string[],
  roots: string[],
  max = 50,
): Promise<string[]> {
  const base = roots[0] ?? process.cwd();
  const out = new Set<string>();
  for (const pattern of patternsIn) {
    if (!/[*?[{]/.test(pattern)) {
      out.add(pattern);
      continue;
    }
    if (isAbsolute(pattern) || pattern.split(/[\\/]/).includes('..')) {
      throw new ArtifactError(
        `Glob '${pattern}' must be workspace-relative without '..'.`,
        'invalid',
      );
    }
    const isMatch = picomatch(pattern, { dot: false });
    const walk = async (dir: string, depth: number): Promise<void> => {
      if (depth > 6 || out.size >= max) return;
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (e.name === 'node_modules' || e.name === '.git') continue;
        const full = join(dir, e.name);
        if (e.isDirectory()) await walk(full, depth + 1);
        else if (e.isFile() && isMatch(relative(base, full).split(sep).join('/'))) out.add(full);
      }
    };
    await walk(base, 0);
  }
  return [...out].slice(0, max);
}
