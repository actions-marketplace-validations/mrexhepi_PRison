import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';

// 1. dist/index.js exists and is non-trivial.
if (!existsSync('dist/index.js') || statSync('dist/index.js').size < 10_000) {
  console.error('dist/index.js is missing or unexpectedly small. Run `npm run build`.');
  process.exit(1);
}

// 2. action.yml points at the bundle and uses a supported runtime.
const action = readFileSync('action.yml', 'utf8');
if (
  !/^\s+using:\s*['"]?node24['"]?\s*$/m.test(action) ||
  !/^\s+main:\s*['"]?dist\/index\.js['"]?\s*$/m.test(action)
) {
  console.error('action.yml must declare runs.using: node24 and runs.main: dist/index.js');
  process.exit(1);
}

// 3. The bundle must not import packages from node_modules at runtime.
const bundle = readFileSync('dist/index.js', 'utf8');
const bare = [
  ...bundle.matchAll(/^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"./][^'"]*)['"]/gm),
  ...bundle.matchAll(/\brequire\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g),
]
  .map((m) => m[1])
  .filter((s) => !s.startsWith('node:'));
const builtins = new Set((await import('node:module')).builtinModules);
const external = bare.filter((s) => !builtins.has(s.split('/')[0]));
if (external.length) {
  console.error(`dist/index.js imports non-bundled packages: ${[...new Set(external)].join(', ')}`);
  process.exit(1);
}

// 4. dist/ matches a fresh build (only when running in a git checkout).
try {
  const diff = execFileSync('git', ['status', '--porcelain', '--', 'dist'], { encoding: 'utf8' });
  if (diff.trim()) {
    console.error(
      'dist/ differs from the committed version. Run `npm run build` and commit dist/.',
    );
    console.error(diff);
    process.exit(1);
  }
} catch {
  console.warn('git not available; skipped dist freshness check.');
}
console.log('dist/index.js verified.');
