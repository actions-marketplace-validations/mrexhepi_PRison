import { build } from 'esbuild';

// Produces a single self-contained ESM bundle. Deterministic output (no timestamps,
// no absolute paths) so CI can verify dist/ is up to date.
await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.js',
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'esm',
  minify: false,
  sourcemap: false,
  legalComments: 'eof',
  logLevel: 'info',
  banner: {
    js: "import { createRequire as __subqCreateRequire } from 'node:module'; const require = __subqCreateRequire(import.meta.url);",
  },
});
