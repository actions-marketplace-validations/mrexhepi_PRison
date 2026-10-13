import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { parseInputs } from '../../src/config/inputs.js';
import { parseRepoConfig } from '../../src/config/load.js';

const root = join(import.meta.dirname, '..', '..');
const read = (p: string) => readFileSync(join(root, p), 'utf8');

describe('distribution metadata', () => {
  const action = parse(read('action.yml')) as {
    runs: { using: string; main: string };
    inputs: Record<string, { default?: string }>;
    outputs: Record<string, unknown>;
  };

  it('is a node24 JavaScript action pointing at the bundle', () => {
    expect(action.runs).toEqual({ using: 'node24', main: 'dist/index.js' });
  });

  it('declares exactly the inputs the code reads', () => {
    const read: string[] = [];
    parseInputs((n) => {
      read.push(n);
      return '';
    });
    expect(Object.keys(action.inputs).sort()).toEqual([...new Set(read)].sort());
  });

  it('declares every output the code sets', () => {
    const src = read('src/main.ts');
    const set = [...src.matchAll(/setOutput\('([a-z-]+)'/g)].map((m) => m[1]);
    for (const o of set) expect(Object.keys(action.outputs)).toContain(o);
  });

  it('example repository config is valid', () => {
    expect(() => parseRepoConfig(read('examples/subq-pr-risk.yml'), 'example')).not.toThrow();
  });

  it('examples reference the published action and pin third-party actions to SHAs', () => {
    for (const f of ['examples/basic.yml', 'examples/terraform.yml', 'examples/security.yml']) {
      const text = read(f);
      expect(text).toContain('uses: mrexhepi/PRison@v1');
      expect(text).toContain('secrets.SUBQ_API_KEY');
      expect(text).not.toContain('pull_request_target');
      for (const m of text.matchAll(/uses:\s*([^\s#]+)/g)) {
        const ref = m[1]!;
        if (ref.startsWith('mrexhepi/PRison')) continue;
        expect(ref).toMatch(/@[0-9a-f]{40}$/);
      }
    }
  });
});
