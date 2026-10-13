export interface DiffLine {
  kind: 'add' | 'del' | 'context';
  /** Line number in the new file (add/context) or old file (del). */
  line: number;
  text: string;
}

export interface ParsedPatch {
  lines: DiffLine[];
  addedLines: number[];
  /** Lines covered by hunks in the new file, valid targets for annotations. */
  newFileLines: Set<number>;
  malformed: boolean;
}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** Parse a GitHub unified-diff `patch` fragment (hunks only, no file headers). */
export function parsePatch(patch: string): ParsedPatch {
  const lines: DiffLine[] = [];
  const addedLines: number[] = [];
  const newFileLines = new Set<number>();
  let oldLine = 0;
  let newLine = 0;
  let inHunk = false;
  let malformed = false;

  for (const raw of patch.split('\n')) {
    const h = HUNK.exec(raw);
    if (h) {
      oldLine = Number(h[1]);
      newLine = Number(h[3]);
      inHunk = true;
      continue;
    }
    if (!inHunk) {
      if (raw.trim() !== '') malformed = true;
      continue;
    }
    if (raw.startsWith('\\')) continue; // "\ No newline at end of file"
    const marker = raw[0];
    const text = raw.slice(1);
    if (marker === '+') {
      lines.push({ kind: 'add', line: newLine, text });
      addedLines.push(newLine);
      newFileLines.add(newLine);
      newLine++;
    } else if (marker === '-') {
      lines.push({ kind: 'del', line: oldLine, text });
      oldLine++;
    } else if (marker === ' ' || raw === '') {
      lines.push({ kind: 'context', line: newLine, text });
      newFileLines.add(newLine);
      oldLine++;
      newLine++;
    } else {
      malformed = true;
    }
  }
  return { lines, addedLines, newFileLines, malformed };
}

export function countPatchLines(patch: string): number {
  let n = 0;
  for (const l of patch.split('\n')) {
    if ((l.startsWith('+') || l.startsWith('-')) && !l.startsWith('+++') && !l.startsWith('---'))
      n++;
  }
  return n;
}
