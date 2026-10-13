import { redactForOutput } from '../utils/redact.js';
import { truncate } from '../utils/text.js';

/**
 * Escape untrusted text for GitHub-flavored Markdown: no HTML, no links/images, no
 * mentions, no tables breakouts, single line. Secrets are redacted first.
 */
export function md(text: string, max = 500): string {
  const clean = truncate(redactForOutput(text).replace(/[\r\n\t]+/g, ' '), max);
  return clean
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_{}[\]()#+!|~])/g, '\\$1')
    .replace(/@(?=[A-Za-z0-9-])/g, '@​')
    .replace(/^(\s*)-/, '$1\\-')
    .replace(/:\/\//g, ':​//');
}

/** Render untrusted text as an inline code span (safe for paths and evidence). */
export function code(text: string, max = 300): string {
  const clean = truncate(redactForOutput(text).replace(/[\r\n\t]+/g, ' '), max).replace(/`/g, "'");
  return `\`${clean.length ? clean : ' '}\``;
}

/** Plain text for check annotations (rendered as text, not Markdown). */
export function plain(text: string, max: number): string {
  return truncate(
    redactForOutput(text)
      .replace(/[\r\n\t]+/g, ' ')
      // eslint-disable-next-line no-control-regex -- stripping control characters is the point
      .replace(/[\u0000-\u001f\u007f]/g, ''),
    max,
  );
}
