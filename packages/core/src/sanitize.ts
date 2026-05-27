/**
 * Untrusted-input handling (BUILD.md §10).
 *
 * Image tags, annotations, CVE descriptions and raw scanner output are
 * attacker-controlled. Before any of it enters an agent's prompt context we:
 *   1. strip control / zero-width characters used to smuggle instructions,
 *   2. neutralize common prompt-injection trigger phrases,
 *   3. clamp length,
 *   4. wrap the result in an explicit, non-instruction data fence.
 *
 * This is defense-in-depth, not a guarantee — agents are also told to treat
 * fenced content strictly as data.
 */

// Zero-width, bidi, and other invisible/control characters used to hide
// payloads. Deliberately keeps tab (U+0009), newline (U+000A), CR (U+000D).
const INVISIBLE = new RegExp(
  '[' +
    '\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F' + // C0/C1 controls
    '\\u00AD' + // soft hyphen
    '\\u200B-\\u200F' + // zero-width + bidi marks
    '\\u202A-\\u202E' + // bidi embedding/override
    '\\u2060-\\u206F' + // word joiner / invisible math
    '\\uFEFF' + // BOM / zero-width no-break space
    ']',
  'g',
);

/**
 * Phrases that, inside untrusted data, are attempts to hijack the agent.
 * We don't delete content blindly — we defang the imperative so it reads as
 * inert text rather than an instruction.
 */
const INJECTION_PATTERNS: Array<{ re: RegExp; replace: string }> = [
  {
    re: /ignore (all |the |your )?(previous|prior|above)\s+(instructions?|prompts?)/gi,
    replace: '[redacted-injection]',
  },
  { re: /disregard (all |the |your )?(previous|prior|above)/gi, replace: '[redacted-injection]' },
  { re: /you are now\b/gi, replace: '[redacted-injection]' },
  { re: /system\s*:\s*/gi, replace: 'system_ ' },
  { re: /assistant\s*:\s*/gi, replace: 'assistant_ ' },
  { re: /<\/?(system|assistant|user|tool)\b[^>]*>/gi, replace: '[tag]' },
  { re: /\bBEGIN\s+(SYSTEM|PROMPT|INSTRUCTIONS?)\b/gi, replace: '[redacted-injection]' },
  {
    re: /\b(reveal|print|leak|exfiltrate)\s+(the\s+)?(system\s+prompt|secrets?|api[\s_-]?keys?)/gi,
    replace: '[redacted-injection]',
  },
];

const DEFAULT_MAX_LEN = 4000;

export interface SanitizeOptions {
  /** Max characters to keep (clamped, with a truncation marker). */
  maxLength?: number;
  /** Wrap output in a labeled data fence. Default true. */
  fence?: boolean;
  /** Label for the fence (e.g. "trivy-cve-description"). */
  label?: string;
}

/**
 * Sanitize a single untrusted string for safe inclusion in agent context.
 */
export function sanitizeUntrusted(input: unknown, opts: SanitizeOptions = {}): string {
  const { maxLength = DEFAULT_MAX_LEN, fence = true, label = 'untrusted-data' } = opts;

  let text = typeof input === 'string' ? input : safeStringify(input);

  // 1. strip invisible / control characters
  text = text.replace(INVISIBLE, '');

  // 2. neutralize injection imperatives
  for (const { re, replace } of INJECTION_PATTERNS) {
    text = text.replace(re, replace);
  }

  // 3. collapse excessive whitespace (another smuggling vector) and clamp
  text = text.replace(/[ \t]{4,}/g, '   ').replace(/\n{4,}/g, '\n\n\n');
  let truncated = false;
  if (text.length > maxLength) {
    text = text.slice(0, maxLength);
    truncated = true;
  }
  text = text.trim();
  if (truncated) text += '\n…[truncated]';

  // 4. fence: prevent fence-breakout, then wrap
  if (!fence) return text;
  const safeLabel = label.replace(/[^a-z0-9_-]/gi, '');
  text = text.replace(/```/g, "'''");
  return `<<${safeLabel}>>\n${text}\n<</${safeLabel}>>`;
}

/** Recursively sanitize the string leaves of an object (e.g. scanner JSON). */
export function sanitizeObject<T>(value: T, opts: SanitizeOptions = {}): T {
  const inner: SanitizeOptions = { ...opts, fence: false };
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return sanitizeUntrusted(v, inner);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) out[k] = walk(val);
      return out;
    }
    return v;
  };
  return walk(value) as T;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
