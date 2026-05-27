/**
 * Tiny, dependency-free unified-diff generator.
 *
 * Remediations are emitted as reviewable patches (BUILD.md §10 — "propose,
 * don't apply"). We synthesize a representative manifest and its hardened
 * version, then render a real unified diff a human can read and a tool can
 * `git apply`. LCS-based so removals/replacements line up correctly; the whole
 * file is emitted as a single hunk (manifests are small).
 */

type Tag = ' ' | '-' | '+';

/** LCS line alignment of `a` → `b`. Deterministic. */
function lcsDiff(a: string[], b: string[]): Array<{ t: Tag; v: string }> {
  const n = a.length;
  const m = b.length;
  // dp[i][j] = LCS length of a[i:] and b[j:]
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const out: Array<{ t: Tag; v: string }> = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ t: ' ', v: a[i]! });
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      out.push({ t: '-', v: a[i]! });
      i++;
    } else {
      out.push({ t: '+', v: b[j]! });
      j++;
    }
  }
  while (i < n) out.push({ t: '-', v: a[i++]! });
  while (j < m) out.push({ t: '+', v: b[j++]! });
  return out;
}

/**
 * Render a unified diff for one file. An empty `beforeText` means a new file
 * (`--- /dev/null`). The full file is a single hunk.
 */
export function unifiedDiff(path: string, beforeText: string, afterText: string): string {
  const a = beforeText.length ? beforeText.replace(/\n$/, '').split('\n') : [];
  const b = afterText.length ? afterText.replace(/\n$/, '').split('\n') : [];
  const ops = lcsDiff(a, b);

  const left = a.length === 0 ? '/dev/null' : `a/${path}`;
  const right = b.length === 0 ? '/dev/null' : `b/${path}`;
  const header =
    `--- ${left}\n+++ ${right}\n` +
    `@@ -${a.length === 0 ? 0 : 1},${a.length} +${b.length === 0 ? 0 : 1},${b.length} @@\n`;

  const body = ops.map((o) => `${o.t}${o.v}`).join('\n');
  return header + body + '\n';
}
