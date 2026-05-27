import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

/**
 * Run a binary WITHOUT a shell (argv array → no shell injection). Untrusted
 * values (image tags, namespaces) are passed as discrete args, never
 * interpolated into a command string. Always bounded by a timeout and buffer.
 */
export async function run(
  binary: string,
  args: string[],
  opts: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      timeout: opts.timeoutMs ?? 120_000,
      maxBuffer: 64 * 1024 * 1024,
      env: opts.env ?? process.env,
      windowsHide: true,
    });
    return { stdout, stderr, code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; code?: number; message?: string };
    // Many scanners exit non-zero when they FIND issues — that is not an error
    // for us; the caller decides based on parseability of stdout.
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? e.message ?? '', code: e.code ?? 1 };
  }
}

/** Is a binary resolvable on PATH? */
export async function isOnPath(binary: string): Promise<boolean> {
  const probe = process.platform === 'win32' ? 'where' : 'which';
  const { code } = await run(probe, [binary], { timeoutMs: 5_000 });
  return code === 0;
}
