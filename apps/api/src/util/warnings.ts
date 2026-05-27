/**
 * `node:sqlite` is still flagged experimental and emits an ExperimentalWarning
 * on first use. Suppress just that one warning so CLI output stays clean,
 * without hiding other process warnings.
 */
export function silenceExperimentalWarnings(): void {
  const original = process.emitWarning.bind(process);
  process.emitWarning = ((warning: string | Error, ...args: unknown[]) => {
    const name = typeof warning === 'string' ? args[0] : (warning as Error).name;
    const text = typeof warning === 'string' ? warning : (warning as Error).message;
    if (name === 'ExperimentalWarning' && /SQLite/i.test(String(text))) return;
    // @ts-expect-error pass through original overloads
    return original(warning, ...args);
  }) as typeof process.emitWarning;
}
