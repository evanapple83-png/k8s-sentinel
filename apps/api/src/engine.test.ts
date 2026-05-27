import { describe, expect, it } from 'vitest';
import { createEngine } from './engine.js';
import type { SentinelConfig } from './config.js';

const base: SentinelConfig = {
  engine: 'mock',
  useBedrock: false,
  useVertex: false,
  models: { collector: 'm', analyst: 'm', author: 'm' },
  hermes: { baseUrl: 'http://localhost', model: 'h' },
  dbPath: ':memory:',
  apiPort: 8787,
};

describe('createEngine', () => {
  it('returns the mock engine when configured', async () => {
    const engine = await createEngine(base);
    expect(engine.id).toBe('mock');
  });

  it('returns the claude engine when configured', async () => {
    const engine = await createEngine({ ...base, engine: 'claude' });
    expect(engine.id).toBe('claude');
  });

  it('throws a clear error when hermes is selected before Phase 4', async () => {
    await expect(createEngine({ ...base, engine: 'hermes' })).rejects.toThrow(/Hermes/);
  });
});
