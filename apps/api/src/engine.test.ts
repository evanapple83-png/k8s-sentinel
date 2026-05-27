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

  it('returns the hermes (air-gap) engine when configured', async () => {
    const engine = await createEngine({
      ...base,
      engine: 'hermes',
      hermes: { baseUrl: 'http://localhost:8080/v1', model: 'NousResearch/Hermes-4-70B' },
    });
    expect(engine.id).toBe('hermes');
  });

  it('refuses a public hermes endpoint (air-gap promise)', async () => {
    await expect(
      createEngine({
        ...base,
        engine: 'hermes',
        hermes: { baseUrl: 'https://api.openai.com/v1', model: 'm' },
      }),
    ).rejects.toThrow(/air-gap|not local/);
  });
});
