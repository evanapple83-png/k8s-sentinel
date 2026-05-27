import { describe, expect, it, vi } from 'vitest';
import { HermesEngine, assertLocalUrl, extractJson, type FetchLike } from './index.js';
import type { AgentEvent, AgentSpec } from '@k8s-sentinel/core';

const spec: AgentSpec = {
  id: 'analyst',
  systemPrompt: 'You are the Analyst.',
  model: 'hermes-test',
  tools: [{ name: 'trivy', kind: 'cli', config: { binary: 'trivy' } }],
  permission: 'read-only',
  maxTurns: 4,
};

/** Build a fetch that returns scripted chat-completion bodies, in order. */
function scriptedFetch(bodies: unknown[]): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  let i = 0;
  const fetchImpl: FetchLike = async (_url, init) => {
    calls.push(init.body);
    const body = bodies[Math.min(i++, bodies.length - 1)];
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify(body),
      json: async () => body,
    };
  };
  return { fetchImpl, calls };
}

function completion(content: string | null, toolCalls?: unknown) {
  return {
    choices: [{ message: { role: 'assistant', content, tool_calls: toolCalls } }],
    usage: { prompt_tokens: 10, completion_tokens: 5 },
  };
}

describe('assertLocalUrl', () => {
  it('accepts loopback, RFC-1918 and in-cluster hosts', () => {
    for (const url of [
      'http://localhost:8080/v1',
      'http://127.0.0.1:8080/v1',
      'http://10.1.2.3:8080/v1',
      'http://192.168.1.10/v1',
      'http://172.16.0.5/v1',
      'http://hermes/v1',
      'http://hermes.sentinel.svc/v1',
      'http://hermes.sentinel.svc.cluster.local/v1',
    ]) {
      expect(() => assertLocalUrl(url, 'hermes')).not.toThrow();
    }
  });

  it('rejects public hosts (air-gap promise)', () => {
    expect(() => assertLocalUrl('https://api.openai.com/v1', 'hermes')).toThrow(/not local/);
    expect(() => assertLocalUrl('https://example.com/v1', 'hermes')).toThrow(/not local/);
  });
});

describe('HermesEngine constructor', () => {
  const fetchImpl = scriptedFetch([completion('{}')]).fetchImpl;
  it('requires baseUrl and model', () => {
    expect(() => new HermesEngine({ baseUrl: '', model: 'm', fetchImpl })).toThrow(/baseUrl/);
    expect(() => new HermesEngine({ baseUrl: 'http://localhost/v1', model: '', fetchImpl })).toThrow(
      /model/,
    );
  });
  it('rejects a public baseUrl', () => {
    expect(() => new HermesEngine({ baseUrl: 'https://api.openai.com/v1', model: 'm', fetchImpl })).toThrow(
      /air-gap/,
    );
  });
});

describe('HermesEngine.run', () => {
  it('returns structured JSON from a tool-free answer', async () => {
    const { fetchImpl, calls } = scriptedFetch([
      completion('Here is the result:\n```json\n{"risk":"high","paths":2}\n```'),
    ]);
    const engine = new HermesEngine({ baseUrl: 'http://localhost:8080/v1', model: 'm', fetchImpl });
    const run = await engine.run<{ risk: string; paths: number }>(spec, { findings: [] });

    expect(engine.id).toBe('hermes');
    expect(run.result).toEqual({ risk: 'high', paths: 2 });
    expect(run.turns).toBe(1);
    expect(run.usage).toEqual({ inputTokens: 10, outputTokens: 5 });
    // It posted to the local /chat/completions endpoint exactly once.
    expect(calls).toHaveLength(1);
  });

  it('executes a tool call then returns the final answer', async () => {
    const toolCall = [{ id: 'c1', type: 'function', function: { name: 'trivy', arguments: '{"args":{}}' } }];
    const { fetchImpl } = scriptedFetch([
      completion(null, toolCall),
      completion('{"done":true}'),
    ]);
    const toolExecutor = vi.fn(async () => ({ findings: 3 }));
    const engine = new HermesEngine({
      baseUrl: 'http://localhost:8080/v1',
      model: 'm',
      fetchImpl,
      toolExecutor,
    });

    const run = await engine.run<{ done: boolean }>(spec, 'analyze');
    expect(toolExecutor).toHaveBeenCalledOnce();
    expect(run.result).toEqual({ done: true });
    expect(run.turns).toBe(2);
    // usage accumulates across both turns
    expect(run.usage).toEqual({ inputTokens: 20, outputTokens: 10 });
  });

  it('throws a clear EngineError on a non-OK endpoint', async () => {
    const fetchImpl: FetchLike = async () => ({
      ok: false,
      status: 503,
      text: async () => 'model loading',
      json: async () => ({}),
    });
    const engine = new HermesEngine({ baseUrl: 'http://localhost:8080/v1', model: 'm', fetchImpl });
    await expect(engine.run(spec, 'x')).rejects.toThrow(/503/);
  });

  it('caps runaway tool loops', async () => {
    const toolCall = [{ id: 'c', type: 'function', function: { name: 'trivy', arguments: '{}' } }];
    // Always asks for a tool, never finalizes → must hit the cap (spec.maxTurns=4).
    const { fetchImpl } = scriptedFetch([completion(null, toolCall)]);
    const engine = new HermesEngine({ baseUrl: 'http://localhost:8080/v1', model: 'm', fetchImpl });
    await expect(engine.run(spec, 'x')).rejects.toThrow(/exceeded 4 turns/);
  });
});

describe('HermesEngine.stream', () => {
  it('emits start → tool_call → tool_result → message → done', async () => {
    const toolCall = [{ id: 'c1', type: 'function', function: { name: 'trivy', arguments: '{}' } }];
    const { fetchImpl } = scriptedFetch([completion(null, toolCall), completion('all clear')]);
    const engine = new HermesEngine({
      baseUrl: 'http://localhost:8080/v1',
      model: 'm',
      fetchImpl,
      toolExecutor: async () => ({ ok: true }),
    });

    const events: AgentEvent[] = [];
    for await (const ev of engine.stream(spec, 'go')) events.push(ev);

    const types = events.map((e) => e.type);
    expect(types[0]).toBe('start');
    expect(types).toContain('tool_call');
    expect(types).toContain('tool_result');
    expect(types).toContain('message');
    expect(types.at(-1)).toBe('done');
  });
});

describe('extractJson', () => {
  it('parses fenced and bare JSON, undefined otherwise', () => {
    expect(extractJson('```json\n{"a":1}\n```')).toEqual({ a: 1 });
    expect(extractJson('result [1,2]')).toEqual([1, 2]);
    expect(extractJson('no json')).toBeUndefined();
  });
});
