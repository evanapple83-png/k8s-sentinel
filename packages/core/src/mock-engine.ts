import type { AgentEngine, AgentEvent, AgentRun, AgentSpec } from './engine.js';

/** A deterministic responder used to script engine output in tests / offline. */
export type MockResponder = (spec: AgentSpec, input: unknown) => unknown;

/**
 * Offline / test engine. Implements `AgentEngine` with no network calls so the
 * full pipeline can run without an API key. Used as the fallback engine when
 * no credentials are configured. Pass a `responder` to script structured
 * results per agent; the default returns a short acknowledgement string.
 */
export class MockEngine implements AgentEngine {
  readonly id = 'mock';
  constructor(private readonly responder: MockResponder = defaultResponder) {}

  async run<TResult>(spec: AgentSpec, input: unknown): Promise<AgentRun<TResult>> {
    const result = this.responder(spec, input) as TResult;
    return { agent: spec.id, result, turns: 1, usage: { inputTokens: 0, outputTokens: 0 } };
  }

  async *stream(spec: AgentSpec, input: unknown): AsyncIterable<AgentEvent> {
    const ts = new Date().toISOString();
    yield { type: 'start', agent: spec.id, ts };
    yield { type: 'message', agent: spec.id, text: `[mock:${spec.id}] processing` };
    void this.responder(spec, input);
    yield { type: 'done', agent: spec.id, ts: new Date().toISOString() };
  }
}

const defaultResponder: MockResponder = (spec) => `[mock:${spec.id}] ok`;
