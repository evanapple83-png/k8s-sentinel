import {
  EngineError,
  type AgentEngine,
  type AgentEvent,
  type AgentRun,
  type AgentSpec,
  type ToolRef,
} from '@k8s-sentinel/core';

/**
 * Hermes adapter (AIR-GAP engine, BUILD.md §1, §5, Phase 4).
 *
 * Hermes (Nous Research, MIT) is model-agnostic, local-first, and emits no
 * telemetry, so it can drive a self-hosted open-weight model with ZERO external
 * calls — the option for disconnected / classified networks. It speaks the
 * OpenAI-compatible Chat Completions API that every common local server (vLLM,
 * llama.cpp, Ollama, TGI, LM Studio) exposes, so this adapter is dependency-free
 * and talks to exactly one endpoint: the configured local `baseUrl`.
 *
 * The engine boundary is sacred: agents/IP only see the `AgentEngine` interface,
 * so swapping Claude ↔ Hermes requires no change above the composition root.
 */
export class HermesEngine implements AgentEngine {
  readonly id = 'hermes';
  private readonly fetchImpl: FetchLike;

  constructor(private readonly config: HermesEngineConfig) {
    if (!config.baseUrl) throw new EngineError('Hermes baseUrl is required', this.id);
    if (!config.model) throw new EngineError('Hermes model is required', this.id);
    assertLocalUrl(config.baseUrl, this.id);
    const resolved = config.fetchImpl ?? globalFetch();
    if (!resolved) {
      throw new EngineError(
        'No fetch implementation available (need Node ≥ 20 global fetch or an injected fetchImpl)',
        this.id,
      );
    }
    this.fetchImpl = resolved;
  }

  async run<TResult>(spec: AgentSpec, input: unknown): Promise<AgentRun<TResult>> {
    let last = '';
    let turns = 0;
    const usage: NonNullable<AgentRun<TResult>['usage']> = { inputTokens: 0, outputTokens: 0 };

    for await (const ev of this.loop(spec, input)) {
      if (ev.type === 'turn') {
        turns = ev.turns;
        usage.inputTokens = (usage.inputTokens ?? 0) + ev.usage.inputTokens;
        usage.outputTokens = (usage.outputTokens ?? 0) + ev.usage.outputTokens;
        if (ev.final) last = ev.text;
      } else if (ev.type === 'error') {
        throw new EngineError(ev.message, this.id);
      }
    }

    const result = (extractJson(last) ?? last) as TResult;
    return { agent: spec.id, result, turns, usage };
  }

  async *stream(spec: AgentSpec, input: unknown): AsyncIterable<AgentEvent> {
    yield { type: 'start', agent: spec.id, ts: new Date().toISOString() };
    try {
      for await (const ev of this.loop(spec, input)) {
        if (ev.type === 'assistant_text') {
          if (ev.text.trim()) yield { type: 'message', agent: spec.id, text: ev.text };
        } else if (ev.type === 'tool_call') {
          yield { type: 'tool_call', agent: spec.id, tool: ev.tool, input: ev.input };
        } else if (ev.type === 'tool_result') {
          yield { type: 'tool_result', agent: spec.id, tool: ev.tool, output: ev.output };
        } else if (ev.type === 'error') {
          yield { type: 'error', agent: spec.id, message: ev.message };
        }
      }
    } catch (err) {
      yield { type: 'error', agent: spec.id, message: (err as Error).message };
    }
    yield { type: 'done', agent: spec.id, ts: new Date().toISOString() };
  }

  /**
   * Single agent turn-loop shared by run()/stream(). Calls the local model,
   * executes any requested tools, feeds results back, and stops on a tool-free
   * answer or the turn cap. Bounded by `maxTurns` so a runaway model can't loop.
   */
  private async *loop(spec: AgentSpec, input: unknown): AsyncIterable<LoopEvent> {
    const messages: ChatMessage[] = [
      { role: 'system', content: spec.systemPrompt },
      { role: 'user', content: renderPrompt(input) },
    ];
    const tools = toOpenAiTools(spec.tools);
    const exec = this.config.toolExecutor ?? defaultToolExecutor;
    const cap = boundTurns(spec.maxTurns, this.config.maxTurnsCap);

    for (let turn = 1; turn <= cap; turn++) {
      const choice = await this.complete(spec, messages, tools);
      const msg = choice.message;
      const text = typeof msg.content === 'string' ? msg.content : '';
      const calls = msg.tool_calls ?? [];

      yield {
        type: 'turn',
        turns: turn,
        text,
        final: calls.length === 0,
        usage: choice.usage,
      };
      if (text.trim()) yield { type: 'assistant_text', text };

      if (calls.length === 0) return; // tool-free answer → done

      // Echo the assistant's tool-call turn, then run each tool and feed results back.
      messages.push({ role: 'assistant', content: msg.content ?? '', tool_calls: calls });
      for (const call of calls) {
        const args = safeParse(call.function.arguments);
        yield { type: 'tool_call', tool: call.function.name, input: args };
        const output = await exec({ name: call.function.name, arguments: args });
        yield { type: 'tool_result', tool: call.function.name, output };
        messages.push({
          role: 'tool',
          tool_call_id: call.id,
          content: typeof output === 'string' ? output : JSON.stringify(output),
        });
      }
    }
    yield { type: 'error', message: `Hermes exceeded ${cap} turns without a final answer` };
  }

  /** One POST to the OpenAI-compatible /chat/completions endpoint. */
  private async complete(
    spec: AgentSpec,
    messages: ChatMessage[],
    tools: OpenAiTool[],
  ): Promise<{ message: ChatMessage; usage: TurnUsage }> {
    const url = `${trimSlash(this.config.baseUrl)}/chat/completions`;
    const body: ChatRequest = {
      model: spec.model || this.config.model,
      messages,
      temperature: this.config.temperature ?? 0,
      stream: false,
      ...(tools.length ? { tools, tool_choice: 'auto' } : {}),
    };

    const headers: Record<string, string> = { 'content-type': 'application/json' };
    // Most local servers ignore auth; send it only when a token is configured.
    if (this.config.apiKey) headers.authorization = `Bearer ${this.config.apiKey}`;

    const res = await withTimeout(
      this.fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(body) }),
      this.config.requestTimeoutMs ?? 120_000,
      this.id,
    );
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new EngineError(`Hermes endpoint returned ${res.status}: ${truncate(detail)}`, this.id);
    }

    const json = (await res.json()) as ChatResponse;
    const message = json.choices?.[0]?.message;
    if (!message) throw new EngineError('Hermes response had no choices', this.id);
    return {
      message,
      usage: {
        inputTokens: json.usage?.prompt_tokens ?? 0,
        outputTokens: json.usage?.completion_tokens ?? 0,
      },
    };
  }
}

export interface HermesEngineConfig {
  /** Local OpenAI-compatible endpoint, e.g. "http://localhost:8080/v1". */
  baseUrl: string;
  /** Default model id served locally, e.g. "NousResearch/Hermes-4-70B". */
  model: string;
  /** Optional bearer token (most local servers don't need one). */
  apiKey?: string;
  /** Deterministic by default for a security tool. */
  temperature?: number;
  /** Per-request timeout (ms). */
  requestTimeoutMs?: number;
  /** Hard ceiling on agent turns; overrides spec.maxTurns when smaller. */
  maxTurnsCap?: number;
  /** Injectable fetch (tests / custom transport). Defaults to global fetch. */
  fetchImpl?: FetchLike;
  /**
   * Executes a tool the model asked for. In our pipeline scanners run in the
   * deterministic Collector, not via the model, so the default tells the model
   * the tool is unavailable and to reason from the context it was given.
   */
  toolExecutor?: ToolExecutor;
}

export type ToolExecutor = (call: { name: string; arguments: unknown }) => Promise<unknown> | unknown;

// --- Air-gap guard ----------------------------------------------------------

/**
 * Refuse a clearly public endpoint by default — the air-gap promise is that
 * Hermes only ever reaches a local/in-cluster model. We allow loopback,
 * RFC-1918 / unique-local ranges, and in-cluster names (no dot or *.local,
 * *.svc, *.cluster.local). A reachable public host would be a misconfiguration.
 */
export function assertLocalUrl(baseUrl: string, engineId: string): void {
  let host: string;
  try {
    host = new URL(baseUrl).hostname.toLowerCase();
  } catch {
    throw new EngineError(`Hermes baseUrl is not a valid URL: ${baseUrl}`, engineId);
  }
  if (isLocalHost(host)) return;
  throw new EngineError(
    `Hermes baseUrl host "${host}" is not local/in-cluster; air-gap mode forbids external endpoints`,
    engineId,
  );
}

function isLocalHost(host: string): boolean {
  if (host === 'localhost' || host === '::1' || host.endsWith('.local')) return true;
  if (host.endsWith('.svc') || host.endsWith('.cluster.local') || host.endsWith('.internal')) {
    return true;
  }
  // In-cluster service short names have no dot.
  if (!host.includes('.')) return true;
  if (host === '127.0.0.1' || host.startsWith('127.')) return true;
  if (host.startsWith('10.') || host.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true; // 172.16.0.0/12
  if (host.startsWith('fc') || host.startsWith('fd')) return true; // fc00::/7 unique-local
  return false;
}

// --- OpenAI wire helpers ----------------------------------------------------

function toOpenAiTools(tools: ToolRef[]): OpenAiTool[] {
  // We don't have JSON schemas for the read-only scanner wrappers, so expose a
  // permissive object param. Tool execution is opt-in via config.toolExecutor.
  return tools.map((t) => ({
    type: 'function',
    function: {
      name: t.name,
      description: `${t.kind} tool "${t.name}" (read-only). Arguments are passed through verbatim.`,
      parameters: {
        type: 'object',
        properties: { args: { type: 'object', description: 'Tool arguments' } },
        additionalProperties: true,
      },
    },
  }));
}

const defaultToolExecutor: ToolExecutor = (call) =>
  JSON.stringify({
    tool: call.name,
    status: 'unavailable',
    note: 'Tools are executed by the deterministic Collector, not the model. Answer from the provided context.',
  });

function renderPrompt(input: unknown): string {
  return typeof input === 'string' ? input : JSON.stringify(input, null, 2);
}

function boundTurns(specMax: number | undefined, cap: number | undefined): number {
  const base = specMax ?? 8;
  return cap ? Math.min(cap, base) : base;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, '');
}

function truncate(s: string, n = 300): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Best-effort: pull a JSON object/array out of model text (handles ``` fences). */
export function extractJson(text: string): unknown {
  if (!text) return undefined;
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1]! : text;
  const start = candidate.search(/[[{]/);
  if (start === -1) return undefined;
  for (let end = candidate.length; end > start; end--) {
    const slice = candidate.slice(start, end);
    if (!/[\]}]$/.test(slice.trimEnd())) continue;
    try {
      return JSON.parse(slice);
    } catch {
      /* keep shrinking */
    }
  }
  return undefined;
}

async function withTimeout<T>(p: Promise<T>, ms: number, engineId: string): Promise<T> {
  const timers = globalThis as unknown as {
    setTimeout: (cb: () => void, ms: number) => unknown;
    clearTimeout: (h: unknown) => void;
  };
  let handle: unknown;
  const timeout = new Promise<never>((_, reject) => {
    handle = timers.setTimeout(
      () => reject(new EngineError(`Hermes request timed out after ${ms}ms`, engineId)),
      ms,
    );
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    timers.clearTimeout(handle);
  }
}

function globalFetch(): FetchLike | undefined {
  return (globalThis as unknown as { fetch?: FetchLike }).fetch;
}

// --- Minimal structural types (no DOM lib / @types/node dependency) ---------

export type FetchLike = (url: string, init: FetchInit) => Promise<FetchResponse>;

interface FetchInit {
  method: string;
  headers: Record<string, string>;
  body: string;
}

interface FetchResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<unknown>;
}

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

interface ToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

interface OpenAiTool {
  type: 'function';
  function: { name: string; description: string; parameters: unknown };
}

interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  temperature: number;
  stream: false;
  tools?: OpenAiTool[];
  tool_choice?: 'auto' | 'none';
}

interface ChatResponse {
  choices?: { message: ChatMessage; finish_reason?: string }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

interface TurnUsage {
  inputTokens: number;
  outputTokens: number;
}

type LoopEvent =
  | { type: 'turn'; turns: number; text: string; final: boolean; usage: TurnUsage }
  | { type: 'assistant_text'; text: string }
  | { type: 'tool_call'; tool: string; input: unknown }
  | { type: 'tool_result'; tool: string; output: unknown }
  | { type: 'error'; message: string };
