/**
 * The engine abstraction (BUILD.md §5).
 *
 * Both runtimes — Claude Agent SDK (default) and Hermes (air-gap) — implement
 * this one interface so the agent "brain" is swappable. ALL product IP
 * (scanner wrappers, correlation, report templates, playbooks) lives ABOVE this
 * line and depends only on these types — never on a concrete engine package.
 */

export type AgentId = 'collector' | 'analyst' | 'author';

export type PermissionMode =
  | 'read-only' // may read cluster/files; no writes, no network mutations
  | 'propose-only' // may produce diffs/PRs as artifacts; never applies them
  | 'approval-required'; // any write requires an explicit human approval gate

/** A tool the engine may expose to the agent (an MCP server or a CLI wrapper). */
export interface ToolRef {
  name: string;
  /** "mcp" servers are spawned/connected; "cli" tools are invoked per-call. */
  kind: 'mcp' | 'cli';
  /** Opaque, engine-interpreted config (command, args, url, env allow-list…). */
  config?: Record<string, unknown>;
}

export interface AgentSpec {
  id: AgentId;
  systemPrompt: string;
  /** Engine-specific model id (e.g. "claude-opus-4-7" or a local Hermes id). */
  model: string;
  tools: ToolRef[];
  /** agentskills.io-style skill packs the engine should load. */
  skills?: string[];
  permission: PermissionMode;
  /** Hard cap on agent turns to bound cost/runtime. */
  maxTurns?: number;
}

/** Streaming progress events surfaced to the UI and audit log. */
export type AgentEvent =
  | { type: 'start'; agent: AgentId; ts: string }
  | { type: 'thinking'; agent: AgentId; text: string }
  | { type: 'tool_call'; agent: AgentId; tool: string; input: unknown }
  | { type: 'tool_result'; agent: AgentId; tool: string; output: unknown }
  | { type: 'message'; agent: AgentId; text: string }
  | { type: 'error'; agent: AgentId; message: string }
  | { type: 'done'; agent: AgentId; ts: string };

export interface AgentRun<TResult> {
  agent: AgentId;
  result: TResult;
  /** Total turns the engine took. */
  turns: number;
  /** Token / cost accounting when the engine reports it. */
  usage?: { inputTokens?: number; outputTokens?: number; costUsd?: number };
}

export interface AgentEngine {
  /** Identifier of the concrete engine, e.g. "claude" | "hermes". */
  readonly id: string;

  /** Run a single agent turn-loop until it produces a typed result. */
  run<TResult>(spec: AgentSpec, input: unknown): Promise<AgentRun<TResult>>;

  /** Stream progress events for the same turn-loop. */
  stream(spec: AgentSpec, input: unknown): AsyncIterable<AgentEvent>;
}

/** Thrown when an engine receives a spec it cannot satisfy. */
export class EngineError extends Error {
  constructor(
    message: string,
    readonly engineId: string,
  ) {
    super(message);
    this.name = 'EngineError';
  }
}
