import { query, type Options, type SDKMessage } from '@anthropic-ai/claude-agent-sdk';
import {
  EngineError,
  type AgentEngine,
  type AgentEvent,
  type AgentRun,
  type AgentSpec,
  type PermissionMode,
} from '@k8s-sentinel/core';

export interface ClaudeEngineConfig {
  /** Anthropic API key. If using Bedrock/Vertex, set the SDK env vars instead. */
  apiKey?: string;
  /** Working directory for the agent session (sandbox execution plane). */
  cwd?: string;
  /** Hard ceiling on turns, overrides spec.maxTurns when smaller. */
  maxTurnsCap?: number;
}

/**
 * Claude Agent SDK adapter (DEFAULT engine). "Claude Code as a library":
 * same agent loop, tool execution and context management, programmable here.
 *
 * The read-only / propose-only guarantees from the security model are enforced
 * by WHICH tools we expose (all scanner MCP servers are read-only) plus the
 * allow-list below — never by trusting the model to behave.
 */
export class ClaudeEngine implements AgentEngine {
  readonly id = 'claude';
  constructor(private readonly config: ClaudeEngineConfig = {}) {}

  async run<TResult>(spec: AgentSpec, input: unknown): Promise<AgentRun<TResult>> {
    const q = query({ prompt: renderPrompt(input), options: this.toOptions(spec) });

    let resultText = '';
    let structured: unknown;
    let turns = 0;
    let usage: AgentRun<TResult>['usage'];

    for await (const msg of q as AsyncIterable<SDKMessage>) {
      if (msg.type === 'result') {
        turns = msg.num_turns;
        if (msg.subtype === 'success') {
          resultText = msg.result;
          structured = msg.structured_output;
        } else {
          throw new EngineError(`Claude run failed: ${msg.subtype}`, this.id);
        }
        usage = {
          inputTokens: msg.usage?.input_tokens,
          outputTokens: msg.usage?.output_tokens,
          costUsd: msg.total_cost_usd,
        };
      }
    }

    const result = (structured ?? extractJson(resultText) ?? resultText) as TResult;
    return { agent: spec.id, result, turns, usage };
  }

  async *stream(spec: AgentSpec, input: unknown): AsyncIterable<AgentEvent> {
    const q = query({ prompt: renderPrompt(input), options: this.toOptions(spec) });
    yield { type: 'start', agent: spec.id, ts: new Date().toISOString() };

    for await (const msg of q as AsyncIterable<SDKMessage>) {
      if (msg.type === 'assistant') {
        for (const block of asArray(msg.message.content)) {
          if (block.type === 'text') {
            const text = String(block.text ?? '');
            if (text.trim()) yield { type: 'message', agent: spec.id, text };
          } else if (block.type === 'tool_use') {
            yield {
              type: 'tool_call',
              agent: spec.id,
              tool: String(block.name ?? 'unknown'),
              input: block.input,
            };
          }
        }
      } else if (msg.type === 'user') {
        for (const block of asArray(msg.message.content)) {
          if (isToolResult(block)) {
            yield {
              type: 'tool_result',
              agent: spec.id,
              tool: block.tool_use_id,
              output: block.content,
            };
          }
        }
      } else if (msg.type === 'result') {
        if (msg.subtype !== 'success') {
          yield { type: 'error', agent: spec.id, message: `run ended: ${msg.subtype}` };
        }
        yield { type: 'done', agent: spec.id, ts: new Date().toISOString() };
      }
    }
  }

  private toOptions(spec: AgentSpec): Options {
    const mcpServers: NonNullable<Options['mcpServers']> = {};
    const allowedTools: string[] = [];
    for (const tool of spec.tools) {
      if (tool.kind === 'mcp' && tool.config) {
        mcpServers[tool.name] = tool.config as never;
      }
      allowedTools.push(tool.name);
    }

    const cap = this.config.maxTurnsCap;
    const maxTurns = cap ? Math.min(cap, spec.maxTurns ?? cap) : spec.maxTurns;

    return {
      systemPrompt: spec.systemPrompt,
      model: spec.model,
      ...(maxTurns ? { maxTurns } : {}),
      mcpServers,
      allowedTools,
      // Writes are never auto-allowed; reads via our read-only MCP tools only.
      disallowedTools: WRITE_TOOLS,
      permissionMode: toSdkPermissionMode(spec.permission),
      // Hermetic: do not load filesystem settings / project CLAUDE.md.
      settingSources: [],
      ...(this.config.cwd ? { cwd: this.config.cwd } : {}),
      ...(this.config.apiKey ? { env: { ...process.env, ANTHROPIC_API_KEY: this.config.apiKey } } : {}),
    };
  }
}

/** Built-in tools that can mutate state — always disallowed for our agents. */
const WRITE_TOOLS = ['Write', 'Edit', 'NotebookEdit', 'Bash'];

function toSdkPermissionMode(mode: PermissionMode): Options['permissionMode'] {
  // We never want a headless agent blocking on a human prompt mid-run, and we
  // never want it bypassing guardrails. 'default' + tool allow/deny lists is
  // the right balance: unlisted tools simply aren't available.
  switch (mode) {
    case 'read-only':
    case 'propose-only':
    case 'approval-required':
      return 'default';
  }
}

function renderPrompt(input: unknown): string {
  return typeof input === 'string' ? input : JSON.stringify(input, null, 2);
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

type ContentBlock = { type: string; [k: string]: unknown };

function asArray(content: unknown): ContentBlock[] {
  return Array.isArray(content) ? (content as ContentBlock[]) : [];
}

function isToolResult(
  b: ContentBlock,
): b is { type: 'tool_result'; tool_use_id: string; content: unknown } {
  return b.type === 'tool_result' && typeof b.tool_use_id === 'string';
}
