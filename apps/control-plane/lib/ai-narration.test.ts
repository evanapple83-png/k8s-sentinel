import { describe, expect, it, vi } from 'vitest';
import {
  SYSTEM_PROMPT,
  buildAskContext,
  buildFindingContext,
  buildFixContext,
  buildPathContext,
  callClaude,
  costMicroCents,
  extractCitations,
  extractText,
  stableStringify,
  AiNarrationError,
  RateLimitError,
} from './ai-narration';

// Fixture mirrors the v3 ARGUS report shape (see lib/argus-mapper.ts +
// tunnel/argus.ts ArgusReportJson). Trimmed to what explain-finding needs.
function fixtureReport() {
  return {
    cluster: 'prod-eu-1',
    scannedAt: '2026-05-28T09:14:00Z',
    riskScore: 100,
    intel: { source: 'live:cisa-kev', version: '2026.05.27', kev_count: 1607 },
    reachableJewels: ['secret:payments/db-credentials', 'CLUSTER-ADMIN'],
    paths: {
      'secret:payments/db-credentials': [
        ['ext:internet', 'wl:payments/invoice-api', 'exploit CVE-2026-31337 (internet-exposed)', null, false],
        ['wl:payments/invoice-api', 'sa:payments/invoice-sa', 'uses ServiceAccount token', null, false],
        ['sa:payments/invoice-sa', 'secret:payments/db-credentials', 'RBAC: can read Secret', null, false],
      ],
    },
    chokePoints: [
      {
        control: { type: 'patch', ref: 'CVE-2026-31337', workload: 'payments/invoice-api' },
        breaks: 2,
        targets: ['secret:payments/db-credentials', 'CLUSTER-ADMIN'],
      },
    ],
    findings: [
      {
        id: 'trivy-001',
        cve: 'CVE-2026-31337',
        title: 'RCE in libfoo < 2.1',
        target: 'payments/invoice-api',
        kev: true,
        ransomware: true,
        epss: 0.92,
        decision: 'Act',
      },
      {
        id: 'trivy-002',
        cve: 'CVE-2026-00099',
        title: 'Low-severity informational',
        target: 'batch/report-worker',
        kev: false,
        decision: 'Track*',
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// buildFindingContext
// ---------------------------------------------------------------------------

describe('buildFindingContext', () => {
  it('returns found=true and trims findings to the targeted one', () => {
    const { context, found } = buildFindingContext(fixtureReport() as never, 'trivy-001');
    expect(found).toBe(true);
    expect(context.findings).toHaveLength(1);
    expect(context.findings![0]!.id).toBe('trivy-001');
    // Top-level structural signals preserved
    expect(context.intel).toBeDefined();
    expect(context.reachableJewels).toBeDefined();
    expect(context.paths).toBeDefined();
    expect(context.chokePoints).toBeDefined();
  });

  it('returns found=false when the id is not in the report', () => {
    const { found } = buildFindingContext(fixtureReport() as never, 'trivy-999');
    expect(found).toBe(false);
  });

  it('drops big-but-irrelevant fields (workloads, activeFindings, metadata)', () => {
    const r: ReturnType<typeof fixtureReport> & {
      activeFindings?: unknown;
      workloads?: unknown;
      metadata?: unknown;
    } = { ...fixtureReport(), activeFindings: [{ id: 'noisy' }], workloads: ['noisy'], metadata: { x: 1 } };
    const { context } = buildFindingContext(r as never, 'trivy-001');
    expect((context as Record<string, unknown>).activeFindings).toBeUndefined();
    expect((context as Record<string, unknown>).workloads).toBeUndefined();
    expect((context as Record<string, unknown>).metadata).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// buildPathContext
// ---------------------------------------------------------------------------

describe('buildPathContext', () => {
  it('narrows paths to the targeted entry + keeps related findings', () => {
    const { context, found } = buildPathContext(fixtureReport() as never, 'secret:payments/db-credentials');
    expect(found).toBe(true);
    expect(Object.keys(context.paths ?? {})).toEqual(['secret:payments/db-credentials']);
    // payments/invoice-api is on this path's hops → its finding should be included.
    const ids = (context.findings ?? []).map((f) => (f as { id: string }).id);
    expect(ids).toContain('trivy-001');
    // batch/report-worker is NOT on this path → its finding should be excluded.
    expect(ids).not.toContain('trivy-002');
  });

  it('returns found=false when the path target is unknown', () => {
    const { found } = buildPathContext(fixtureReport() as never, 'nonexistent:jewel');
    expect(found).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildFixContext
// ---------------------------------------------------------------------------

describe('buildFixContext', () => {
  it('narrows paths + chokePoints to the targeted index', () => {
    const { context, found } = buildFixContext(fixtureReport() as never, 0);
    expect(found).toBe(true);
    expect(context.chokePoints).toHaveLength(1);
    expect(Object.keys(context.paths ?? {})).toEqual(['secret:payments/db-credentials']);
    // findings narrowed to ones on a workload along the broken paths
    const ids = (context.findings ?? []).map((f) => (f as { id: string }).id);
    expect(ids).toContain('trivy-001');
    expect(ids).not.toContain('trivy-002');
  });

  it('returns found=false on a missing index', () => {
    const { found } = buildFixContext(fixtureReport() as never, 99);
    expect(found).toBe(false);
  });

  it('returns found=false on a negative index', () => {
    const { found } = buildFixContext(fixtureReport() as never, -1);
    expect(found).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildAskContext — open-ended, full report unless oversized
// ---------------------------------------------------------------------------

describe('buildAskContext', () => {
  it('returns the report verbatim when under the size cap', () => {
    const r = fixtureReport();
    const out = buildAskContext(r as never);
    expect(out).toEqual(r);
  });

  it('strips noisy fields when the serialized report exceeds 120 KB', () => {
    const big = {
      ...fixtureReport(),
      // pad activeFindings beyond the threshold
      activeFindings: Array.from({ length: 2000 }, (_, i) => ({
        id: `af-${i}`,
        long: 'x'.repeat(100),
      })),
      workloads: ['noisy'],
      metadata: { x: 1 },
    };
    expect(stableStringify(big).length).toBeGreaterThan(120_000);
    const out = buildAskContext(big as never);
    expect((out as Record<string, unknown>).activeFindings).toBeUndefined();
    expect((out as Record<string, unknown>).workloads).toBeUndefined();
    expect((out as Record<string, unknown>).metadata).toBeUndefined();
    // Structural top-level fields preserved.
    expect(out.intel).toBeDefined();
    expect(out.paths).toBeDefined();
    expect(out.findings).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// stableStringify — caching invariant
// ---------------------------------------------------------------------------

describe('stableStringify', () => {
  it('sorts object keys deterministically at every level', () => {
    const a = stableStringify({ b: 1, a: 2 });
    const b = stableStringify({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1}');
  });

  it('handles nested arrays + objects', () => {
    const v = { z: [{ y: 1, x: 2 }, { a: 3 }] };
    expect(stableStringify(v)).toBe('{"z":[{"x":2,"y":1},{"a":3}]}');
  });

  it('preserves primitives + null', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify(42)).toBe('42');
    expect(stableStringify('s')).toBe('"s"');
  });
});

// ---------------------------------------------------------------------------
// extractCitations — hallucination post-check
// ---------------------------------------------------------------------------

describe('extractCitations', () => {
  it('finds finding ids that exist in the report', () => {
    const text = 'Finding trivy-001 is the highest-leverage issue today.';
    const { citations, warnings } = extractCitations(text, fixtureReport() as never);
    expect(citations).toEqual([{ type: 'finding', id: 'trivy-001' }]);
    expect(warnings).toEqual([]);
  });

  it('finds crown-jewel references', () => {
    const text = 'The path reaches CLUSTER-ADMIN via the invoice-api workload.';
    const { citations } = extractCitations(text, fixtureReport() as never);
    expect(citations.some((c) => c.type === 'jewel' && c.id === 'CLUSTER-ADMIN')).toBe(true);
  });

  it('finds path targets', () => {
    const text = 'See path secret:payments/db-credentials for the full chain.';
    const { citations } = extractCitations(text, fixtureReport() as never);
    expect(
      citations.some(
        (c) => c.type === 'path' && c.id === 'secret:payments/db-credentials',
      ),
    ).toBe(true);
  });

  it('flags finding-shape tokens that arent in the report (likely hallucination)', () => {
    const text = 'See F-007 and trivy-999 — both critical.';
    const { warnings } = extractCitations(text, fixtureReport() as never);
    expect(warnings).toContain('F-007');
  });

  it('does NOT flag CVE ids that arent in findings[] (CVEs can be discussed freely)', () => {
    const text = 'Patching CVE-2026-12345 would close the underlying class of bugs.';
    const { warnings } = extractCitations(text, fixtureReport() as never);
    expect(warnings).not.toContain('CVE-2026-12345');
  });

  it('deduplicates repeated tokens', () => {
    const text = 'trivy-001 is critical. trivy-001 also reaches a jewel.';
    const { citations } = extractCitations(text, fixtureReport() as never);
    expect(citations.filter((c) => c.id === 'trivy-001')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// costMicroCents — pricing math
// ---------------------------------------------------------------------------

describe('costMicroCents', () => {
  it('charges $3/1M input, $15/1M output for claude-sonnet-4-6', () => {
    // 1M input + 1M output should be $3 + $15 = $18 = 18_000_000 microcents.
    const usd = costMicroCents('claude-sonnet-4-6', {
      inputTokens: 1_000_000,
      outputTokens: 1_000_000,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    });
    expect(usd).toBe(18_000_000);
  });

  it('applies 1.25× to cache writes and 0.1× to cache reads', () => {
    // 1M cache write @ $3 × 1.25 = $3.75
    // 1M cache read  @ $3 × 0.10 = $0.30
    const usd = costMicroCents('claude-sonnet-4-6', {
      inputTokens: 0,
      outputTokens: 0,
      cacheCreationInputTokens: 1_000_000,
      cacheReadInputTokens: 1_000_000,
    });
    expect(usd).toBe(3_750_000 + 300_000);
  });

  it('falls back to sonnet pricing for an unknown model', () => {
    const a = costMicroCents('unknown-model', {
      inputTokens: 1_000_000,
      outputTokens: 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    });
    const b = costMicroCents('claude-sonnet-4-6', {
      inputTokens: 1_000_000,
      outputTokens: 0,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    });
    expect(a).toBe(b);
  });

  it('charges opus-4-7 at $5/$25 (different from sonnet)', () => {
    const usd = costMicroCents('claude-opus-4-7', {
      inputTokens: 1_000_000,
      outputTokens: 1_000_000,
      cacheCreationInputTokens: 0,
      cacheReadInputTokens: 0,
    });
    expect(usd).toBe(5_000_000 + 25_000_000);
  });
});

// ---------------------------------------------------------------------------
// callClaude — mocked fetch
// ---------------------------------------------------------------------------

function fakeAnthropicResponse(text: string, usage?: Partial<{ input_tokens: number; output_tokens: number; cache_creation_input_tokens: number; cache_read_input_tokens: number }>): Response {
  return new Response(
    JSON.stringify({
      id: 'msg_test',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text }],
      model: 'claude-sonnet-4-6',
      stop_reason: 'end_turn',
      usage: {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        ...usage,
      },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('callClaude', () => {
  it('happy path: POSTs to /v1/messages with the expected headers + body, extracts text', async () => {
    const fetchSpy = vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe('https://api.anthropic.com/v1/messages');
      const headers = init.headers as Record<string, string>;
      expect(headers['x-api-key']).toBe('sk-test');
      expect(headers['anthropic-version']).toBe('2023-06-01');
      const body = JSON.parse(init.body as string);
      expect(body.model).toBe('claude-sonnet-4-6');
      expect(body.system).toHaveLength(2);
      expect(body.system[1].cache_control).toEqual({ type: 'ephemeral' });
      return fakeAnthropicResponse('Explained.');
    });
    const r = await callClaude({
      apiKey: 'sk-test',
      model: 'claude-sonnet-4-6',
      systemBlocks: [
        { type: 'text', text: SYSTEM_PROMPT },
        { type: 'text', text: '{"x":1}', cache_control: { type: 'ephemeral' } },
      ],
      messages: [{ role: 'user', content: 'Why?' }],
      maxTokens: 256,
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });
    expect(extractText(r)).toBe('Explained.');
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it('maps a 429 with retry-after into RateLimitError', async () => {
    const fetchSpy = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: 'rate limited' }), {
          status: 429,
          headers: { 'retry-after': '17' },
        }),
    );
    await expect(
      callClaude({
        apiKey: 'sk-test',
        model: 'claude-sonnet-4-6',
        systemBlocks: [{ type: 'text', text: 'x' }],
        messages: [{ role: 'user', content: 'q' }],
        maxTokens: 256,
        fetchImpl: fetchSpy as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ name: 'RateLimitError', retryAfterSeconds: 17 });
  });

  it('maps a 401 to a clear 503 (server-side key bad — clients should not see auth errors)', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 401 }));
    await expect(
      callClaude({
        apiKey: 'sk-test',
        model: 'claude-sonnet-4-6',
        systemBlocks: [{ type: 'text', text: 'x' }],
        messages: [{ role: 'user', content: 'q' }],
        maxTokens: 256,
        fetchImpl: fetchSpy as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ name: 'AiNarrationError', status: 503 });
  });

  it('maps a 529 overload into 503 with retry guidance', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 529 }));
    await expect(
      callClaude({
        apiKey: 'sk-test',
        model: 'claude-sonnet-4-6',
        systemBlocks: [{ type: 'text', text: 'x' }],
        messages: [{ role: 'user', content: 'q' }],
        maxTokens: 256,
        fetchImpl: fetchSpy as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ name: 'AiNarrationError', status: 503 });
  });

  it('throws AiNarrationError(502) when fetch itself throws (network down)', async () => {
    const fetchSpy = vi.fn(async () => {
      throw new TypeError('network unreachable');
    });
    await expect(
      callClaude({
        apiKey: 'sk-test',
        model: 'claude-sonnet-4-6',
        systemBlocks: [{ type: 'text', text: 'x' }],
        messages: [{ role: 'user', content: 'q' }],
        maxTokens: 256,
        fetchImpl: fetchSpy as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(AiNarrationError);
  });
});

// ---------------------------------------------------------------------------
// SYSTEM_PROMPT — byte-stability invariant
// ---------------------------------------------------------------------------

describe('SYSTEM_PROMPT', () => {
  it('is byte-stable — never changes between calls (caching invariant)', () => {
    // Snapshot the opening sentence; if this changes, every cached prefix in
    // every workspace invalidates. Done deliberately, not accidentally.
    // Also snapshot the length so a stray edit deep in the prompt is caught.
    expect(SYSTEM_PROMPT.startsWith('You are the security analyst inside K8s Sentinel.')).toBe(true);
    expect(SYSTEM_PROMPT.length).toBe(1040);
  });

  it('contains the explicit defensive-language constraints (spec §2)', () => {
    expect(SYSTEM_PROMPT).toMatch(/may NOT generate exploit code/i);
    expect(SYSTEM_PROMPT).toMatch(/may NOT propose commands that modify the cluster/i);
    expect(SYSTEM_PROMPT).toMatch(/sole source of truth/i);
  });
});

// ---------------------------------------------------------------------------
// RateLimitError — shape for the route to lift to HTTP
// ---------------------------------------------------------------------------

describe('RateLimitError', () => {
  it('carries retryAfterSeconds and status=429', () => {
    const e = new RateLimitError(42, 'slow down');
    expect(e.status).toBe(429);
    expect(e.retryAfterSeconds).toBe(42);
  });
});
