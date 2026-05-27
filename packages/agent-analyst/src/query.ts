import {
  sanitizeUntrusted,
  type AttackPath,
  type Finding,
  type Severity,
} from '@k8s-sentinel/core';
import type { FindingContext } from './reachability.js';

/**
 * Plain-English query over the posture graph (BUILD.md §3, Feature 4 / the
 * "Ask" Spotlight bar in §8). Deterministic by design — like the rest of the
 * Analyst, the heavy lifting is code, so this runs offline with no model in the
 * loop. (An engine-backed front-end can still translate fuzzier prose into one
 * of these queries, but the matching itself is auditable and reproducible.)
 *
 * Example the DoD calls out:
 *   "show everything internet-exposed running as root"
 *     → findings where ctx.internetExposed && ctx.runAsRoot
 */

type FacetTest = (f: Finding, ctx: FindingContext | undefined) => boolean;

interface FacetDef {
  key: string;
  label: string;
  /** Phrase(s) that activate the facet. Matched against the lower-cased query. */
  pattern: RegExp;
  test: FacetTest;
}

/**
 * Facet order matters: the more specific phrase is matched first and then
 * "consumed" (blanked out) so a broader phrase can't double-fire. e.g.
 * "internet-exposed" is consumed before the bare "exposed" facet is checked,
 * and "running as root" before the bare "running" facet.
 */
const FACET_DEFS: FacetDef[] = [
  {
    key: 'internet-exposed',
    label: 'internet-exposed',
    pattern: /internet[- ]?(?:facing|exposed)|exposed to (?:the )?internet|public(?:ly)?[- ]?(?:facing|exposed|reachable)/,
    test: (_f, c) => !!c?.internetExposed,
  },
  {
    key: 'run-as-root',
    label: 'running as root',
    pattern: /(?:runs?|running)\s+as\s+root|\bas\s+root\b|\broot\b/,
    test: (_f, c) => !!c?.runAsRoot,
  },
  {
    key: 'over-privileged',
    label: 'over-privileged',
    pattern: /over[- ]?privileg\w*/,
    test: (_f, c) => !!c?.overPrivileged,
  },
  {
    key: 'privileged',
    label: 'privileged',
    pattern: /privileged/,
    test: (_f, c) => !!c?.privileged,
  },
  {
    key: 'secret-access',
    label: 'can read secrets',
    pattern: /secrets?|credentials?|read secrets/,
    test: (_f, c) => !!c?.canReachSecret,
  },
  {
    key: 'exposed',
    label: 'exposed',
    pattern: /\bexposed\b|reachable from outside/,
    test: (_f, c) => !!c?.exposed,
  },
  {
    key: 'reachable',
    label: 'reachable',
    pattern: /\breachable\b/,
    test: (_f, c) => !!c?.reachable,
  },
  {
    key: 'running',
    label: 'running',
    pattern: /\brunning\b|\blive\b|\bscheduled\b/,
    test: (_f, c) => !!c?.running,
  },
];

const SOURCE_ALIASES: Array<[Finding['source'], RegExp]> = [
  ['trivy', /\btrivy\b|\bcve\b|\bvuln(?:erab\w*)?\b/],
  ['kubescape', /\bkubescape\b|\bmisconfig\w*\b/],
  ['kube-bench', /\bkube[- ]?bench\b|\bbenchmark\b/],
  ['falco', /\bfalco\b|\bruntime\b/],
];

const SEVERITY_WORDS: Severity[] = ['critical', 'high', 'medium', 'low'];

export interface ActiveFacet {
  key: string;
  label: string;
}

export interface ParsedQuery {
  raw: string;
  facets: ActiveFacet[];
  severities: Severity[];
  sources: Finding['source'][];
  namespace?: string;
  /** Caller asked to see attack paths, not just findings. */
  wantsPaths: boolean;
  /** Limit results to the top N by exploitability. */
  topN?: number;
  /** Query terms we couldn't interpret (surfaced so the UI can hint). */
  unmatched: string;
}

export interface QueryContext {
  findings: Finding[];
  paths: AttackPath[];
  contexts: Map<string, FindingContext>;
  /** Known namespaces (used to resolve "in <ns>" safely). */
  namespaces?: string[];
}

export interface QueryResult {
  query: string;
  parsed: ParsedQuery;
  findings: Finding[];
  /** Paths whose findings intersect the matched set (or all, for a path query). */
  paths: AttackPath[];
  /** One-line, plain-English answer. */
  answer: string;
}

/** Parse a plain-English query into a structured, auditable filter. */
export function parseQuery(raw: string, namespaces: string[] = []): ParsedQuery {
  // Lower-case, normalise separators, pad so \b anchors work at the edges.
  let work = ` ${raw.toLowerCase().replace(/[_/]+/g, ' ')} `;
  const consume = (re: RegExp) => {
    work = work.replace(new RegExp(re.source, 'g'), ' ');
  };

  const facets: ActiveFacet[] = [];
  for (const def of FACET_DEFS) {
    if (def.pattern.test(work)) {
      facets.push({ key: def.key, label: def.label });
      consume(def.pattern);
    }
  }

  const severities: Severity[] = [];
  for (const s of SEVERITY_WORDS) {
    const re = new RegExp(`\\b${s}\\b`);
    if (re.test(work)) {
      severities.push(s);
      consume(re);
    }
  }

  const sources: Finding['source'][] = [];
  for (const [src, re] of SOURCE_ALIASES) {
    if (re.test(work)) {
      sources.push(src);
      consume(re);
    }
  }

  let namespace: string | undefined;
  const nsMatch = work.match(/\b(?:in|namespace|ns)\s+([a-z][a-z0-9-]*)/);
  if (nsMatch && namespaces.includes(nsMatch[1]!)) {
    namespace = nsMatch[1];
  } else {
    for (const ns of namespaces) {
      if (new RegExp(`\\b${escapeRe(ns)}\\b`).test(work)) {
        namespace = ns;
        break;
      }
    }
  }
  if (namespace) consume(new RegExp(`\\b(?:in|namespace|ns)\\s+${escapeRe(namespace)}|\\b${escapeRe(namespace)}\\b`));

  let topN: number | undefined;
  const topMatch = work.match(/\btop\s+(\d+)/);
  if (topMatch) {
    topN = Math.max(1, Number.parseInt(topMatch[1]!, 10));
    consume(/\btop\s+\d+/);
  } else if (/\b(?:top|worst|highest|riskiest|biggest|most (?:critical|severe|risky|dangerous|exploitable))\b/.test(work)) {
    topN = 5;
  }

  const wantsPaths = /\battack[- ]?paths?\b|\bpaths?\b|\bkill[- ]?chains?\b|\bchains?\b/.test(work);
  if (wantsPaths) consume(/\battack[- ]?paths?\b|\bpaths?\b|\bkill[- ]?chains?\b|\bchains?\b/);

  // Drop filler words; whatever survives is genuinely unrecognised.
  const unmatched = work
    .replace(
      /\b(?:show|list|find|get|all|every(?:thing)?|me|my|our|the|a|an|with|that|are?|is|and|or|of|to|in|on|can|do|does|did|has|have|workloads?|findings?|issues?|containers?|pods?|services?|please|which|what|where|who|how|any)\b/g,
      ' ',
    )
    .replace(/\s+/g, ' ')
    .trim();

  return { raw, facets, severities, sources, namespace, wantsPaths, topN, unmatched };
}

/** Answer a plain-English query against an analysed run. */
export function answerQuery(query: string, ctx: QueryContext): QueryResult {
  const parsed = parseQuery(query, ctx.namespaces ?? []);

  const hasFilter =
    parsed.facets.length > 0 ||
    parsed.severities.length > 0 ||
    parsed.sources.length > 0 ||
    parsed.namespace !== undefined;

  const matched = ctx.findings.filter((f) => matchesFinding(f, ctx.contexts.get(f.id), parsed));
  matched.sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0) || a.id.localeCompare(b.id));
  const findings = parsed.topN ? matched.slice(0, parsed.topN) : matched;

  // Path query with no other filter → all paths; otherwise paths that touch the
  // matched findings (so "internet-exposed running as root" surfaces its chain).
  let paths: AttackPath[];
  if (parsed.wantsPaths && !hasFilter) {
    paths = [...ctx.paths].sort((a, b) => b.score - a.score);
  } else {
    const matchedIds = new Set(matched.map((f) => f.id));
    paths = ctx.paths
      .filter((p) => p.findingIds.some((id) => matchedIds.has(id)))
      .sort((a, b) => b.score - a.score);
  }

  return { query, parsed, findings, paths, answer: buildAnswer(parsed, findings, paths, hasFilter) };
}

// ---- matching -------------------------------------------------------------

function matchesFinding(f: Finding, ctx: FindingContext | undefined, p: ParsedQuery): boolean {
  if (p.severities.length > 0 && !p.severities.includes(f.severity)) return false;
  if (p.sources.length > 0 && !p.sources.includes(f.source)) return false;
  if (p.namespace !== undefined && (ctx?.workload?.namespace ?? f.resource.namespace) !== p.namespace) {
    return false;
  }
  for (const facet of p.facets) {
    const def = FACET_DEFS.find((d) => d.key === facet.key)!;
    if (!def.test(f, ctx)) return false;
  }
  return true;
}

// ---- answer ---------------------------------------------------------------

function buildAnswer(
  p: ParsedQuery,
  findings: Finding[],
  paths: AttackPath[],
  hasFilter: boolean,
): string {
  const criteria = describeCriteria(p);
  if (findings.length === 0 && paths.length === 0) {
    return `No findings match ${criteria}.`;
  }

  const n = findings.length;
  const head = hasFilter
    ? `${n} finding${n === 1 ? '' : 's'} match ${criteria}`
    : `${n} finding${n === 1 ? '' : 's'} (ranked by exploitability)`;

  const lead = findings[0];
  const tail = lead
    ? ` — top: ${cleanText(lead.title)} on ${refLabel(lead)} (score ${lead.exploitScore ?? 0}).`
    : '.';

  const pathNote =
    paths.length > 0
      ? ` ${paths.length} attack path${paths.length === 1 ? '' : 's'} involve${paths.length === 1 ? 's' : ''} them (top scores ${paths[0]!.score}/100).`
      : '';

  return head + tail + pathNote;
}

function describeCriteria(p: ParsedQuery): string {
  const parts: string[] = [];
  for (const f of p.facets) parts.push(f.label);
  if (p.severities.length > 0) parts.push(p.severities.join('/') + ' severity');
  if (p.sources.length > 0) parts.push(`from ${p.sources.join('/')}`);
  if (p.namespace) parts.push(`in ${p.namespace}`);
  if (parts.length === 0) return '"' + cleanText(p.raw) + '"';
  return parts.join(', ');
}

function refLabel(f: Finding): string {
  const ns = f.resource.namespace ? `${f.resource.namespace}/` : '';
  return cleanText(`${ns}${f.resource.name}`);
}

/** Findings carry attacker-controlled text; defang before it lands in an answer. */
function cleanText(s: string): string {
  return sanitizeUntrusted(s, { fence: false, maxLength: 100 });
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
