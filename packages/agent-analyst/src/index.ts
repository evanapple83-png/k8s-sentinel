/**
 * @k8s-sentinel/agent-analyst — Agent 2, the correlation brain (core IP).
 *
 * Enriches findings with reachability + exploitability, maps them to compliance
 * controls, fuses them into ranked attack paths, and answers plain-English
 * queries over the posture graph. Pure/deterministic — runs offline.
 */
export * from './reachability.js';
export * from './compliance.js';
export * from './correlate.js';
export * from './analyze.js';
export * from './query.js';
export * from './spec.js';
