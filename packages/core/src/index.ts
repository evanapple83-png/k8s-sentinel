/**
 * @k8s-sentinel/core — the contract everything else depends on.
 *
 * IP (agents, scanner wrappers, correlation, reports) imports ONLY from here.
 * Concrete engines (engine-claude, engine-hermes) implement `AgentEngine`.
 */

export * from './engine.js';
export * from './findings.js';
export * from './inventory.js';
export * from './attack-path.js';
export * from './audit.js';
export * from './audit-sink.js';
export * from './sanitize.js';
export * from './harden.js';
export * from './mock-engine.js';
