import { MockEngine, type AgentEngine } from '@k8s-sentinel/core';
import { ClaudeEngine } from '@k8s-sentinel/engine-claude';
import type { SentinelConfig } from './config.js';

/**
 * Composition root for the engine boundary (BUILD.md §3, §5).
 *
 * This is the ONLY module allowed to import concrete engine packages. Agent /
 * IP code receives an `AgentEngine` and never knows which one it got — swapping
 * Claude ↔ Hermes ↔ Mock requires no change above this line.
 */
export async function createEngine(config: SentinelConfig): Promise<AgentEngine> {
  switch (config.engine) {
    case 'claude':
      return new ClaudeEngine({
        apiKey: config.anthropicApiKey,
        cwd: process.cwd(),
        maxTurnsCap: 30,
      });

    case 'hermes': {
      // Phase 4: air-gapped local model. Loaded lazily via a runtime specifier
      // so the package is only required when actually selected.
      const hermesPkg = '@k8s-sentinel/engine-hermes';
      const mod = (await import(/* @vite-ignore */ hermesPkg).catch(() => null)) as {
        HermesEngine?: new (cfg: unknown) => AgentEngine;
      } | null;
      if (!mod?.HermesEngine) {
        throw new Error(
          'Hermes engine selected but @k8s-sentinel/engine-hermes is not available (Phase 4).',
        );
      }
      return new mod.HermesEngine({ baseUrl: config.hermes.baseUrl, model: config.hermes.model });
    }

    case 'mock':
    default:
      return new MockEngine();
  }
}
