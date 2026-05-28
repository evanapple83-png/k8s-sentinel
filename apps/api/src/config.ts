import 'dotenv/config';

export type EngineChoice = 'claude' | 'hermes' | 'mock';

export interface SentinelConfig {
  engine: EngineChoice;
  anthropicApiKey?: string;
  useBedrock: boolean;
  useVertex: boolean;
  models: { collector: string; analyst: string; author: string };
  hermes: { baseUrl: string; model: string };
  dbPath: string;
  apiPort: number;
  kubeconfig?: string;
  /** Cluster name carried in the posture report's run summary. CLUSTER_NAME env. */
  clusterName?: string;
}

function env(key: string, fallback?: string): string | undefined {
  const v = process.env[key];
  return v && v.length > 0 ? v : fallback;
}

/**
 * Resolve runtime config from the environment. Engine selection:
 *   - explicit SENTINEL_ENGINE wins;
 *   - else "claude" when credentials are present (API key / Bedrock / Vertex);
 *   - else "mock" so the pipeline still runs offline (no external calls).
 */
export function loadConfig(): SentinelConfig {
  const useBedrock = env('CLAUDE_CODE_USE_BEDROCK') === '1';
  const useVertex = env('CLAUDE_CODE_USE_VERTEX') === '1';
  const apiKey = env('ANTHROPIC_API_KEY');
  const hasClaudeCreds = Boolean(apiKey || useBedrock || useVertex);

  const requested = env('SENTINEL_ENGINE') as EngineChoice | undefined;
  const engine: EngineChoice = requested ?? (hasClaudeCreds ? 'claude' : 'mock');

  return {
    engine,
    anthropicApiKey: apiKey,
    useBedrock,
    useVertex,
    models: {
      collector: env('SENTINEL_MODEL_COLLECTOR', 'claude-haiku-4-5')!,
      analyst: env('SENTINEL_MODEL_ANALYST', 'claude-opus-4-7')!,
      author: env('SENTINEL_MODEL_AUTHOR', 'claude-sonnet-4-6')!,
    },
    hermes: {
      baseUrl: env('HERMES_BASE_URL', 'http://localhost:8080/v1')!,
      model: env('HERMES_MODEL', 'NousResearch/Hermes-4-70B')!,
    },
    dbPath: env('SENTINEL_DB_PATH', './data/sentinel.sqlite')!,
    apiPort: Number(env('API_PORT', '8787')),
    kubeconfig: env('KUBECONFIG'),
    clusterName: env('CLUSTER_NAME'),
  };
}
