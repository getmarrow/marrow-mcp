import type { MarrowModelUsageInput } from './types';
import { normalizeModelUsage } from './model-usage';
function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export interface MarrowHabitLoopCopy {
  contract: 'marrow.habit-loop.v1';
  headline: string;
  next: string;
  avoid: string[];
  savings: string;
  text: string;
}

export function formatHabitLoopCopy(source: unknown): MarrowHabitLoopCopy | null {
  const root = asRecord(source);
  if (!root) return null;
  const nestedData = asRecord(root.data);
  const habit = asRecord(root.habit_loop)
    || asRecord(nestedData?.habit_loop)
    || (asString(root.contract) === 'marrow.habit-loop.v1' ? root : null);
  if (!habit || asString(habit.contract) !== 'marrow.habit-loop.v1') return null;

  const headline = asString(habit.headline) || 'Marrow is on.';
  const next = asString(habit.exact_next_action) || 'Stay quiet unless the work is deploy, merge, publish, migration, secrets, or billing.';
  const avoid = Array.isArray(habit.avoid)
    ? habit.avoid.map((item) => asString(item)).filter((item): item is string => Boolean(item)).slice(0, 5)
    : [];
  const savingsRecord = asRecord(habit.session_savings);
  const savings = asString(savingsRecord?.message)
    || (savingsRecord?.evidence_backed === true
      ? 'Reuse produced evidence-backed savings.'
      : 'No reuse yet. Empty savings are honest.');

  return {
    contract: 'marrow.habit-loop.v1',
    headline,
    next,
    avoid,
    savings,
    text: [headline, `Next: ${next}`, ...(avoid.length ? [`Avoid: ${avoid[0]}`] : []), `Savings: ${savings}`].join('\n'),
  };
}

export interface ModelUsageCaptureContext {
  /** Observed request endpoint, supplied by the host adapter/config; never taken from response content. */
  endpoint?: string;
  provider?: string;
  pricing_dimensions?: Record<string, string | number>;
  billing_mode?: 'api' | 'subscription';
  usage_kind?: 'delta' | 'cumulative';
  occurred_at?: string;
}

export function modelUsageCaptureContextFromEnv(): ModelUsageCaptureContext {
  let pricing_dimensions: ModelUsageCaptureContext['pricing_dimensions'];
  const raw = process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS;
  if (raw && raw.length <= 2048) {
    try { pricing_dimensions = normalizeModelUsage({ pricing_dimensions: JSON.parse(raw) }).pricing_dimensions as ModelUsageCaptureContext['pricing_dimensions']; } catch { /* Unknown configuration remains unpriced. */ }
  }
  return { endpoint: process.env.MARROW_MODEL_USAGE_ENDPOINT, pricing_dimensions,
    billing_mode: process.env.MARROW_MODEL_USAGE_BILLING_MODE === 'subscription' ? 'subscription' : undefined };
}

export function extractModelUsageFromUnknown(source: unknown, context: ModelUsageCaptureContext = {}): MarrowModelUsageInput | null {
  const root = asRecord(source);
  if (!root) return null;
  const response = asRecord(root.response) || asRecord(root.message) || root;
  const usage = asRecord(response.usage) || asRecord(response.token_usage) || asRecord(response.usageMetadata);
  if (!usage) return null;
  const number = (value: unknown): number | undefined => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  const numberAt = (...keys: string[]): number | undefined => {
    for (const key of keys) { if (Object.hasOwn(usage, key)) return number(usage[key]); }
    return undefined;
  };
  const model = asString(response.model) || asString(response.modelVersion) || undefined;
  const declaredProvider = asString(root.provider) || asString(response.provider) || context.provider;
  const responseId = asString(response.id);
  const numericKeys = ['input_tokens', 'prompt_tokens', 'inputTokenCount', 'promptTokenCount', 'output_tokens', 'completion_tokens', 'outputTokenCount', 'candidatesTokenCount', 'cached_tokens', 'cache_read_input_tokens', 'cachedContentTokenCount', 'cache_write_tokens', 'cache_creation_input_tokens', 'total_tokens', 'totalTokenCount', 'totalTokens'];
  if (numericKeys.some(key => Object.hasOwn(usage, key) && number(usage[key]) === undefined)) return null;
  for (const detail of [asRecord(usage.input_tokens_details), asRecord(usage.prompt_tokens_details)]) {
    if (detail && ['cached_tokens', 'cache_write_tokens'].some(key => Object.hasOwn(detail, key) && number(detail[key]) === undefined)) return null;
  }
  let endpointProvider: string | undefined;
  try {
    const endpoint = new URL(context.endpoint || '');
    if (endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password && !endpoint.port) {
      endpointProvider = ({ 'api.openai.com': 'openai', 'api.anthropic.com': 'anthropic' } as Record<string, string>)[endpoint.hostname];
    }
  } catch { /* No endpoint proof. */ }
  const provider = declaredProvider || endpointProvider;
  const mismatch = !!(endpointProvider && (declaredProvider && endpointProvider !== declaredProvider
    || endpointProvider === 'openai' && model?.startsWith('claude-')
    || endpointProvider === 'anthropic' && model && !model.startsWith('claude-')
    || endpointProvider === 'openai' && responseId?.startsWith('msg_')
    || endpointProvider === 'anthropic' && /^(?:resp_|chatcmpl[-_])/.test(responseId || '')));
  const openai = provider === 'openai';
  const anthropic = provider === 'anthropic';
  const input_tokens = numberAt('input_tokens', 'prompt_tokens', 'inputTokenCount', 'promptTokenCount');
  const output_tokens = numberAt('output_tokens', 'completion_tokens', 'outputTokenCount', 'candidatesTokenCount');
  const details = asRecord(usage.input_tokens_details) || asRecord(usage.prompt_tokens_details);
  const cached_tokens = numberAt('cached_tokens', 'cache_read_input_tokens', 'cachedContentTokenCount') ?? (openai ? number(details?.cached_tokens) : undefined);
  const cache_write_tokens = numberAt('cache_write_tokens', 'cache_creation_input_tokens') ?? (openai ? number(details?.cache_write_tokens) : undefined);
  // Native Anthropic input excludes cache reads/writes; OpenAI input includes them.
  const token_semantics = openai ? 'input_includes_cache' : anthropic ? 'disjoint' : undefined;
  const observedTotal = numberAt('total_tokens', 'totalTokenCount', 'totalTokens');
  const total_tokens = observedTotal ?? (input_tokens !== undefined && output_tokens !== undefined && token_semantics
    ? input_tokens + output_tokens + (anthropic ? (cached_tokens || 0) + (cache_write_tokens || 0) : 0) : undefined);
  if ([input_tokens, output_tokens, cached_tokens, cache_write_tokens, total_tokens].every(value => value === undefined)) return null;
  const id = asString(response.id);
  const stableId = !mismatch && id && (openai && /^(?:chatcmpl|resp)_[a-zA-Z0-9_-]{1,120}$/.test(id)
    || openai && /^chatcmpl-[a-zA-Z0-9_-]{1,120}$/.test(id)
    || anthropic && /^msg_[a-zA-Z0-9_-]{1,120}$/.test(id)) ? `${provider}:${id}` : undefined;
  const dims = { ...context.pricing_dimensions };
  const tier = asString(response.service_tier) || asString(usage.service_tier);
  if (tier && (openai || anthropic)) dims.tier = tier === 'default' && openai ? 'standard' : tier;
  const geo = asString(usage.inference_geo);
  if (anthropic && geo) dims.region = geo;
  const creation = asRecord(usage.cache_creation);
  if (anthropic && creation) {
    const five = number(creation.ephemeral_5m_input_tokens), hour = number(creation.ephemeral_1h_input_tokens);
    if (five !== undefined && hour !== undefined && cache_write_tokens === five + hour && five + hour > 0) {
      dims.cache_ttl = five && hour ? 'mixed_unresolved' : hour ? '1h' : '5m';
    } else if (cache_write_tokens) dims.cache_ttl = 'unresolved';
  }
  const usage_kind = context.usage_kind === 'cumulative' || root.usage_kind === 'cumulative' || response.usage_kind === 'cumulative' || root.type === 'message_start' ? 'cumulative'
    : stableId ? 'delta' : context.usage_kind;
  // No raw content, endpoint, guessed coverage or client-asserted savings crosses this boundary.
  try {
    return normalizeModelUsage({ provider, model, input_tokens, output_tokens, cached_tokens, cache_write_tokens, total_tokens,
      token_semantics, billing_host: endpointProvider && !mismatch ? 'first_party' : undefined,
      usage_event_id: stableId, usage_kind, occurred_at: context.occurred_at,
      pricing_dimensions: Object.keys(dims).length ? dims : undefined, billing_mode: context.billing_mode,
    }) as MarrowModelUsageInput;
  } catch { return null; }
}
