import { redactSensitiveText, redactSensitiveValue } from './redact';
import type { MarrowModelUsageInput } from './types';

const stringFields = ['agent_id', 'session_id', 'workflow_id', 'decision_id', 'provider', 'model', 'task_type', 'action_type', 'source', 'marrow_intervention', 'billing_host', 'usage_event_id', 'baseline_usage_id', 'comparison_id', 'task_fingerprint', 'constraints_fingerprint'] as const;
const numberFields = ['input_tokens', 'output_tokens', 'cached_tokens', 'cache_write_tokens', 'total_tokens', 'cost_usd', 'latency_ms', 'baseline_tokens', 'estimated_tokens_saved', 'estimated_cost_saved_usd', 'estimated_minutes_saved'] as const;
const enums = { token_semantics: ['input_includes_cache', 'disjoint'], usage_kind: ['delta', 'cumulative'], usage_role: ['task', 'marrow_overhead'], billing_mode: ['api', 'subscription'], cost_source: ['provider_response'] } as const;
const booleanFields = ['success', 'coverage_complete', 'overhead_complete'] as const;
const safeLabel = /^[a-zA-Z0-9_.:/@-]{1,160}$/;

/** Compact evidence only. Reject malformed supplied values; never coerce null into observed zero. */
export function normalizeModelUsage(input: MarrowModelUsageInput = {}): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('model_usage must be an object');
  const body: Record<string, unknown> = {};
  const invalid = (key: string): never => { throw new TypeError(`Invalid model usage ${key}`); };
  for (const key of stringFields) {
    const value = input[key];
    if (value === undefined || (value === null && ['agent_id', 'session_id', 'workflow_id', 'decision_id'].includes(key))) continue;
    if (['task_type', 'action_type', 'source', 'marrow_intervention'].includes(key)) {
      if (typeof value !== 'string' || !value.trim() || value.length > 180) invalid(key);
      body[key] = redactSensitiveText(value as string);
      continue;
    }
    if (typeof value !== 'string' || !safeLabel.test(value) || redactSensitiveText(value) !== value || /^(?:sk|mrw|ghp|github_pat|npm)_[\w-]+$/i.test(value)) invalid(key);
    body[key] = value;
  }
  for (const key of numberFields) {
    const value = input[key];
    if (value === undefined) continue;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || (key.endsWith('tokens') && !Number.isSafeInteger(value))) invalid(key);
    body[key] = value;
  }
  for (const [key, values] of Object.entries(enums)) {
    const value = input[key as keyof MarrowModelUsageInput];
    if (value === undefined) continue;
    if (typeof value !== 'string' || !(values as readonly string[]).includes(value)) invalid(key);
    body[key] = value;
  }
  for (const key of booleanFields) {
    if (input[key] === undefined) continue;
    if (typeof input[key] !== 'boolean') invalid(key);
    body[key] = input[key];
  }
  if (input.occurred_at !== undefined) {
    if (typeof input.occurred_at !== 'string' || input.occurred_at.length > 40 || !/^\d{4}-\d{2}-\d{2}T/.test(input.occurred_at) || !Number.isFinite(Date.parse(input.occurred_at))) invalid('occurred_at');
    body.occurred_at = new Date(input.occurred_at).toISOString();
  }
  if (input.pricing_dimensions !== undefined) {
    const dims = input.pricing_dimensions;
    if (!dims || typeof dims !== 'object' || Array.isArray(dims) || Object.keys(dims).length > 16) invalid('pricing_dimensions');
    const result: Record<string, string | number> = {};
    for (const [key, value] of Object.entries(dims)) {
      if (!/^[a-z_]{1,40}$/.test(key) || key === '__proto__' || !(typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(value) || typeof value === 'number' && Number.isFinite(value) && value >= 0)) invalid('pricing_dimensions');
      const filtered = redactSensitiveValue({ [key]: value }) as Record<string, unknown>;
      if (filtered[key] !== value) invalid('pricing_dimensions');
      result[key] = value;
    }
    body.pricing_dimensions = result;
  }
  return body;
}

export const MODEL_USAGE_EVIDENCE_PROPERTIES = {
  ...Object.fromEntries(stringFields.map(key => [key, { type: 'string', maxLength: 160 }])),
  ...Object.fromEntries(numberFields.map(key => [key, { type: key.endsWith('tokens') ? 'integer' : 'number', minimum: 0 }])),
  ...Object.fromEntries(Object.entries(enums).map(([key, values]) => [key, { type: 'string', enum: values }])),
  ...Object.fromEntries(booleanFields.map(key => [key, { type: 'boolean' }])),
  occurred_at: { type: 'string', format: 'date-time', maxLength: 40 },
  pricing_dimensions: { type: 'object', maxProperties: 16, additionalProperties: { anyOf: [{ type: 'string', maxLength: 80 }, { type: 'number', minimum: 0 }] } },
};
