import { createHash } from 'crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { redactSensitiveValue } from './redact';

const FRESH_AGE_MS = 30_000;
const MAX_CACHE_AGE_MS = 5 * 60 * 1_000;
const MAX_STATUS_BYTES = 16_000;

interface StatusCacheRecord {
  version: 1;
  stored_at: string;
  source: 'runtime' | 'status';
  status: Record<string, unknown>;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function cachePath(apiKey: string, baseUrl: string, agentId?: string, home = homedir()): string {
  const namespace = createHash('sha256')
    .update(`${baseUrl}|${apiKey}|${agentId || 'account'}`)
    .digest('hex')
    .slice(0, 24);
  const directory = join(home, '.marrow', 'cache');
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('Marrow status cache directory must be owner-only and cannot be a symlink');
  }
  return join(directory, `status-${namespace}.json`);
}

function projectStatus(value: unknown): Record<string, unknown> | null {
  const status = asRecord(value);
  if (!status || status.ok !== true) return null;
  const measurement = asRecord(status.measurement_availability);
  const diagnostics = asRecord(status.diagnostics);
  const memory = asRecord(status.memory);
  const measured = measurement?.available === true;
  const hasMemory = measured
    ? (memory?.has_memory === true || status.has_memory === true)
    : null;
  const rawDecisionCount = memory?.decision_count ?? status.decision_count;
  const decisionCount = measured && typeof rawDecisionCount === 'number' && Number.isFinite(rawDecisionCount)
    ? rawDecisionCount
    : null;
  if (measured && decisionCount === null) return null;
  const projected = {
    ok: true,
    response_mode: 'compact',
    status_contract: 'marrow.agent-status.v2',
    enabled: measured ? status.enabled === true : null,
    health: typeof status.health === 'string' ? status.health : measured ? 'available' : 'warming',
    message: typeof status.message === 'string' ? status.message : 'Marrow returned last-known measured status.',
    measurement_availability: measurement || {
      available: false,
      state: 'warming',
      exact: false,
      source: 'unknown',
    },
    memory: {
      state: !measured ? 'unknown' : hasMemory ? 'present' : 'empty',
      has_memory: hasMemory,
      decision_count: decisionCount,
      source: measurement?.source || 'unknown',
      exact: measurement?.exact === true,
    },
    has_memory: hasMemory,
    low_history: measured && typeof status.low_history === 'boolean' ? status.low_history : null,
    decision_count: decisionCount,
    outcome_eligible_decision_count: measured && Number.isFinite(Number(status.outcome_eligible_decision_count))
      ? Number(status.outcome_eligible_decision_count)
      : null,
    outcome_count: measured && Number.isFinite(Number(status.outcome_count)) ? Number(status.outcome_count) : null,
    success_rate: measured && (status.success_rate === null || Number.isFinite(Number(status.success_rate)))
      ? status.success_rate
      : null,
    first_event_at: measured && typeof status.first_event_at === 'string' ? status.first_event_at : null,
    last_event_at: measured && typeof status.last_event_at === 'string' ? status.last_event_at : null,
    recent_decisions_24h: measured && Number.isFinite(Number(status.recent_decisions_24h)) ? Number(status.recent_decisions_24h) : null,
    recent_outcome_count_24h: measured && Number.isFinite(Number(status.recent_outcome_count_24h)) ? Number(status.recent_outcome_count_24h) : null,
    readiness: asRecord(status.readiness),
    capture_diagnosis: asRecord(status.capture_diagnosis),
    failure_reasons: Array.isArray(status.failure_reasons) ? status.failure_reasons : [],
    agent_warnings: Array.isArray(status.agent_warnings) ? status.agent_warnings : [],
    missed_hooks: Array.isArray(status.missed_hooks) ? status.missed_hooks : [],
    hook_status: asRecord(status.hook_status),
    automatic_outcome_closure: asRecord(status.automatic_outcome_closure),
    proof_pack_enforcement: asRecord(status.proof_pack_enforcement),
    diagnostics: diagnostics ? {
      key_found: diagnostics.key_found,
      key_valid: diagnostics.key_valid,
      account_active: diagnostics.account_active,
      agent_identity_accepted: diagnostics.agent_identity_accepted,
      query_ms: diagnostics.query_ms,
      query_source: diagnostics.query_source,
      approximate: diagnostics.approximate,
      summary_freshness_status: diagnostics.summary_freshness_status,
      summary_refreshed_at: diagnostics.summary_refreshed_at,
      query_budget: diagnostics.query_budget,
      deeper_diagnostics_endpoint: '/v1/agent/status',
    } : null,
    next_action: typeof status.next_action === 'string' ? status.next_action : null,
    proof: asRecord(status.proof),
  };
  return redactSensitiveValue(projected) as Record<string, unknown>;
}

export function writeStatusCache(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  status: unknown;
  source: 'runtime' | 'status';
  home?: string;
}): boolean {
  const status = projectStatus(input.status);
  if (!status) return false;
  const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error('Marrow status cache file cannot be a symlink');
  const record: StatusCacheRecord = {
    version: 1,
    stored_at: new Date().toISOString(),
    source: input.source,
    status,
  };
  const serialized = JSON.stringify(record);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_STATUS_BYTES) return false;
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, serialized, { encoding: 'utf8', mode: 0o600, flag: 'w' });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  return true;
}

export function readStatusCache(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  home?: string;
}): { status: Record<string, unknown>; source: 'runtime' | 'status'; stale_ms: number; freshness: 'fresh' | 'stale' } | null {
  const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
  if (!existsSync(path)) return null;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > MAX_STATUS_BYTES) return null;
  try {
    const record = JSON.parse(readFileSync(path, 'utf8')) as Partial<StatusCacheRecord>;
    const storedAt = Date.parse(String(record.stored_at || ''));
    const staleMs = Date.now() - storedAt;
    if (record.version !== 1 || !Number.isFinite(storedAt) || staleMs < 0 || staleMs > MAX_CACHE_AGE_MS) return null;
    if (record.source !== 'runtime' && record.source !== 'status') return null;
    const status = projectStatus(record.status);
    if (!status) return null;
    return {
      status,
      source: record.source,
      stale_ms: staleMs,
      freshness: staleMs <= FRESH_AGE_MS ? 'fresh' : 'stale',
    };
  } catch {
    return null;
  }
}

export function cachedStatusPayload(cached: NonNullable<ReturnType<typeof readStatusCache>>): Record<string, unknown> {
  return {
    ...cached.status,
    live: false,
    cached: true,
    stale: cached.freshness === 'stale',
    status_source: cached.source === 'runtime' ? 'last_known_runtime_status' : 'last_known_status',
    status_freshness: cached.freshness,
    stale_ms: cached.stale_ms,
    authorization_state: 'status_only_non_authorizing',
    fresh_runtime_gate_required_for_high_risk: true,
    exact_next_action: cached.freshness === 'fresh'
      ? 'This last-known status is within the 30-second fast-status window. Use a fresh runtime gate before high-risk work.'
      : 'The live status refresh did not complete. Use this status as context only and obtain a fresh runtime gate before high-risk work.',
  };
}
