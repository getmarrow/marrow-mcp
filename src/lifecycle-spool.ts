import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { redactSensitiveText } from './redact';

export const LIFECYCLE_EVENT_TYPES = [
  'prompt_submitted',
  'goal_started',
  'pre_action_checked',
  'risk_gate_requested',
  'tool_completed',
  'tool_failed',
  'command_completed',
  'command_failed',
  'verification_evidence_added',
  'workflow_completed',
  'session_completed',
  'learned_workflow_created',
  'journey_update',
  'subagent_completed',
  'handoff_started',
  'handoff_completed',
  'proof_pack_closed',
  'outcome_committed',
] as const;

export type LifecycleEventType = typeof LIFECYCLE_EVENT_TYPES[number];

export type LifecycleEvent = {
  event_id?: string;
  event_type: LifecycleEventType;
  harness?: string;
  agent_id?: string;
  action: string;
  workflow_id?: string;
  session_id?: string;
  decision_id?: string;
  correlation_id?: string;
  adapter_version?: string;
  capability_level?: 'native_hooks' | 'mcp' | 'sdk_passive_runtime' | 'governed_wrapper' | 'event_contract';
  config_fingerprint?: string;
  expected_hooks?: string[];
  observed_hook?: string;
  intervention_disposition?: 'followed' | 'ignored' | 'overridden';
  action_changed?: boolean;
  risk_level?: 'low' | 'medium' | 'high';
  outcome_state?: 'pending' | 'closed' | 'unknown' | 'timed_out';
  success?: boolean;
  occurred_at?: string;
};

type DeliveryState = 'queued' | 'dead_letter';
type StoredEvent = Required<Pick<LifecycleEvent, 'event_id' | 'event_type' | 'harness' | 'agent_id' | 'action' | 'occurred_at'>>
  & Omit<LifecycleEvent, 'event_id' | 'event_type' | 'harness' | 'agent_id' | 'action' | 'occurred_at'>
  & { attempts: number; delivery_state: DeliveryState; last_status?: number };

const EVENT_TYPES = new Set<string>(LIFECYCLE_EVENT_TYPES);
const RISK_LEVELS = new Set(['low', 'medium', 'high']);
const OUTCOME_STATES = new Set(['pending', 'closed', 'unknown', 'timed_out']);
const CAPABILITY_LEVELS = new Set(['native_hooks', 'mcp', 'sdk_passive_runtime', 'governed_wrapper', 'event_contract']);
const INTERVENTION_DISPOSITIONS = new Set(['followed', 'ignored', 'overridden']);
const MAX_EVENTS = 1000;
const MAX_RECORD_BYTES = 4096;
const MAX_SPOOL_BYTES = 2 * 1024 * 1024;
const MAX_ATTEMPTS = 3;
const DELIVERY_REQUEST_TIMEOUT_MS = 750;
const DELIVERY_DRAIN_BUDGET_MS = 900;
const LOCK_WAIT_MS = 20;
const LOCK_ATTEMPTS = 250;
const LOCK_STALE_MS = 30_000;

function safeId(value: unknown, fallback?: string): string | undefined {
  const normalized = typeof value === 'string' ? value.trim().slice(0, 128) : '';
  return normalized && /^[A-Za-z0-9._:-]+$/.test(normalized) ? normalized : fallback;
}

function optionalId(value: unknown, field: string): string | undefined {
  if (value == null || value === '') return undefined;
  const id = safeId(value);
  if (!id) throw new Error(`invalid lifecycle ${field}`);
  return id;
}

function compactAction(value: unknown): string {
  const safe = redactSensitiveText(String(value || 'agent lifecycle event'))
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[redacted-email]')
    .replace(/\bhttps?:\/\/\S+/gi, '[redacted-url]')
    .replace(/(?:^|\s)(?:\/[A-Za-z0-9._-]+){2,}/g, ' [redacted-path]')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
  if (!safe) throw new Error('invalid lifecycle action');
  return safe;
}

function hookList(value: unknown): string[] | undefined {
  if (value == null) return undefined;
  if (!Array.isArray(value) || value.length > 12) throw new Error('invalid lifecycle expected_hooks');
  const hooks = value.map((hook) => optionalId(hook, 'expected_hooks'));
  if (hooks.some((hook) => !hook)) throw new Error('invalid lifecycle expected_hooks');
  return [...new Set(hooks as string[])];
}

function canonicalTimestamp(value: unknown): string {
  const timestamp = value == null ? new Date().toISOString() : String(value).trim();
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) {
    throw new Error('invalid lifecycle occurred_at');
  }
  return timestamp;
}

function spoolPath(apiKey: string, agentId?: string): { path: string; ownsParent: boolean } {
  if (process.env.MARROW_EVENT_SPOOL_PATH) {
    return { path: process.env.MARROW_EVENT_SPOOL_PATH, ownsParent: false };
  }
  const namespace = createHash('sha256').update(`${apiKey}:${agentId || 'account'}`).digest('hex').slice(0, 20);
  return { path: join(homedir(), '.marrow', 'spool', `mcp-${namespace}.json`), ownsParent: true };
}

function ensureParent(path: string, ownsParent: boolean): void {
  const parent = dirname(path);
  if (!existsSync(parent)) mkdirSync(parent, { recursive: true, mode: 0o700 });
  if (ownsParent) chmodSync(parent, 0o700);
}

function sleep(milliseconds: number): void {
  const lock = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(lock, 0, 0, milliseconds);
}

function withLock<T>(path: string, ownsParent: boolean, operation: () => T): T {
  ensureParent(path, ownsParent);
  const lockPath = `${path}.lock`;
  let descriptor: number | null = null;
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      descriptor = openSync(lockPath, 'wx', 0o600);
      break;
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
      if (code !== 'EEXIST') throw error;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) unlinkSync(lockPath);
      } catch {
        // The lock may have been released between checks.
      }
      sleep(LOCK_WAIT_MS);
    }
  }
  if (descriptor == null) throw new Error('lifecycle spool lock timeout');
  try {
    return operation();
  } finally {
    closeSync(descriptor);
    try { unlinkSync(lockPath); } catch { /* lock already removed */ }
  }
}

function validateStoredEvent(value: unknown): StoredEvent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid lifecycle spool record');
  const event = value as Record<string, unknown>;
  if (!EVENT_TYPES.has(String(event.event_type))) throw new Error('invalid lifecycle event_type');
  if (event.risk_level != null && !RISK_LEVELS.has(String(event.risk_level))) throw new Error('invalid lifecycle risk_level');
  if (event.outcome_state != null && !OUTCOME_STATES.has(String(event.outcome_state))) throw new Error('invalid lifecycle outcome_state');
  if (event.capability_level != null && !CAPABILITY_LEVELS.has(String(event.capability_level))) throw new Error('invalid lifecycle capability_level');
  if (event.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(String(event.intervention_disposition))) throw new Error('invalid lifecycle intervention_disposition');
  if (event.action_changed != null && typeof event.action_changed !== 'boolean') throw new Error('invalid lifecycle action_changed');
  const expectedHooks = hookList(event.expected_hooks);
  const stored: StoredEvent = {
    event_id: safeId(event.event_id) || (() => { throw new Error('invalid lifecycle event_id'); })(),
    event_type: String(event.event_type) as LifecycleEventType,
    harness: safeId(event.harness, 'custom') || 'custom',
    agent_id: safeId(event.agent_id, 'unknown') || 'unknown',
    action: compactAction(event.action),
    ...(safeId(event.workflow_id) ? { workflow_id: safeId(event.workflow_id) } : {}),
    ...(safeId(event.session_id) ? { session_id: safeId(event.session_id) } : {}),
    ...(safeId(event.decision_id) ? { decision_id: safeId(event.decision_id) } : {}),
    ...(safeId(event.correlation_id) ? { correlation_id: safeId(event.correlation_id) } : {}),
    ...(safeId(event.adapter_version) ? { adapter_version: safeId(event.adapter_version) } : {}),
    ...(event.capability_level ? { capability_level: String(event.capability_level) as LifecycleEvent['capability_level'] } : {}),
    ...(safeId(event.config_fingerprint) ? { config_fingerprint: safeId(event.config_fingerprint) } : {}),
    ...(expectedHooks ? { expected_hooks: expectedHooks } : {}),
    ...(safeId(event.observed_hook) ? { observed_hook: safeId(event.observed_hook) } : {}),
    ...(event.intervention_disposition ? { intervention_disposition: String(event.intervention_disposition) as LifecycleEvent['intervention_disposition'] } : {}),
    ...(typeof event.action_changed === 'boolean' ? { action_changed: event.action_changed } : {}),
    ...(event.risk_level ? { risk_level: String(event.risk_level) as LifecycleEvent['risk_level'] } : {}),
    ...(event.outcome_state ? { outcome_state: String(event.outcome_state) as LifecycleEvent['outcome_state'] } : {}),
    ...(typeof event.success === 'boolean' ? { success: event.success } : {}),
    occurred_at: canonicalTimestamp(event.occurred_at),
    attempts: Number.isInteger(event.attempts) && Number(event.attempts) >= 0 ? Math.min(Number(event.attempts), MAX_ATTEMPTS) : 0,
    delivery_state: event.delivery_state === 'dead_letter' ? 'dead_letter' : 'queued',
    ...(Number.isInteger(event.last_status) ? { last_status: Number(event.last_status) } : {}),
  };
  if (Buffer.byteLength(JSON.stringify(stored), 'utf8') > MAX_RECORD_BYTES) {
    throw new Error('lifecycle spool record exceeds byte limit');
  }
  return stored;
}

function compact(input: LifecycleEvent): StoredEvent {
  if (!input || typeof input !== 'object') throw new Error('invalid lifecycle event');
  if (!EVENT_TYPES.has(String(input.event_type))) throw new Error('invalid lifecycle event_type');
  if (input.risk_level != null && !RISK_LEVELS.has(input.risk_level)) throw new Error('invalid lifecycle risk_level');
  if (input.outcome_state != null && !OUTCOME_STATES.has(input.outcome_state)) throw new Error('invalid lifecycle outcome_state');
  if (input.capability_level != null && !CAPABILITY_LEVELS.has(input.capability_level)) throw new Error('invalid lifecycle capability_level');
  if (input.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(input.intervention_disposition)) throw new Error('invalid lifecycle intervention_disposition');
  if (input.action_changed != null && typeof input.action_changed !== 'boolean') throw new Error('invalid lifecycle action_changed');
  const eventId = optionalId(input.event_id, 'event_id') || randomUUID();
  const harness = optionalId(input.harness, 'harness') || 'custom';
  const agentId = optionalId(input.agent_id, 'agent_id') || 'unknown';
  const workflowId = optionalId(input.workflow_id, 'workflow_id');
  const sessionId = optionalId(input.session_id, 'session_id');
  const decisionId = optionalId(input.decision_id, 'decision_id');
  const correlationId = optionalId(input.correlation_id, 'correlation_id')
    || decisionId
    || workflowId
    || sessionId
    || eventId;
  const expectedHooks = hookList(input.expected_hooks);
  return validateStoredEvent({
    event_id: eventId,
    event_type: input.event_type,
    harness,
    agent_id: agentId,
    action: compactAction(input.action),
    ...(workflowId ? { workflow_id: workflowId } : {}),
    ...(sessionId ? { session_id: sessionId } : {}),
    ...(decisionId ? { decision_id: decisionId } : {}),
    correlation_id: correlationId,
    ...(optionalId(input.adapter_version, 'adapter_version') ? { adapter_version: optionalId(input.adapter_version, 'adapter_version') } : {}),
    ...(input.capability_level ? { capability_level: input.capability_level } : {}),
    ...(optionalId(input.config_fingerprint, 'config_fingerprint') ? { config_fingerprint: optionalId(input.config_fingerprint, 'config_fingerprint') } : {}),
    ...(expectedHooks ? { expected_hooks: expectedHooks } : {}),
    ...(optionalId(input.observed_hook, 'observed_hook') ? { observed_hook: optionalId(input.observed_hook, 'observed_hook') } : {}),
    ...(input.intervention_disposition ? { intervention_disposition: input.intervention_disposition } : {}),
    ...(typeof input.action_changed === 'boolean' ? { action_changed: input.action_changed } : {}),
    ...(input.risk_level ? { risk_level: input.risk_level } : {}),
    ...(input.outcome_state ? { outcome_state: input.outcome_state } : {}),
    ...(typeof input.success === 'boolean' ? { success: input.success } : {}),
    occurred_at: canonicalTimestamp(input.occurred_at),
    attempts: 0,
    delivery_state: 'queued',
  });
}

function readUnlocked(path: string): { events: StoredEvent[]; recoveredCorruption: boolean } {
  if (!existsSync(path)) return { events: [], recoveredCorruption: false };
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error('invalid lifecycle spool');
    if (parsed.length > MAX_EVENTS) throw new Error('lifecycle spool exceeds event capacity');
    return { events: parsed.map(validateStoredEvent), recoveredCorruption: false };
  } catch {
    const quarantine = `${path}.corrupt-${Date.now()}-${randomUUID()}`;
    renameSync(path, quarantine);
    return { events: [], recoveredCorruption: true };
  }
}

function writeUnlocked(path: string, events: StoredEvent[]): void {
  if (events.length > MAX_EVENTS) {
    throw new Error('lifecycle spool capacity exceeded; receipt was not accepted');
  }
  const serialized = JSON.stringify(events);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_SPOOL_BYTES) {
    throw new Error('lifecycle spool byte capacity exceeded; receipt was not accepted');
  }
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, serialized, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function mutate<T>(path: string, ownsParent: boolean, operation: (events: StoredEvent[]) => T): { result: T; recoveredCorruption: boolean } {
  return withLock(path, ownsParent, () => {
    const current = readUnlocked(path);
    const result = operation(current.events);
    writeUnlocked(path, current.events);
    return { result, recoveredCorruption: current.recoveredCorruption };
  });
}

function snapshot(path: string, ownsParent: boolean): { events: StoredEvent[]; recoveredCorruption: boolean } {
  return withLock(path, ownsParent, () => readUnlocked(path));
}

function retryable(status: number): boolean {
  return status === 0 || [408, 425, 429, 500, 502, 503, 504].includes(status);
}

async function deliver(baseUrl: string, apiKey: string, queued: StoredEvent, timeoutMs: number): Promise<number> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const response = await Promise.race([
      fetch(`${baseUrl}/v1/agent/integrations/events`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'X-Marrow-Client': 'mcp',
          ...(queued.session_id ? { 'X-Marrow-Session-Id': queued.session_id } : {}),
          ...(queued.agent_id !== 'unknown' ? { 'X-Marrow-Agent-Id': queued.agent_id } : {}),
        },
        body: JSON.stringify(queued),
        signal: controller.signal,
      }),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Error('lifecycle delivery timeout'));
        }, timeoutMs);
      }),
    ]);
    return response.status;
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

export async function recordLifecycleEvent(input: {
  apiKey: string;
  baseUrl: string;
  event: LifecycleEvent;
}): Promise<{
  event_id: string;
  accepted: boolean;
  queued: boolean;
  failed: boolean;
  pending: number;
  recovered_corruption: boolean;
}> {
  const location = spoolPath(input.apiKey, input.event.agent_id);
  const event = compact(input.event);
  let recoveredCorruption = mutate(location.path, location.ownsParent, (events) => {
    const index = events.findIndex((row) => row.event_id === event.event_id);
    if (index < 0) events.push(event);
  }).recoveredCorruption;

  const initial = snapshot(location.path, location.ownsParent);
  recoveredCorruption ||= initial.recoveredCorruption;
  const deliveryDeadline = Date.now() + DELIVERY_DRAIN_BUDGET_MS;
  for (const queued of initial.events.filter((row) => row.delivery_state === 'queued').slice(0, 10)) {
    const remainingMs = Math.min(DELIVERY_REQUEST_TIMEOUT_MS, deliveryDeadline - Date.now());
    if (remainingMs <= 0) break;
    let status = 0;
    try {
      status = await deliver(input.baseUrl, input.apiKey, queued, remainingMs);
    } catch {
      status = 0;
    }
    mutate(location.path, location.ownsParent, (events) => {
      const current = events.find((row) => row.event_id === queued.event_id);
      if (!current || current.delivery_state !== 'queued') return;
      if (status >= 200 && status < 300) {
        events.splice(events.indexOf(current), 1);
        return;
      }
      current.attempts += 1;
      if (!retryable(status) || current.attempts >= MAX_ATTEMPTS) {
        current.delivery_state = 'dead_letter';
        if (status > 0) current.last_status = status;
      }
    });
    if (!(status >= 200 && status < 300)) break;
  }

  const final = snapshot(location.path, location.ownsParent);
  recoveredCorruption ||= final.recoveredCorruption;
  const current = final.events.find((row) => row.event_id === event.event_id);
  return {
    event_id: event.event_id,
    accepted: !current,
    queued: current?.delivery_state === 'queued',
    failed: current?.delivery_state === 'dead_letter',
    pending: final.events.length,
    recovered_corruption: recoveredCorruption,
  };
}
