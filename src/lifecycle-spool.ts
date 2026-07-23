import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { redactSensitiveText } from './redact';

export type LifecycleEvent = {
  event_id?: string;
  event_type: string;
  harness?: string;
  agent_id?: string;
  action: string;
  workflow_id?: string;
  session_id?: string;
  decision_id?: string;
  risk_level?: 'low' | 'medium' | 'high';
  outcome_state?: 'pending' | 'closed' | 'unknown' | 'timed_out';
  success?: boolean;
  occurred_at?: string;
};

type StoredEvent = Required<Pick<LifecycleEvent, 'event_id' | 'event_type' | 'harness' | 'agent_id' | 'action' | 'occurred_at'>>
  & Omit<LifecycleEvent, 'event_id' | 'event_type' | 'harness' | 'agent_id' | 'action' | 'occurred_at'>
  & { attempts: number };

const MAX_EVENTS = 100;

function safeId(value: unknown, fallback?: string): string | undefined {
  const normalized = typeof value === 'string' ? value.trim().slice(0, 128) : '';
  return normalized && /^[A-Za-z0-9._:-]+$/.test(normalized) ? normalized : fallback;
}

function spoolPath(apiKey: string, agentId?: string): string {
  if (process.env.MARROW_EVENT_SPOOL_PATH) return process.env.MARROW_EVENT_SPOOL_PATH;
  const namespace = createHash('sha256').update(`${apiKey}:${agentId || 'account'}`).digest('hex').slice(0, 20);
  return join(homedir(), '.marrow', 'spool', `mcp-${namespace}.json`);
}

function read(path: string): StoredEvent[] {
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return Array.isArray(parsed) ? parsed.slice(-MAX_EVENTS) : [];
  } catch {
    return [];
  }
}

function write(path: string, events: StoredEvent[]): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  chmodSync(dirname(path), 0o700);
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, JSON.stringify(events.slice(-MAX_EVENTS)), { encoding: 'utf8', mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function compact(input: LifecycleEvent): StoredEvent {
  return {
    event_id: safeId(input.event_id) || randomUUID(),
    event_type: safeId(input.event_type, 'unknown') || 'unknown',
    harness: safeId(input.harness, 'custom') || 'custom',
    agent_id: safeId(input.agent_id, 'unknown') || 'unknown',
    action: redactSensitiveText(String(input.action || input.event_type)).replace(/\s+/g, ' ').trim().slice(0, 240),
    ...(safeId(input.workflow_id) ? { workflow_id: safeId(input.workflow_id) } : {}),
    ...(safeId(input.session_id) ? { session_id: safeId(input.session_id) } : {}),
    ...(safeId(input.decision_id) ? { decision_id: safeId(input.decision_id) } : {}),
    ...(input.risk_level ? { risk_level: input.risk_level } : {}),
    ...(input.outcome_state ? { outcome_state: input.outcome_state } : {}),
    ...(typeof input.success === 'boolean' ? { success: input.success } : {}),
    occurred_at: input.occurred_at || new Date().toISOString(),
    attempts: 0,
  };
}

function retryable(status: number): boolean {
  return [408, 425, 429, 500, 502, 503, 504].includes(status);
}

export async function recordLifecycleEvent(input: {
  apiKey: string;
  baseUrl: string;
  event: LifecycleEvent;
}): Promise<{ event_id: string; queued: boolean; pending: number }> {
  const path = spoolPath(input.apiKey, input.event.agent_id);
  const event = compact(input.event);
  const initial = read(path).filter((row) => row.event_id !== event.event_id);
  write(path, [...initial, event]);

  const remaining = read(path);
  for (const queued of remaining.slice(0, 10)) {
    try {
      const response = await fetch(`${input.baseUrl}/v1/agent/integrations/events`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${input.apiKey}`,
          'Content-Type': 'application/json',
          'X-Marrow-Client': 'mcp',
          ...(queued.session_id ? { 'X-Marrow-Session-Id': queued.session_id } : {}),
          ...(queued.agent_id !== 'unknown' ? { 'X-Marrow-Agent-Id': queued.agent_id } : {}),
        },
        body: JSON.stringify(queued),
      });
      if (response.ok) {
        write(path, read(path).filter((row) => row.event_id !== queued.event_id));
        continue;
      }
      if (retryable(response.status) && queued.attempts < 3) {
        write(path, read(path).map((row) => row.event_id === queued.event_id ? { ...row, attempts: row.attempts + 1 } : row));
        break;
      }
      write(path, read(path).filter((row) => row.event_id !== queued.event_id));
    } catch {
      write(path, read(path).map((row) => row.event_id === queued.event_id ? { ...row, attempts: row.attempts + 1 } : row));
      break;
    }
  }

  const pending = read(path).length;
  return { event_id: event.event_id, queued: pending > 0, pending };
}
