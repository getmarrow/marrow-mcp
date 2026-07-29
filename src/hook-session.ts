import { resolveMarrowEnv } from './env';
import { recordLifecycleEvent } from './lifecycle-spool';
import { marrowSessionEnd, validateBaseUrl } from './index';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const SESSION_HOOK_COMMAND = 'npx -y @getmarrow/mcp session-hook';
const MAX_HOOK_INPUT_BYTES = 64 * 1024;
const SESSION_END_TIMEOUT_MS = 900;

type StopHookSource = {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
};

function readStopHookSource(input?: unknown): StopHookSource {
  let value = input;
  if (value === undefined) {
    try {
      const raw = readFileSync(0, 'utf8').slice(0, MAX_HOOK_INPUT_BYTES);
      value = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      value = {};
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const source = value as Record<string, unknown>;
  const take = (field: string): string | undefined => {
    const candidate = typeof source[field] === 'string' ? String(source[field]).trim().slice(0, 1024) : '';
    return candidate || undefined;
  };
  return {
    session_id: take('session_id'),
    transcript_path: take('transcript_path'),
    cwd: take('cwd'),
    hook_event_name: take('hook_event_name'),
  };
}

function stopCorrelation(source: StopHookSource, sessionId?: string): string {
  const stableSource = sessionId || JSON.stringify([
    source.session_id || '',
    source.transcript_path || '',
    source.cwd || '',
    source.hook_event_name || 'Stop',
  ]);
  return createHash('sha256').update(stableSource).digest('hex').slice(0, 32);
}

async function boundedSessionEnd(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string,
): Promise<void> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      marrowSessionEnd(apiKey, baseUrl, false, sessionId, agentId, controller.signal),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Error('session end timeout'));
        }, SESSION_END_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function settingsPath(startDir: string): string {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  let dir = startDir;
  while (true) {
    const candidate = path.join(dir, '.claude', 'settings.json');
    if (fs.existsSync(candidate) || fs.existsSync(path.join(dir, '.git'))) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.join(startDir, '.claude', 'settings.json');
}

export function installSessionEndHook(startDir = process.cwd()): { settingsPath: string; installed: boolean } {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  const target = settingsPath(startDir);
  const settings = fs.existsSync(target) && fs.readFileSync(target, 'utf8').trim()
    ? JSON.parse(fs.readFileSync(target, 'utf8')) as Record<string, unknown>
    : {};
  const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
    ? settings.hooks as Record<string, unknown>
    : {};
  const stop = Array.isArray(hooks.Stop) ? [...hooks.Stop] : [];
  const installed = stop.some((entry) => JSON.stringify(entry).includes(SESSION_HOOK_COMMAND));
  if (!installed) stop.push({ hooks: [{ type: 'command', command: SESSION_HOOK_COMMAND }] });
  settings.hooks = { ...hooks, Stop: stop };
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath: target, installed: !installed };
}

export async function runSessionHookCommand(input?: unknown): Promise<void> {
  if (process.env.MARROW_AUTO_HOOK === 'false') return;
  const resolved = resolveMarrowEnv();
  if (!resolved.apiKey) return;
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  const source = readStopHookSource(input);
  const sessionId = resolved.sessionId || source.session_id || undefined;
  const agentId = resolved.agentId || undefined;
  const correlation = stopCorrelation(source, sessionId);
  await recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_id: `session-stop-${correlation}`,
      event_type: 'session_completed',
      harness: 'claude-code',
      agent_id: agentId,
      session_id: sessionId,
      workflow_id: `session-${correlation}`,
      correlation_id: correlation,
      observed_hook: 'session_end',
      action: 'agent session ended',
      outcome_state: 'pending',
    },
  });
  try {
    await boundedSessionEnd(resolved.apiKey, baseUrl, sessionId, agentId);
  } catch {
    // The pending lifecycle receipt remains durable for later reconciliation.
  }
}
