import { recordLifecycleEvent } from './lifecycle-spool';
import { marrowModelUsage, marrowSessionEnd, validateBaseUrl } from './index';
import { extractModelUsageFromUnknown } from './habit-loop-copy';
import { readFileSync } from 'node:fs';
import {
  findHookSettingsPath,
  clientReportedHookLifecycleIdentity,
  normalizeHookEventPayload,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
  resolveNativeHookIdentity,
  SESSION_END_HOOK_COMMAND,
  stableSessionWorkflowId,
} from './hook-contract';

export const SESSION_HOOK_COMMAND = SESSION_END_HOOK_COMMAND;
const MAX_HOOK_INPUT_BYTES = 64 * 1024;
const SESSION_END_TIMEOUT_MS = 900;

type StopHookSource = {
  session_id?: string;
  conversation_id?: string;
  generation_id?: string;
  tool_use_id?: string;
  task_id?: string;
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
  const source = normalizeHookEventPayload(value);
  const take = (field: string): string | undefined => {
    const candidate = typeof source[field] === 'string' ? String(source[field]).trim().slice(0, 1024) : '';
    return candidate || undefined;
  };
  return {
    session_id: take('session_id'),
    conversation_id: take('conversation_id'),
    generation_id: take('generation_id'),
    tool_use_id: take('tool_use_id'),
    task_id: take('task_id'),
    transcript_path: take('transcript_path'),
    cwd: take('cwd'),
    hook_event_name: take('hook_event_name'),
  };
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
      marrowSessionEnd(apiKey, baseUrl, true, sessionId, agentId, controller.signal),
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

export function installSessionEndHook(startDir = process.cwd()): { settingsPath: string; installed: boolean } {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  const target = findHookSettingsPath(startDir);
  const settings = readHookSettingsForInstall(startDir);
  const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
    ? settings.hooks as Record<string, unknown>
    : {};
  const reconciled = reconcileMarrowCommandHook(settings, 'Stop', 'session-hook', SESSION_HOOK_COMMAND);
  settings.hooks = { ...hooks, Stop: reconciled.entries };
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath: target, installed: reconciled.changed };
}

export function sessionEndAutoCommitOpen(value?: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (value === false || value === 0 || value === '0' || value === 'false') return false;
  return Boolean(value);
}

export async function runSessionHookCommand(input?: unknown): Promise<void> {
  if (process.env.MARROW_AUTO_HOOK === 'false') return;
  const identity = resolveNativeHookIdentity(process.argv[2]);
  const resolved = identity.environment;
  if (!resolved.apiKey) return;
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  const source = readStopHookSource(input);
  const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id || undefined;
  const agentId = identity.agent_id;
  const workflowId = stableSessionWorkflowId(
    sessionId,
    identity.harness === 'cursor'
      ? [source.conversation_id, source.generation_id, source.tool_use_id]
      : identity.harness === 'cline'
      ? [source.task_id, source.hook_event_name]
      : identity.harness === 'windsurf'
      ? [source.session_id, source.tool_use_id]
      : [source.transcript_path, source.cwd],
  );
  const correlation = workflowId.slice('session-'.length);
  await recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_id: `session-stop-${correlation}`,
      event_type: 'session_completed',
      ...clientReportedHookLifecycleIdentity(identity),
      session_id: sessionId,
      workflow_id: workflowId,
      correlation_id: correlation,
      action: identity.harness === 'cline' && source.hook_event_name === 'TaskCancel'
        ? 'agent task cancelled'
        : identity.harness === 'windsurf'
        ? 'cascade response completed'
        : 'agent session ended',
      outcome_state: 'pending',
    },
  });
  try {
    await boundedSessionEnd(resolved.apiKey, baseUrl, sessionId, agentId);
  } catch {
    // The pending lifecycle receipt remains durable for later reconciliation.
  }

  if (identity.harness !== 'windsurf' && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
    const usage = extractModelUsageFromUnknown(input);
    if (usage && (usage.input_tokens || usage.output_tokens || usage.total_tokens || usage.cached_tokens)) {
      await marrowModelUsage(resolved.apiKey, baseUrl, {
        ...usage,
        source: 'mcp_session_end',
        marrow_intervention: 'passive_model_usage_capture',
        action_type: 'session',
      }, sessionId, agentId).catch(() => undefined);
    }
  }
}
