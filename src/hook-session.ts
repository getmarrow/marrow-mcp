import { captureCodexNativeUsage } from './codex-native-usage';
import { payloadBoundEvent, recordLifecycleEvent } from './lifecycle-spool';
import { marrowModelUsage, marrowSessionEnd, validateBaseUrl } from './index';
import { extractModelUsageFromUnknown, modelUsageCaptureContextFromEnv } from './habit-loop-copy';
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
import { readLocalControlState } from './control-state';
import { clearSessionLoopGuard } from './session-loop-guard';
import { approvalHostFor, flushHoldOutbox, hostSessionIdFor, noteCursorSession, type HoldContext } from './host-approval';

export const SESSION_HOOK_COMMAND = SESSION_END_HOOK_COMMAND;
const MAX_HOOK_INPUT_BYTES = 64 * 1024;
const SESSION_END_TIMEOUT_MS = 900;
const completedGrokTurns = new Set<string>();

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

function readStopHookInput(input?: unknown): unknown {
  let value = input;
  if (value === undefined) {
    try {
      const raw = readFileSync(0, 'utf8').slice(0, MAX_HOOK_INPUT_BYTES);
      value = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      value = {};
    }
  }
  return value;
}

function readStopHookSource(input: unknown): StopHookSource {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const source = normalizeHookEventPayload(input);
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
  const identity = resolveNativeHookIdentity(process.argv[2]);
  try {
    if (process.env.MARROW_AUTO_HOOK === 'false') return;
    try { if (!readLocalControlState().enabled) return; } catch { return; }
    const resolved = identity.environment;
    const payload = readStopHookInput(input);
    const raw = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as Record<string, unknown> : {};
    if (identity.harness === 'cursor' && raw.hook_event_name === 'sessionStart') {
      // Evidence for Cursor approval prompts: only a local, non-background session is interactive.
      const sessionKey = typeof raw.session_id === 'string' ? raw.session_id : typeof raw.conversation_id === 'string' ? raw.conversation_id : '';
      if (resolved.apiKey && sessionKey) {
        try {
          const context: HoldContext = {
            apiKey: resolved.apiKey,
            baseUrl: validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai'),
            sessionId: sessionKey,
            agentId: identity.agent_id,
            harness: identity.harness,
            host: 'cursor',
            hostSessionId: hostSessionIdFor([sessionKey], sessionKey),
          };
          noteCursorSession(context, { isBackgroundAgent: raw.is_background_agent });
        } catch { /* without evidence Cursor holds are denied, not asked */ }
      }
      process.stdout.write('{}');
      return;
    }
    const source = readStopHookSource(payload);
    const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id
      || stableSessionWorkflowId(undefined, [identity.harness, process.cwd()]);
    const agentId = identity.agent_id;
    try { clearSessionLoopGuard({ sessionId, agentId, harness: identity.harness }); } catch { /* session close remains best effort */ }
    if (!resolved.apiKey) return;
    const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
    const workflowId = stableSessionWorkflowId(
      sessionId,
      identity.harness === 'cursor'
        ? [source.conversation_id, source.generation_id, source.tool_use_id]
        : identity.harness === 'cline'
        ? [source.task_id, source.hook_event_name]
        : ['windsurf', 'gemini', 'grok'].includes(identity.harness)
        ? [source.session_id, source.tool_use_id]
        : [source.transcript_path, source.cwd],
    );
    const correlation = workflowId.slice('session-'.length);
    if (identity.harness === 'grok') {
      if (completedGrokTurns.has(correlation)) return;
      completedGrokTurns.add(correlation);
      if (completedGrokTurns.size > 1024) {
        const oldest = completedGrokTurns.values().next().value;
        if (oldest) completedGrokTurns.delete(oldest);
      }
    }
    await recordLifecycleEvent({
      apiKey: resolved.apiKey,
      baseUrl,
      reuseQueuedBase: `session-stop-${correlation}`,
      event: payloadBoundEvent(`session-stop-${correlation}`, {
        event_type: 'session_completed',
        ...clientReportedHookLifecycleIdentity(identity),
        session_id: sessionId,
        workflow_id: workflowId,
        correlation_id: correlation,
        action: identity.harness === 'cline' && source.hook_event_name === 'TaskCancel'
          ? 'agent task cancelled'
          : identity.harness === 'windsurf'
          ? 'cascade response completed'
          : identity.harness === 'gemini'
          ? 'agent turn completed'
          : identity.harness === 'grok'
          ? 'agent turn completed'
          : 'agent session ended',
        outcome_state: 'pending',
      }),
    });
    try {
      await boundedSessionEnd(resolved.apiKey, baseUrl, sessionId, agentId);
    } catch {
      // The pending lifecycle receipt remains durable for later reconciliation.
    }
    await flushHoldOutbox({
      apiKey: resolved.apiKey,
      baseUrl,
      sessionId,
      agentId,
      harness: identity.harness,
      host: approvalHostFor(identity.harness),
      hostSessionId: hostSessionIdFor([source.session_id, source.conversation_id, source.task_id], sessionId),
    }, 2, 2_000).catch(() => undefined);

    if (!['windsurf', 'gemini', 'grok'].includes(identity.harness) && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
      const usage = extractModelUsageFromUnknown(payload, { ...modelUsageCaptureContextFromEnv(), usage_kind: 'cumulative' });
      if (usage) {
        await marrowModelUsage(resolved.apiKey, baseUrl, {
          ...usage,
          source: 'mcp_session_end',
          marrow_intervention: 'passive_model_usage_capture',
          action_type: 'session',
        }, sessionId, agentId).catch(() => undefined);
      } else if (identity.harness === 'codex') {
        await captureCodexNativeUsage(payload, resolved.apiKey, baseUrl, agentId);
      }
    }
  } catch (error) {
    if (!['gemini', 'grok'].includes(identity.harness)) throw error;
  } finally {
    if (identity.harness === 'gemini') process.stdout.write('{}');
  }
}
