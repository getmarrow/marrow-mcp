import { captureCodexNativeUsage } from './codex-native-usage';
import { marrowModelUsage, validateBaseUrl } from './index';
import { extractModelUsageFromUnknown, modelUsageCaptureContextFromEnv } from './habit-loop-copy';
import { backgroundNudgeEnabled, recordLifecycleEvent } from './lifecycle-spool';
import { classifyTool } from './hook-pre-action';
import { readLocalControlState } from './control-state';
import { isOfficialMarrowMcpEvent, isReadOnlyToolEvent, normalizeHookToolName } from './hook-tool-policy';
import { recordSessionLoopOutcome, type LoopGuardOperation } from './session-loop-guard';
import {
  approvalHostFor,
  flushHoldOutbox,
  hostSessionIdFor,
  noteDialogShown,
  settleAfterTool,
  settleToolBatch,
  type HoldContext,
} from './host-approval';
import {
  ACTION_RESULT_HOOK_COMMAND,
  findHookSettingsPath,
  clientReportedHookLifecycleIdentity,
  NATIVE_HOOK_MATCHER,
  normalizeHookEventPayload,
  PERMISSION_REQUEST_HOOK_COMMAND,
  privateHookLoopGuardPayload,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
  resolveNativeHookIdentity,
  stableSessionWorkflowId,
  stableToolCorrelation,
} from './hook-contract';

export const AUTO_HOOK_COMMAND = ACTION_RESULT_HOOK_COMMAND;
export const AUTO_HOOK_MATCHER = NATIVE_HOOK_MATCHER;
const HOOK_DEBUG = process.env.MARROW_HOOK_DEBUG === 'true';

function debug(msg: string): void {
  if (HOOK_DEBUG) process.stderr.write(msg + '\n');
}

interface HookEvent {
  tool_calls?: unknown;
  transcript_path?: unknown;
  session_id?: string;
  conversation_id?: string;
  generation_id?: string;
  task_id?: string;
  hook_event_name?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  tool_result?: unknown;
  tool_output?: unknown;
  error?: unknown;
  error_message?: unknown;
  failure_type?: unknown;
  duration_ms?: unknown;
  success?: unknown;
  is_interrupt?: boolean;
}

interface HookInstallResult {
  settingsPath: string;
  installed: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function getString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function normalizeToolName(toolName: string): string {
  return normalizeHookToolName(toolName);
}

export function shouldSkipAutoLog(event: HookEvent): boolean {
  return isReadOnlyToolEvent(event);
}

export function deriveAction(event: HookEvent): string | null {
  const toolName = getString(event.tool_name);
  if (!toolName || shouldSkipAutoLog(event)) return null;
  if (isOfficialMarrowMcpEvent(event)) return null;
  return classifyTool(event).action;
}

export function deriveToolOutcome(event: HookEvent): { success: boolean; duration_ms?: number } {
  const response = event.tool_output ?? event.tool_response ?? event.tool_result;
  const responseRecord = asRecord(response);
  const errorValue = responseRecord?.error;

  const failed = event.hook_event_name === 'PostToolUseFailure'
    || event.error != null
    || event.error_message != null
    || event.failure_type != null
    || event.success === false
    || errorValue !== undefined && errorValue !== null
    || responseRecord?.is_error === true
    || responseRecord?.success === false
    || (typeof responseRecord?.exit_code === 'number' && responseRecord.exit_code !== 0)
    || /^(?:failed|error|blocked)$/i.test(String(responseRecord?.status || ''));

  const duration = typeof event.duration_ms === 'number' && Number.isFinite(event.duration_ms)
    ? Math.max(0, Math.min(300_000, Math.round(event.duration_ms)))
    : undefined;
  return { success: !failed, ...(duration === undefined ? {} : { duration_ms: duration }) };
}

async function readStdin(): Promise<string> {
  const chunks: string[] = [];
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return chunks.join('');
}

export function installPostToolUseHook(startDir: string = process.cwd()): HookInstallResult {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');

  const settingsPath = findHookSettingsPath(startDir);
  const settings = readHookSettingsForInstall(startDir);

  const hooks = asRecord(settings.hooks) || {};
  const success = reconcileMarrowCommandHook(settings, 'PostToolUse', 'hook', AUTO_HOOK_COMMAND, AUTO_HOOK_MATCHER);
  const failure = reconcileMarrowCommandHook(settings, 'PostToolUseFailure', 'hook', AUTO_HOOK_COMMAND, AUTO_HOOK_MATCHER);

  settings.hooks = {
    ...hooks,
    PostToolUse: success.entries,
    PostToolUseFailure: failure.entries,
  };

  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');

  return {
    settingsPath,
    installed: success.changed || failure.changed,
  };
}

let spooledLifecycleEvent = false;
/** True only when the latest runHookCommand call spooled an event for background delivery. */
export function hookSpooledLifecycleEvent(): boolean {
  return spooledLifecycleEvent;
}

function holdContextFor(
  identity: ReturnType<typeof resolveNativeHookIdentity>,
  event: HookEvent,
  sessionIdOverride?: string,
): HoldContext | null {
  const apiKey = identity.environment.apiKey || '';
  if (!apiKey) return null;
  let baseUrl: string;
  try {
    baseUrl = validateBaseUrl(identity.environment.baseUrl || 'https://api.getmarrow.ai');
  } catch {
    return null;
  }
  const sessionId = sessionIdOverride || identity.environment.sessionId || getString(event.session_id) || getString(event.conversation_id)
    || getString(event.task_id) || stableSessionWorkflowId(undefined, [identity.harness, process.cwd()]);
  return {
    apiKey,
    baseUrl,
    sessionId,
    agentId: identity.agent_id,
    harness: identity.harness,
    host: approvalHostFor(identity.harness),
    hostSessionId: hostSessionIdFor([event.session_id, event.conversation_id, event.task_id], sessionId),
  };
}

/** Model-facing context for a held call that ran (never contains an approval code). */
let heldActionContext: string | null = null;
let lastHookEventName: unknown = null;

function emitHeldActionContext(identity: ReturnType<typeof resolveNativeHookIdentity>, eventName: unknown): void {
  const text = heldActionContext;
  heldActionContext = null;
  if (!text || !['claude-code', 'codex', 'mcp-client'].includes(identity.harness)) return;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: eventName === 'PostToolUseFailure' ? 'PostToolUseFailure' : 'PostToolUse',
      additionalContext: text,
    },
  }));
}

export async function runHookCommand(input?: unknown): Promise<void> {
  spooledLifecycleEvent = false;
  heldActionContext = null;
  lastHookEventName = null;
  const identity = resolveNativeHookIdentity(process.argv[2]);
  if (process.env.MARROW_AUTO_HOOK === 'false') {
    if (identity.harness === 'gemini') process.stdout.write('{}');
    return;
  }

  try { if (!readLocalControlState().enabled) { if (identity.harness === 'gemini') process.stdout.write('{}'); return; } }
  catch { if (identity.harness === 'gemini') process.stdout.write('{}'); return; }

  try {
    let event: HookEvent;
    if (input === undefined) {
      const raw = (await readStdin()).trim();
      if (!raw) return;
      try {
        event = normalizeHookEventPayload(JSON.parse(raw)) as HookEvent;
      } catch {
        debug('[marrow-hook] skipped invalid JSON');
        return;
      }
    } else {
      event = normalizeHookEventPayload(input) as HookEvent;
    }
    lastHookEventName = event.hook_event_name;

    const resolvedEnv = identity.environment;
    if (identity.harness === 'codex' && resolvedEnv.apiKey && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
      const context = modelUsageCaptureContextFromEnv();
      const supplied = extractModelUsageFromUnknown(event.tool_response, context)
        || extractModelUsageFromUnknown(event.tool_result, context)
        || extractModelUsageFromUnknown(event.tool_output, context)
        || extractModelUsageFromUnknown(event, context);
      if (!supplied) await captureCodexNativeUsage(event, resolvedEnv.apiKey,
        validateBaseUrl(resolvedEnv.baseUrl || 'https://api.getmarrow.ai'), identity.agent_id);
    }
    if (event.hook_event_name === 'PostToolBatch') {
      // Claude Code, installed async: decides still-open asked calls of the batch.
      const batchContext = holdContextFor(identity, event);
      if (batchContext) {
        await settleToolBatch(batchContext, { toolCalls: event.tool_calls, transcriptPath: event.transcript_path });
        await flushHoldOutbox(batchContext);
      }
      return;
    }
    if (isOfficialMarrowMcpEvent(event)) {
      return;
    }
    const privateLoopPayload = privateHookLoopGuardPayload(event);
    const classified = classifyTool(event);
    const sessionId = resolvedEnv.sessionId || getString(event.session_id) || getString(event.conversation_id) || getString(event.task_id)
      || stableSessionWorkflowId(undefined, [identity.harness, process.cwd()]);
    const agentId = identity.agent_id;
    const outcome = deriveToolOutcome(event);
    const loopOperation: LoopGuardOperation = {
      sessionId,
      agentId,
      harness: identity.harness,
      toolName: event.tool_name,
      toolInput: privateLoopPayload.toolInput ?? event.tool_input,
      invocationId: event.tool_use_id,
      readOnly: classified.readOnly,
    };
    try {
      recordSessionLoopOutcome(
        loopOperation,
        outcome.success,
        privateLoopPayload.toolResult ?? event.tool_output ?? event.tool_response ?? event.tool_result
          ?? { success: event.success, error: event.error, failure_type: event.failure_type },
      );
    } catch {
      debug('[marrow-hook] local loop guard state is unsafe');
    }

    // A held call that ran: the operator allowed it in the host prompt, or a
    // waited hold was approved and retried. Report and close, or hand off.
    const heldContext = holdContextFor(identity, event, sessionId);
    if (heldContext) {
      const correlation = stableToolCorrelation({ ...event, session_id: sessionId });
      const handoff = await settleAfterTool(heldContext, {
        correlation,
        toolUseId: getString(event.tool_use_id) || null,
        generationId: getString(event.generation_id) || null,
        success: outcome.success,
      }).catch(() => null);
      if (handoff) heldActionContext = handoff;
      // Resend due queued reports only when this call did no held-call work (hook time limits).
      else await flushHoldOutbox(heldContext, 1, 2_000).catch(() => undefined);
    }

    if (shouldSkipAutoLog(event)) {
      debug('[marrow-hook] recorded read-only result locally; skipped network event');
      return;
    }

    const action = deriveAction(event);
    if (!action) return;

    const apiKey = resolvedEnv.apiKey || '';
    if (!apiKey) {
      debug(`[marrow-hook] skipped missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
      return;
    }

    const baseUrl = validateBaseUrl(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
    const { success } = outcome;

    const toolName = normalizeToolName(getString(event.tool_name) || 'tool');
    const eventType = toolName === 'bash'
      ? success ? 'command_completed' : 'command_failed'
      : success ? 'tool_completed' : 'tool_failed';
    const lifecycleCorrelation = stableToolCorrelation({ ...event, session_id: sessionId });
    // Spool only: PostToolUse runs on every tool call, so it must add ~no latency.
    // cli.ts launches a detached background nudge that delivers the spooled event.
    // With the nudge disabled (MARROW_HOOK_BACKGROUND_NUDGE=false) keep bounded inline delivery.
    const deferred = backgroundNudgeEnabled();
    const receipt = await recordLifecycleEvent({
      apiKey,
      baseUrl,
      deferDelivery: deferred,
      event: {
        event_id: `posttool-${lifecycleCorrelation}`,
        event_type: eventType,
        ...clientReportedHookLifecycleIdentity(identity),
        session_id: sessionId,
        workflow_id: stableSessionWorkflowId(sessionId, event.generation_id || event.tool_use_id || event.task_id),
        correlation_id: lifecycleCorrelation,
        action,
        target: classified.target,
        surfaces: classified.surfaces,
        risk_level: classified.risk,
        success,
        outcome_state: 'pending',
      },
    });
    spooledLifecycleEvent = deferred && receipt.queued;

    if (identity.harness !== 'grok' && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
      const capture = modelUsageCaptureContextFromEnv();
      const usage = extractModelUsageFromUnknown(event.tool_response, capture)
        || extractModelUsageFromUnknown(event.tool_result, capture)
        || extractModelUsageFromUnknown(event.tool_output, capture)
        || extractModelUsageFromUnknown(event, capture);
      if (usage) {
        await marrowModelUsage(apiKey, baseUrl, {
          ...usage,
          source: 'mcp_post_tool_use',
          marrow_intervention: 'passive_model_usage_capture',
          success,
          action_type: classified.type || 'tool',
        }, sessionId, agentId).catch(() => undefined);
      }
    }

  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    debug(`[marrow-hook] ${message}`);
  } finally {
    if (identity.harness === 'gemini') process.stdout.write('{}');
    else emitHeldActionContext(identity, lastHookEventName);
  }
}

/**
 * Claude Code PermissionRequest, pass-through: notes that the host is about to
 * show its own permission dialog for an asked (held) call. It never prints a
 * decision, so it cannot answer the dialog; setup installs it with async: true.
 * PermissionRequest input has no tool_use_id, so the call is matched on the
 * session, the tool name and the tool input.
 */
export async function runPermissionRequestHookCommand(input?: unknown): Promise<void> {
  try {
    if (process.env.MARROW_AUTO_HOOK === 'false') return;
    try { if (!readLocalControlState().enabled) return; } catch { return; }
    const identity = resolveNativeHookIdentity(process.argv[2]);
    let event: HookEvent;
    if (input === undefined) {
      const raw = (await readStdin()).trim();
      if (!raw || raw.length > 4 * 1024 * 1024) return;
      event = normalizeHookEventPayload(JSON.parse(raw)) as HookEvent;
    } else {
      event = normalizeHookEventPayload(input) as HookEvent;
    }
    if (event.hook_event_name !== undefined && event.hook_event_name !== 'PermissionRequest') return;
    if (!getString(event.tool_name)) return;
    const context = holdContextFor(identity, event);
    if (!context || context.host !== 'claude-code') return;
    noteDialogShown(context, stableToolCorrelation({ ...event, session_id: context.sessionId }));
  } catch {
    debug('[marrow-hook] permission request marker was not recorded');
  }
}

export function installPermissionRequestHook(startDir: string = process.cwd()): HookInstallResult {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  const settingsPath = findHookSettingsPath(startDir);
  const settings = readHookSettingsForInstall(startDir);
  const hooks = asRecord(settings.hooks) || {};
  // async: the marker never delays or answers the dialog. PostToolBatch runs
  // the result hook in the background to settle declines.
  const permission = reconcileMarrowCommandHook(settings, 'PermissionRequest', 'permission-request-hook', PERMISSION_REQUEST_HOOK_COMMAND, AUTO_HOOK_MATCHER, { async: true });
  const batch = reconcileMarrowCommandHook(settings, 'PostToolBatch', 'hook', AUTO_HOOK_COMMAND, undefined, { async: true });
  settings.hooks = {
    ...hooks,
    PermissionRequest: permission.entries,
    PostToolBatch: batch.entries,
  };
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath, installed: permission.changed || batch.changed };
}
