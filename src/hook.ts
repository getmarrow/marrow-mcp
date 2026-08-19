import { marrowModelUsage, validateBaseUrl } from './index';
import { extractModelUsageFromUnknown } from './habit-loop-copy';
import { resolveMarrowEnv } from './env';
import { recordLifecycleEvent } from './lifecycle-spool';
import { classifyTool } from './hook-pre-action';
import { isOfficialMarrowMcpTool, isReadOnlyToolEvent, normalizeHookToolName } from './hook-tool-policy';
import {
  ACTION_RESULT_HOOK_COMMAND,
  findHookSettingsPath,
  nativeHookEvidence,
  NATIVE_HOOK_MATCHER,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
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
  session_id?: string;
  hook_event_name?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  tool_result?: unknown;
  error?: unknown;
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
  if (isOfficialMarrowMcpTool(toolName)) return null;
  return classifyTool(event).action;
}

function deriveToolSuccess(event: HookEvent): boolean {
  const response = event.tool_response ?? event.tool_result;
  const responseRecord = asRecord(response);
  const errorValue = responseRecord?.error;

  const failed = event.hook_event_name === 'PostToolUseFailure'
    || event.error != null
    || errorValue !== undefined && errorValue !== null
    || responseRecord?.is_error === true
    || responseRecord?.success === false
    || (typeof responseRecord?.exit_code === 'number' && responseRecord.exit_code !== 0)
    || /^(?:failed|error|blocked)$/i.test(String(responseRecord?.status || ''));

  return !failed;
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

export async function runHookCommand(): Promise<void> {
  if (process.env.MARROW_AUTO_HOOK === 'false') {
    process.exit(0);
    return;
  }

  try {
    const raw = (await readStdin()).trim();
    if (!raw) {
      process.exit(0);
      return;
    }

    let event: HookEvent;
    try {
      event = JSON.parse(raw) as HookEvent;
    } catch {
      debug('[marrow-hook] skipped invalid JSON');
      process.exit(0);
      return;
    }

    if (shouldSkipAutoLog(event)) {
      debug('[marrow-hook] skipped read-only tool');
      process.exit(0);
      return;
    }

    const classified = classifyTool(event);
    const action = deriveAction(event);
    if (!action) {
      process.exit(0);
      return;
    }

    const resolvedEnv = resolveMarrowEnv();
    const apiKey = resolvedEnv.apiKey || '';
    if (!apiKey) {
      debug(`[marrow-hook] skipped missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
      process.exit(0);
      return;
    }

    const baseUrl = validateBaseUrl(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
    const sessionId = resolvedEnv.sessionId || getString(event.session_id);
    const agentId = resolvedEnv.agentId || undefined;
    const success = deriveToolSuccess(event);

    const toolName = normalizeToolName(getString(event.tool_name) || 'tool');
    const eventType = toolName === 'bash'
      ? success ? 'command_completed' : 'command_failed'
      : success ? 'tool_completed' : 'tool_failed';
    const lifecycleCorrelation = stableToolCorrelation({ ...event, session_id: sessionId });
    await recordLifecycleEvent({
      apiKey,
      baseUrl,
      event: {
        event_id: `posttool-${lifecycleCorrelation}`,
        event_type: eventType,
        harness: 'claude-code',
        agent_id: agentId,
        session_id: sessionId,
        workflow_id: stableSessionWorkflowId(sessionId, event.tool_use_id),
        correlation_id: lifecycleCorrelation,
        ...nativeHookEvidence('action_result'),
        action,
        target: classified.target,
        surfaces: classified.surfaces,
        risk_level: classified.risk,
        success,
        outcome_state: 'pending',
      },
    });

    if (process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
      const usage = extractModelUsageFromUnknown(event.tool_response)
        || extractModelUsageFromUnknown(event.tool_result)
        || extractModelUsageFromUnknown(event);
      if (usage && (usage.input_tokens || usage.output_tokens || usage.total_tokens || usage.cached_tokens)) {
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
  }

  process.exit(0);
}
