import { marrowAgentRuntime, marrowEnforcement, marrowThink, validateBaseUrl } from './index';
import { MarrowRequestError } from './request-reliability';
import { recordLifecycleEvent } from './lifecycle-spool';
import { CONTROL_BYPASS_ACTION, readLocalControlState } from './control-state';
import { runtimeAuthorizationReceiptId } from './runtime-contract';
import { consultSessionLoopGuard, type LoopGuardOperation } from './session-loop-guard';
import { hookToolCommand, isMcpHookTool, isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool, isProtectedShellMutation, isReadOnlyToolEvent, normalizeHookToolName } from './hook-tool-policy';
import {
  clientReportedHookLifecycleIdentity,
  findHookSettingsPath,
  NATIVE_HOOK_MATCHER,
  PRE_ACTION_HOOK_COMMAND,
  normalizeHookEventPayload,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
  resolveNativeHookIdentity,
  MARROW_OUTAGE_WARNING,
  stableSessionWorkflowId,
  stableToolCorrelation,
} from './hook-contract';
export { MARROW_OUTAGE_WARNING };

const MAX_INPUT_BYTES = 64 * 1024;
// Cold auth may already use 900ms plus a 1600ms in-flight grace before think
// and enforcement. Keep this above that budget so a slow store is not aborted
// and misread as an outage.
export const PRE_ACTION_CONTROL_TIMEOUT_MS = 8_000;
const CONTROL_OUTAGE_CODES = new Set([
  'request_timeout',
  'dns_unavailable',
  'connection_reset',
  'service_unavailable',
]);
const NETWORK_ERROR_CODES = new Set([
  'ENOTFOUND',
  'ECONNRESET',
  'ECONNREFUSED',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
]);

export class PreActionControlTimeoutError extends Error {
  readonly code = 'request_timeout';

  constructor() {
    super('Marrow control path timed out');
    this.name = 'PreActionControlTimeoutError';
  }
}

export function isMarrowControlOutage(error: unknown): boolean {
  if (error instanceof PreActionControlTimeoutError) return true;
  if (error instanceof MarrowRequestError) return CONTROL_OUTAGE_CODES.has(error.code);
  if (!error || typeof error !== 'object') return false;
  const named = error as { name?: unknown; code?: unknown; message?: unknown };
  if (named.name === 'AbortError' || named.name === 'TimeoutError') return true;
  if (typeof named.code === 'string' && NETWORK_ERROR_CODES.has(named.code)) return true;
  return error instanceof TypeError && /fetch|network|getaddrinfo/i.test(String(named.message || ''));
}

export type PreToolUseEvent = {
  session_id?: string;
  conversation_id?: string;
  generation_id?: string;
  task_id?: string;
  hook_event_name?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
};

type PreActionControlResult = {
  runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null;
  permit: Awaited<ReturnType<typeof marrowEnforcement>> | null;
  protectedRisk: boolean;
  enforcementError?: string;
  outage?: boolean;
};

export function isMarrowOutage(result: PreActionControlResult): boolean {
  return result.outage === true;
}

const SAFE_DECISION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;

export function localControlAllowOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client'): Record<string, unknown> | null {
  if (harness === 'windsurf') return null;
  if (harness === 'cursor') return { permission: 'allow' };
  if (harness === 'cline') return { cancel: false };
  if (harness === 'gemini' || harness === 'grok') return { decision: 'allow' };
  return {};
}

export function localLoopGuardDenyOutput(
  harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client',
  reason: string,
): Record<string, unknown> | null {
  const bounded = reason.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500);
  if (harness === 'windsurf') return null;
  if (harness === 'cursor') return { permission: 'deny', user_message: bounded, agent_message: bounded };
  if (harness === 'cline') return { cancel: true, errorMessage: bounded };
  if (harness === 'gemini' || harness === 'grok') return { decision: 'deny', reason: bounded };
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: bounded } };
}

function emitLoopGuardDenial(
  harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client',
  reason: string,
): void {
  if (harness === 'windsurf') {
    process.exitCode = 2;
    process.stderr.write(`${reason.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500)}\n`);
    return;
  }
  process.stdout.write(JSON.stringify(localLoopGuardDenyOutput(harness, reason)));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  process.stdin.resume();
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > MAX_INPUT_BYTES) throw new Error('pre-action hook input exceeds byte limit');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function classifyTool(event: PreToolUseEvent): {
  action: string;
  target: string;
  type: string;
  role: string;
  surfaces: string[];
  risk: 'low' | 'medium' | 'high';
  protected: boolean;
  readOnly: boolean;
} {
  const tool = String(event.tool_name || 'tool').slice(0, 64);
  const normalizedTool = normalizeHookToolName(tool);
  const command = hookToolCommand(event);
  const input = `${normalizedTool} ${command} ${JSON.stringify(event.tool_input || {})}`.toLowerCase();
  const readOnly = isReadOnlyToolEvent(event);
  const protectedShellCommand = isProtectedShellMutation(command);
  const infrastructureDeployment = /\b(?:kubectl|terraform|pulumi|helm)\b/.test(command.toLowerCase())
    && protectedShellCommand;
  let type = 'process';
  if (/\b(?:publish|unpublish|deprecate)\b/.test(input)) type = 'publish';
  else if (/\b(?:deploy|release|wrangler)\b/.test(input) || infrastructureDeployment) type = 'deploy';
  else if (/\b(?:merge|pull request|git push)\b/.test(input) || /\bgit\b[^\n;&|]{0,240}\bpush\b/.test(command.toLowerCase())) type = 'review';
  else if (/\b(?:migration|schema|database|d1)\b/.test(input)) type = 'migration';
  else if (/\b(?:secret|credential|token|key|permission)\b/.test(input)) type = 'audit';
  else if (/\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input)) type = 'financial';
  const surfaces = [
    /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) || infrastructureDeployment ? 'production' : '',
    /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
    /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
    /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
    /\b(?:migration|schema|database|d1)\b/.test(input) ? 'database' : '',
    /\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input) ? 'financial' : '',
  ].filter(Boolean);
  const protectedAction = !readOnly && (
    /\b(?:deploy|release|publish|git\s+push|git\s+merge|gh\s+pr\s+merge|migration|migrate|secret|credential|rotate|revoke|payment|refund|charge|invoice|production|prod)\b/.test(input)
    || protectedShellCommand
    || (isMcpHookTool(event.tool_name) && !isOfficialMarrowMcpTool(event.tool_name))
    || (['use_mcp_tool', 'use_tool'].includes(normalizedTool) && !isOfficialMarrowMcpEvent(event))
  );
  const risk = readOnly ? 'low' : protectedAction ? 'high' : 'medium';
  const target = surfaces.includes('npm') ? `npm:${type}`
    : surfaces.includes('github') ? `github:${type}`
    : surfaces.includes('production') ? `production:${type}`
    : surfaces.includes('database') ? `database:${type}`
    : surfaces.includes('financial') ? `financial:${type}`
    : surfaces.includes('secrets') ? `secrets:${type}`
    : `workspace:${type}`;
  return {
    action: `classified ${tool} action: ${type} on ${surfaces.join(', ') || 'workspace'}`,
    target,
    type,
    role: type === 'publish' ? 'deploy' : ['deploy', 'review', 'migration', 'audit'].includes(type) ? type : 'general',
    surfaces: surfaces.length ? surfaces : ['workspace'],
    risk,
    protected: protectedAction,
    readOnly,
  };
}

export function cursorPreActionHookOutput(result: PreActionControlResult): Record<string, unknown> {
  if (isMarrowOutage(result)) {
    return { permission: 'allow', user_message: MARROW_OUTAGE_WARNING, agent_message: MARROW_OUTAGE_WARNING };
  }
  const { runtime, permit, protectedRisk } = result;
  const message = (value: unknown): string => String(value || 'Marrow denied this action.')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);
  if (protectedRisk && (!runtime || !permit?.verified)) {
    const denial = message(result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.');
    return {
      permission: 'deny',
      user_message: denial,
      agent_message: denial,
    };
  }
  const gate = runtime?.risk_gate;
  if (!gate) return { permission: 'allow' };
  const reason = runtime?.exact_next_action
    || gate.reasons?.[0]?.message
    || 'Marrow requires additional proof or operator review before this action.';
  if (gate.decision === 'review_required' || gate.decision === 'block' || gate.allow === false) {
    const denial = message(reason);
    return { permission: 'deny', user_message: denial, agent_message: denial };
  }
  return { permission: 'allow' };
}

export function clinePreActionHookOutput(result: PreActionControlResult): Record<string, unknown> {
  if (isMarrowOutage(result)) return { cancel: false };
  if (result.protectedRisk && (!result.runtime || !result.permit?.verified)) {
    const credentialsUnavailable = /credentials are unavailable/i.test(String(result.enforcementError || ''));
    return {
      cancel: true,
      errorMessage: credentialsUnavailable
        ? 'Marrow credentials are unavailable for this protected action. Restore the configured agent key and retry.'
        : 'Marrow could not verify the required action permit. Restore trusted governance and retry.',
    };
  }
  const gate = result.runtime?.risk_gate;
  if (!gate) return { cancel: false };
  if (gate.decision === 'review_required' || gate.decision === 'block' || gate.allow === false) {
    return {
      cancel: true,
      errorMessage: gate.decision === 'review_required'
        ? 'Marrow requires operator review before this protected action.'
        : 'Marrow blocked this protected action under the current policy.',
    };
  }
  return { cancel: false };
}

export function windsurfPreActionDecision(result: PreActionControlResult): { exitCode: 0 | 2; stderr: string } {
  if (isMarrowOutage(result)) return { exitCode: 0, stderr: `${MARROW_OUTAGE_WARNING}\n` };
  const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
  const gate = result.runtime?.risk_gate;
  const denied = unavailable
    || gate?.decision === 'review_required'
    || gate?.decision === 'block'
    || gate?.allow === false;
  return denied
    ? {
      exitCode: 2,
      stderr: 'Marrow blocked this action because required governance approval or proof is unavailable.\n',
    }
    : { exitCode: 0, stderr: '' };
}

export function geminiPreActionHookOutput(result: PreActionControlResult): { decision: 'allow' | 'deny'; reason?: string } {
  if (isMarrowOutage(result)) return { decision: 'allow' };
  const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
  const gate = result.runtime?.risk_gate;
  const denied = unavailable
    || gate?.decision === 'review_required'
    || gate?.decision === 'block'
    || gate?.allow === false;
  return denied
    ? {
      decision: 'deny',
      reason: 'Marrow blocked this action because required governance approval or proof is unavailable.',
    }
    : { decision: 'allow' };
}

export function grokPreActionHookOutput(result: PreActionControlResult): { decision: 'allow' | 'deny'; reason?: string } {
  if (isMarrowOutage(result)) return { decision: 'allow' };
  const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
  const gate = result.runtime?.risk_gate;
  const denied = unavailable
    || gate?.decision === 'review_required'
    || gate?.decision === 'block'
    || gate?.allow === false;
  return denied
    ? { decision: 'deny', reason: 'Marrow blocked this protected action.' }
    : { decision: 'allow' };
}

export function preActionHookOutput(result: PreActionControlResult, harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client' = 'claude-code'): Record<string, unknown> {
  if (harness === 'cursor') return cursorPreActionHookOutput(result);
  if (harness === 'cline') return clinePreActionHookOutput(result);
  if (harness === 'gemini') return geminiPreActionHookOutput(result);
  if (harness === 'grok') return grokPreActionHookOutput(result);
  if (isMarrowOutage(result)) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext: MARROW_OUTAGE_WARNING,
      },
    };
  }
  const { runtime, permit, protectedRisk } = result;
  if (protectedRisk && (!runtime || !permit?.verified)) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.',
      },
    };
  }
  if (!runtime?.risk_gate) {
    return {};
  }
  const gate = runtime.risk_gate;
  const reason = runtime.exact_next_action
    || gate.reasons?.[0]?.message
    || 'Marrow requires additional proof or operator review before this action.';
  const permissionDecision = gate.decision === 'review_required'
    ? harness === 'codex' ? 'deny' : 'ask'
    : gate.decision === 'block' || gate.allow === false
    ? 'deny'
    : null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      ...(permissionDecision ? { permissionDecision, permissionDecisionReason: reason } : {}),
      ...(runtime.before_you_act || permit?.permit_id ? {
        additionalContext: [
          runtime.before_you_act,
          permit?.permit_id ? `Marrow action permit verified: ${permit.permit_id}. Evidence and outcome closure remain required.` : null,
        ].filter(Boolean).join('\n'),
      } : {}),
    },
  };
}

function emitDecision(result: PreActionControlResult, harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client' = 'claude-code'): void {
  if (harness === 'windsurf') {
    const decision = windsurfPreActionDecision(result);
    process.exitCode = decision.exitCode;
    if (decision.stderr) process.stderr.write(decision.stderr);
    return;
  }
  if (result.outage) process.stderr.write(`${MARROW_OUTAGE_WARNING}\n`);
  process.stdout.write(JSON.stringify(preActionHookOutput(result, harness)));
}

async function withTimeout<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation(controller.signal),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new PreActionControlTimeoutError());
        }, PRE_ACTION_CONTROL_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function installPreActionHook(startDir = process.cwd()): { settingsPath: string; installed: boolean } {
  const fs = require('node:fs') as typeof import('node:fs');
  const path = findHookSettingsPath(startDir);
  const settings = readHookSettingsForInstall(startDir);
  const hooks = asRecord(settings.hooks) || {};
  const reconciled = reconcileMarrowCommandHook(
    settings,
    'PreToolUse',
    'pre-action-hook',
    PRE_ACTION_HOOK_COMMAND,
    NATIVE_HOOK_MATCHER,
  );
  settings.hooks = { ...hooks, PreToolUse: reconciled.entries };
  fs.mkdirSync(require('node:path').dirname(path), { recursive: true });
  fs.writeFileSync(path, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath: path, installed: reconciled.changed };
}

export async function runPreActionHookCommand(input?: unknown): Promise<void> {
  if (process.env.MARROW_AUTO_HOOK === 'false') return;
  const identity = resolveNativeHookIdentity(process.argv[2]);
  let event = input;
  if (event === undefined) {
    try {
      const raw = (await readStdin()).trim();
      event = raw ? normalizeHookEventPayload(JSON.parse(raw)) : {};
    } catch {
      emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow rejected malformed or oversized pre-action input.' }, identity.harness);
      return;
    }
  }
  const source = asRecord(normalizeHookEventPayload(event)) as PreToolUseEvent | null;
  if (!source?.tool_name) {
    emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow could not classify this mutation-capable tool request.' }, identity.harness);
    return;
  }
  if (isOfficialMarrowMcpEvent(source)) {
    if (identity.harness === 'windsurf') {
      process.exitCode = 0;
      return;
    }
    process.stdout.write(JSON.stringify(
      identity.harness === 'cursor' ? { permission: 'allow' }
        : identity.harness === 'cline' ? { cancel: false }
        : ['gemini', 'grok'].includes(identity.harness) ? { decision: 'allow' }
        : {},
    ));
    return;
  }
  const classified = classifyTool(source);
  let localControl;
  try {
    localControl = readLocalControlState();
  } catch {
    emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow local control state is unsafe. Protected actions remain blocked until the owner repairs it.' }, identity.harness);
    return;
  }
  if (!localControl.enabled) {
    const resolved = identity.environment;
    const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id;
    const correlation = stableToolCorrelation({ ...source, session_id: sessionId });
    if (resolved.apiKey) {
      try {
        const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
        await recordLifecycleEvent({ apiKey: resolved.apiKey, baseUrl, event: {
          event_id: `owner-bypass-${correlation}`,
          event_type: 'pre_action_checked',
          ...clientReportedHookLifecycleIdentity(identity),
          session_id: sessionId,
          workflow_id: stableSessionWorkflowId(sessionId, source.generation_id || source.tool_use_id || source.task_id),
          correlation_id: correlation,
          action: CONTROL_BYPASS_ACTION,
          surfaces: classified.surfaces.slice(0, 6),
          risk_level: classified.risk,
          outcome_state: 'pending',
          intervention_disposition: 'overridden',
          action_changed: false,
        } }).catch(() => null);
      } catch { /* owner bypass is not trapped by telemetry configuration */ }
    }
    const allow = localControlAllowOutput(identity.harness);
    if (allow === null) process.exitCode = 0;
    else process.stdout.write(JSON.stringify(allow));
    return;
  }
  let resolved = identity.environment;
  const enforcementRequired = classified.protected || ['windsurf', 'gemini', 'grok'].includes(identity.harness);
  const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id
    || stableSessionWorkflowId(undefined, [identity.harness, process.cwd()]);
  const agentId = identity.agent_id;
  const correlation = stableToolCorrelation({ ...source, session_id: sessionId });
  const loopOperation: LoopGuardOperation = {
    sessionId,
    agentId,
    harness: identity.harness,
    toolName: source.tool_name,
    toolInput: source.tool_input,
    invocationId: source.tool_use_id,
    readOnly: classified.readOnly,
  };
  let loopDecision;
  try {
    loopDecision = consultSessionLoopGuard(loopOperation);
  } catch {
    emitLoopGuardDenial(identity.harness, 'Marrow local loop guard state is unsafe. Repair the private owner-only state before retrying.');
    return;
  }
  if (!loopDecision.allow) {
    if (resolved.apiKey) {
      try {
        const loopBaseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
        await recordLifecycleEvent({ apiKey: resolved.apiKey, baseUrl: loopBaseUrl, event: {
          event_id: `loop-block-${loopDecision.receipt.slice(4)}`,
          event_type: 'pre_action_checked',
          ...clientReportedHookLifecycleIdentity(identity),
          session_id: sessionId,
          workflow_id: stableSessionWorkflowId(sessionId),
          correlation_id: loopDecision.receipt,
          action: 'local session loop guard blocked an unchanged repeated operation',
          target: 'marrow:loop-guard',
          surfaces: ['workspace'],
          risk_level: 'low',
          outcome_state: 'pending',
          intervention_disposition: 'followed',
          action_changed: true,
        } }).catch(() => null);
      } catch { /* local denial remains authoritative when telemetry is unavailable */ }
    }
    emitLoopGuardDenial(identity.harness, loopDecision.reason || `Marrow local loop guard blocked this unchanged repeat. Receipt: ${loopDecision.receipt}.`);
    return;
  }
  if (classified.readOnly) {
    const allow = localControlAllowOutput(identity.harness);
    if (allow === null) process.exitCode = 0;
    else process.stdout.write(JSON.stringify(allow));
    return;
  }

  let baseUrl: string;
  try {
    baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  } catch {
    emitDecision({
      runtime: null,
      permit: null,
      protectedRisk: enforcementRequired,
      enforcementError: 'Marrow enforcement configuration is unavailable. Restore the trusted configuration before retrying this protected action.',
    }, identity.harness);
    return;
  }
  if (!resolved.apiKey) {
    emitDecision({
      runtime: null,
      permit: null,
      protectedRisk: enforcementRequired,
      enforcementError: 'Marrow credentials are unavailable for this protected action. Restore the configured agent key before retrying.',
    }, identity.harness);
    return;
  }
  const lifecycle = recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_id: `pretool-${correlation}`,
      event_type: 'pre_action_checked',
      ...clientReportedHookLifecycleIdentity(identity),
      session_id: sessionId,
      workflow_id: stableSessionWorkflowId(sessionId, source.generation_id || source.tool_use_id || source.task_id),
      correlation_id: correlation,
      action: classified.action,
      target: classified.target,
      surfaces: classified.surfaces,
      risk_level: classified.risk,
      outcome_state: 'pending',
    },
  }).catch(() => null);
  const control = async (signal: AbortSignal): Promise<PreActionControlResult> => {
    const runtime = await marrowAgentRuntime(resolved.apiKey, baseUrl, {
      action: classified.action,
      target: classified.target,
      type: classified.type,
      role: classified.role,
      surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    const gate = runtime.risk_gate;
    if (gate?.decision === 'block' || gate?.decision === 'review_required' || gate?.allow === false) {
      return { runtime, permit: null, protectedRisk: enforcementRequired };
    }
    const gateReceiptId = runtimeAuthorizationReceiptId(runtime);
    const runtimeIds = [runtime.decision_id, runtime.completion_contract?.decision_id, runtime.runtime_authorization?.decision_id]
      .filter((value): value is string => typeof value === 'string' && SAFE_DECISION_ID.test(value));
    const distinctRuntimeIds = [...new Set(runtimeIds)];
    const creationRequired = runtime.completion_contract?.decision_creation_required
      ?? runtime.runtime_authorization?.decision_creation_required;
    if (distinctRuntimeIds.length > 1) {
      return { runtime, permit: null, protectedRisk: enforcementRequired, enforcementError: 'Marrow runtime returned conflicting decision identifiers.' };
    }
    let decisionId = distinctRuntimeIds[0] || null;
    if (creationRequired === true) {
      const decision = await marrowThink(resolved.apiKey, baseUrl, {
        action: classified.action,
        target: classified.target,
        surfaces: classified.surfaces,
        type: classified.type,
        source_kind: 'integration',
        source_meta: {
          harness: identity.harness,
          correlation_id: correlation,
          gate_receipt_id: gateReceiptId,
        },
      }, sessionId, agentId, signal);
      decisionId = SAFE_DECISION_ID.test(decision.decision_id) ? decision.decision_id : null;
    }
    if (!decisionId) {
      return {
        runtime,
        permit: null,
        protectedRisk: enforcementRequired,
        ...(enforcementRequired ? { enforcementError: 'Marrow runtime did not provide a valid decision and did not authorize decision creation.' } : {}),
      };
    }
    const issued = await marrowEnforcement(resolved.apiKey, baseUrl, {
      operation: 'issue',
      action: classified.action,
      action_type: classified.type,
      target: classified.target,
      correlation_id: correlation,
      harness: identity.harness,
      decision_id: decisionId,
      gate_receipt_id: gateReceiptId,
      proof_requirements: runtime.proof_pack?.fields || [],
      surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    const issuedPermitId = typeof issued.permit_id === 'string' ? issued.permit_id.trim() : '';
    if (!issued.permit || !issuedPermitId) {
      return { runtime, permit: { ...issued, verified: false }, protectedRisk: enforcementRequired, enforcementError: 'Marrow did not issue a complete action permit.' };
    }
    const verified = await marrowEnforcement(resolved.apiKey, baseUrl, {
      operation: 'verify',
      permit: issued.permit,
      action: classified.action,
      action_type: classified.type,
      target: classified.target,
      surfaces: classified.surfaces,
      correlation_id: correlation,
      harness: identity.harness,
    }, sessionId, agentId, signal);
    const verifiedPermitId = typeof verified.permit_id === 'string' ? verified.permit_id.trim() : '';
    const verifiedExactly = verified.verified === true && verifiedPermitId === issuedPermitId;
    return {
      runtime,
      permit: { ...issued, ...verified, permit_id: issuedPermitId, permit: undefined, verified: verifiedExactly },
      protectedRisk: enforcementRequired,
      ...(verifiedExactly ? {} : { enforcementError: 'Marrow permit verification did not match the issued permit.' }),
    };
  };
  const [result] = await Promise.all([
    withTimeout(control).catch((error: unknown): PreActionControlResult => (
      isMarrowControlOutage(error)
        ? {
          runtime: null,
          permit: null,
          protectedRisk: enforcementRequired,
          outage: true,
          enforcementError: MARROW_OUTAGE_WARNING,
        }
        : {
          runtime: null,
          permit: null,
          protectedRisk: enforcementRequired,
          enforcementError: 'Marrow rejected this protected action. Restore trusted governance before retrying.',
        }
    )),
    lifecycle,
  ]);
  emitDecision(result, identity.harness);
}
