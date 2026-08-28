import { marrowAgentRuntime, marrowEnforcement, marrowThink, validateBaseUrl } from './index';
import { recordLifecycleEvent } from './lifecycle-spool';
import { runtimeAuthorizationReceiptId } from './runtime-contract';
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
  stableSessionWorkflowId,
  stableToolCorrelation,
} from './hook-contract';

const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 3000;
export const GOVERNED_WRAPPER_COMMAND = 'npx @getmarrow/install run --agent <agent-id> -- -- <command>';

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
};

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
    || (normalizedTool === 'use_mcp_tool' && !isOfficialMarrowMcpEvent(event))
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

export function preActionHookOutput(result: PreActionControlResult, harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'grok' | 'mcp-client' = 'claude-code'): Record<string, unknown> {
  if (harness === 'cursor') return cursorPreActionHookOutput(result);
  if (harness === 'cline') return clinePreActionHookOutput(result);
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

function emitDecision(result: PreActionControlResult, harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'grok' | 'mcp-client' = 'claude-code'): void {
  process.stdout.write(JSON.stringify(preActionHookOutput(result, harness)));
}

export function grokPreActionAdvisoryOutput(): Record<string, unknown> {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: [
        'This Grok hook is client-self-reported advisory context, not certified control or an enforcement boundary.',
        `Run consequential commands through the governed wrapper: ${GOVERNED_WRAPPER_COMMAND}`,
      ].join('\n'),
    },
  };
}

async function withTimeout<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T | null> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation(controller.signal),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(null);
        }, RUNTIME_TIMEOUT_MS);
      }),
    ]);
  } catch {
    return null;
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
    process.stdout.write(JSON.stringify(
      identity.harness === 'cursor' ? { permission: 'allow' }
        : identity.harness === 'cline' ? { cancel: false }
        : {},
    ));
    return;
  }
  const classified = classifyTool(source);
  if (classified.readOnly) {
    process.stdout.write(JSON.stringify(
      identity.harness === 'cursor' ? { permission: 'allow' }
        : identity.harness === 'cline' ? { cancel: false }
        : {},
    ));
    return;
  }
  let resolved = identity.environment;
  const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id;
  const agentId = identity.agent_id;
  const correlation = stableToolCorrelation({ ...source, session_id: sessionId });

  if (identity.harness === 'grok') {
    if (resolved.apiKey) {
      try {
        const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
        await recordLifecycleEvent({
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
        }).catch(() => undefined);
      } catch {
        // Advisory output remains available when self-reported telemetry cannot be delivered.
      }
    }
    process.stdout.write(JSON.stringify(grokPreActionAdvisoryOutput()));
    return;
  }

  let baseUrl: string;
  try {
    baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  } catch {
    emitDecision({
      runtime: null,
      permit: null,
      protectedRisk: classified.protected,
      enforcementError: 'Marrow enforcement configuration is unavailable. Restore the trusted configuration before retrying this protected action.',
    }, identity.harness);
    return;
  }
  if (!resolved.apiKey) {
    emitDecision({
      runtime: null,
      permit: null,
      protectedRisk: classified.protected,
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
    const gateReceiptId = runtimeAuthorizationReceiptId(runtime);
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
    const issued = await marrowEnforcement(resolved.apiKey, baseUrl, {
      operation: 'issue',
      action: classified.action,
      action_type: classified.type,
      target: classified.target,
      correlation_id: correlation,
      harness: identity.harness,
      decision_id: decision.decision_id,
      gate_receipt_id: gateReceiptId,
      proof_requirements: runtime.proof_pack?.fields || [],
      surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    const issuedPermitId = typeof issued.permit_id === 'string' ? issued.permit_id.trim() : '';
    if (!issued.permit || !issuedPermitId) {
      return { runtime, permit: { ...issued, verified: false }, protectedRisk: classified.protected, enforcementError: 'Marrow did not issue a complete action permit.' };
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
      protectedRisk: classified.protected,
      ...(verifiedExactly ? {} : { enforcementError: 'Marrow permit verification did not match the issued permit.' }),
    };
  };
  const [result] = await Promise.all([withTimeout(control), lifecycle]);
  emitDecision(result || {
    runtime: null,
    permit: null,
    protectedRisk: classified.protected,
    enforcementError: 'Marrow governance timed out before this protected action. Retry instead of bypassing the gate.',
  }, identity.harness);
}
