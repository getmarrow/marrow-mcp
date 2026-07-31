import { marrowAgentRuntime, marrowEnforcement, marrowThink, validateBaseUrl } from './index';
import { resolveMarrowEnv } from './env';
import { recordLifecycleEvent } from './lifecycle-spool';
import {
  findHookSettingsPath,
  nativeHookEvidence,
  NATIVE_HOOK_MATCHER,
  PRE_ACTION_HOOK_COMMAND,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
  stableSessionWorkflowId,
  stableToolCorrelation,
} from './hook-contract';

const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 3000;

export type PreToolUseEvent = {
  session_id?: string;
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
  type: string;
  role: string;
  surfaces: string[];
  risk: 'low' | 'medium' | 'high';
} {
  const tool = String(event.tool_name || 'tool').slice(0, 64);
  const input = JSON.stringify(event.tool_input || {}).toLowerCase();
  let type = 'process';
  if (/\b(?:deploy|release|publish|wrangler)\b/.test(input)) type = 'deploy';
  else if (/\b(?:merge|pull request|git push)\b/.test(input)) type = 'review';
  else if (/\b(?:migration|schema|database|d1)\b/.test(input)) type = 'migration';
  else if (/\b(?:secret|credential|token|key|permission)\b/.test(input)) type = 'audit';
  const surfaces = [
    /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) ? 'production' : '',
    /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
    /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
    /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
  ].filter(Boolean);
  const risk = surfaces.includes('production') || surfaces.includes('secrets') ? 'high' : 'medium';
  return {
    action: `classified ${tool} action: ${type} on ${surfaces.join(', ') || 'workspace'}`,
    type,
    role: ['deploy', 'review', 'migration', 'audit'].includes(type) ? type : 'general',
    surfaces: surfaces.length ? surfaces : ['workspace'],
    risk,
  };
}

export function preActionHookOutput(result: PreActionControlResult): Record<string, unknown> {
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
    ? 'ask'
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

function emitDecision(result: PreActionControlResult): void {
  process.stdout.write(JSON.stringify(preActionHookOutput(result)));
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
  let event = input;
  if (event === undefined) {
    try {
      const raw = (await readStdin()).trim();
      event = raw ? JSON.parse(raw) : {};
    } catch {
      process.stdout.write('{}');
      return;
    }
  }
  const source = asRecord(event) as PreToolUseEvent | null;
  if (!source?.tool_name) {
    process.stdout.write('{}');
    return;
  }
  const resolved = resolveMarrowEnv();
  if (!resolved.apiKey) {
    process.stdout.write('{}');
    return;
  }
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  const sessionId = resolved.sessionId || source.session_id;
  const agentId = resolved.agentId || undefined;
  const correlation = stableToolCorrelation({ ...source, session_id: sessionId });
  const classified = classifyTool(source);
  const lifecycle = recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_id: `pretool-${correlation}`,
      event_type: 'pre_action_checked',
      harness: 'claude-code',
      agent_id: agentId,
      session_id: sessionId,
      workflow_id: stableSessionWorkflowId(sessionId, source.tool_use_id),
      correlation_id: correlation,
      ...nativeHookEvidence('pre_action'),
      action: classified.action,
      risk_level: classified.risk,
      outcome_state: 'pending',
    },
  }).catch(() => null);
  const control = async (signal: AbortSignal): Promise<PreActionControlResult> => {
    const runtime = await marrowAgentRuntime(resolved.apiKey, baseUrl, {
      action: classified.action,
      type: classified.type,
      role: classified.role,
      surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    const decision = await marrowThink(resolved.apiKey, baseUrl, {
      action: classified.action,
      type: classified.type,
      source_kind: 'integration',
      source_meta: {
        harness: 'claude-code',
        correlation_id: correlation,
        gate_receipt_id: runtime.gate_receipt?.id || runtime.gate_receipt_id || null,
      },
    }, sessionId, agentId);
    const issued = await marrowEnforcement(resolved.apiKey, baseUrl, {
      operation: 'issue',
      action: classified.action,
      action_type: classified.type,
      target: correlation,
      correlation_id: correlation,
      harness: 'claude-code',
      decision_id: decision.decision_id,
      gate_receipt_id: runtime.gate_receipt?.id || runtime.gate_receipt_id || null,
      proof_requirements: runtime.proof_pack?.fields || [],
      surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    if (!issued.permit) return { runtime, permit: issued, protectedRisk: classified.risk === 'high', enforcementError: 'Marrow did not issue an action permit.' };
    const verified = await marrowEnforcement(resolved.apiKey, baseUrl, {
      operation: 'verify',
      permit: issued.permit,
      action: classified.action,
      action_type: classified.type,
      target: correlation,
      correlation_id: correlation,
      harness: 'claude-code',
    }, sessionId, agentId, signal);
    return { runtime, permit: { ...issued, ...verified, permit: undefined }, protectedRisk: classified.risk === 'high' };
  };
  const [result] = await Promise.all([withTimeout(control), lifecycle]);
  emitDecision(result || {
    runtime: null,
    permit: null,
    protectedRisk: classified.risk === 'high',
    enforcementError: 'Marrow governance timed out before this protected action. Retry instead of bypassing the gate.',
  });
}
