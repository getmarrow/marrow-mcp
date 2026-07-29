import { marrowAgentRuntime, validateBaseUrl } from './index';
import { resolveMarrowEnv } from './env';
import { recordLifecycleEvent } from './lifecycle-spool';
import {
  findHookSettingsPath,
  hasExactCommandHook,
  nativeHookEvidence,
  NATIVE_HOOK_MATCHER,
  PRE_ACTION_HOOK_COMMAND,
  readHookSettings,
  stableSessionWorkflowId,
  stableToolCorrelation,
} from './hook-contract';

const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 900;

export type PreToolUseEvent = {
  session_id?: string;
  hook_event_name?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
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

function classifyTool(event: PreToolUseEvent): {
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

export function preActionHookOutput(runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null): Record<string, unknown> {
  if (!runtime?.risk_gate) {
    return {};
  }
  const gate = runtime.risk_gate;
  const reason = runtime.exact_next_action
    || gate.reasons?.[0]?.message
    || 'Marrow requires additional proof or operator review before this action.';
  const permissionDecision = gate.allow === false || gate.decision === 'block'
    ? 'deny'
    : gate.decision === 'review_required'
    ? 'ask'
    : null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      ...(permissionDecision ? { permissionDecision, permissionDecisionReason: reason } : {}),
      ...(runtime.before_you_act ? { additionalContext: runtime.before_you_act } : {}),
    },
  };
}

function emitDecision(runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null): void {
  process.stdout.write(JSON.stringify(preActionHookOutput(runtime)));
}

async function withTimeout<T>(promise: Promise<T>): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<null>((resolve) => {
        timer = setTimeout(() => {
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
  const settings = readHookSettings(startDir);
  const hooks = asRecord(settings.hooks) || {};
  const preToolUse = Array.isArray(hooks.PreToolUse) ? [...hooks.PreToolUse] : [];
  const installed = hasExactCommandHook(settings, 'PreToolUse', PRE_ACTION_HOOK_COMMAND, NATIVE_HOOK_MATCHER);
  if (!installed) {
    preToolUse.push({
      matcher: NATIVE_HOOK_MATCHER,
      hooks: [{ type: 'command', command: PRE_ACTION_HOOK_COMMAND }],
    });
  }
  settings.hooks = { ...hooks, PreToolUse: preToolUse };
  fs.mkdirSync(require('node:path').dirname(path), { recursive: true });
  fs.writeFileSync(path, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath: path, installed: !installed };
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
  const runtime = marrowAgentRuntime(resolved.apiKey, baseUrl, {
    action: classified.action,
    type: classified.type,
    role: classified.role,
    surfaces: classified.surfaces,
  }, sessionId, agentId);
  const [result] = await Promise.all([withTimeout(runtime), lifecycle]);
  emitDecision(result);
}
