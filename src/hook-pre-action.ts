import { createHash } from 'node:crypto';
import { marrowAgentRuntime, marrowCommit, marrowEnforcement, marrowThink, validateBaseUrl } from './index';
import { MarrowRequestError } from './request-reliability';
import { recordLifecycleEvent } from './lifecycle-spool';
import { CONTROL_BYPASS_ACTION, readLocalControlState } from './control-state';
import { runtimeAuthorizationReceiptId } from './runtime-contract';
import { consultSessionLoopGuard, type LoopGuardOperation } from './session-loop-guard';
import {
  hookToolCommand,
  isMcpHookTool,
  isOfficialMarrowMcpEvent,
  isOfficialMarrowMcpTool,
  isProtectedShellMutation,
  isReadOnlyToolEvent,
  isSecretMaterialAccess,
  isShellGovernedTool,
  normalizeHookToolName,
  toolClassificationText,
} from './hook-tool-policy';
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

// Claude Code sends the whole tool input, and a Write of a long document grows
// further once JSON-escaped, so tens of kilobytes of markdown must still parse.
export const MAX_PRE_ACTION_INPUT_BYTES = 4 * 1024 * 1024;
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
  permission_mode?: string;
  scratchpad_dir?: string;
};

type PreActionControlResult = {
  runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null;
  permit: Awaited<ReturnType<typeof marrowEnforcement>> | null;
  protectedRisk: boolean;
  enforcementError?: string;
  failure?: 'credential_scope' | 'unavailable';
  outage?: boolean;
};

export function isMarrowOutage(result: PreActionControlResult): boolean {
  return result.outage === true;
}

const SAFE_FAILURE_CODE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/;
const SAFE_AGENT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
// The key is valid but not bound to the agent this hook acts as.
const AGENT_CREDENTIAL_SCOPE_CODES = new Set(['ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID', 'MARROW_AGENT_SCOPE_MISMATCH']);
// Marrow could not be used at all, as opposed to answering with a policy or credential decision.
const CONTROL_UNAVAILABLE_CODES = new Set(['tls_failure', 'invalid_response', 'edge_access_denied']);

export function controlFailureKind(error: unknown): PreActionControlResult['failure'] {
  if (!(error instanceof MarrowRequestError)) return undefined;
  if (error.status === 403 && AGENT_CREDENTIAL_SCOPE_CODES.has(error.backendCode || '')) return 'credential_scope';
  return CONTROL_UNAVAILABLE_CODES.has(error.code) ? 'unavailable' : undefined;
}

// Names a reached control failure by HTTP status and stable failure code only, so the
// denial is diagnosable without echoing private service text into the agent transcript.
export function controlRejectionMessage(error: unknown, agentId?: string): string {
  const detail: string[] = [];
  if (error instanceof MarrowRequestError) {
    if (typeof error.status === 'number' && Number.isInteger(error.status)) detail.push(`HTTP ${error.status}`);
    const code = [error.backendCode, error.code].find((value) => typeof value === 'string' && SAFE_FAILURE_CODE.test(value));
    if (code) detail.push(code);
  }
  const suffix = detail.length ? ` (${detail.join(' ')})` : '';
  const kind = controlFailureKind(error);
  if (kind === 'credential_scope') {
    const agent = agentId && SAFE_AGENT_ID.test(agentId)
      ? `agent "${agentId}"`
      : 'this hook\'s agent (no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set)';
    return `This Marrow API key is not authorized to obtain action permits for ${agent}${suffix}. Use the API key issued to that agent, or set MARROW_FLEET_AGENT_ID (or MARROW_AGENT_ID) to the agent this key belongs to, then retry.`;
  }
  if (kind === 'unavailable') {
    return `Marrow is unavailable, so this protected action was denied${suffix}. Retry when Marrow is reachable.`;
  }
  return `Marrow rejected this protected action${suffix}. Restore trusted governance before retrying.`;
}

// Claude Code permission modes in which a PreToolUse "ask" reaches a person.
// bypassPermissions disables prompts, dontAsk auto-denies anything that would
// prompt, and plan mode with bypass available runs edits without prompting.
// https://code.claude.com/docs/en/hooks#pretooluse-decision-control
// https://code.claude.com/docs/en/permission-modes
const OWNER_PROMPT_PERMISSION_MODES = new Set(['default', 'acceptEdits', 'auto']);

export type OwnerApprovalPrompt = { available: boolean; unavailableReason: string };

const NO_OWNER_PROMPT: OwnerApprovalPrompt = { available: false, unavailableReason: 'this agent host cannot prompt the owner' };

/**
 * Whether a PreToolUse "ask" from this hook reaches a person who can approve.
 * Only Claude Code asks; the generic entrypoint counts as Claude Code only when
 * Claude Code itself spawned the hook (CLAUDE_CODE_CHILD_SESSION, v2.1.172+).
 */
export function ownerApprovalPrompt(
  harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client',
  event: Pick<PreToolUseEvent, 'permission_mode' | 'scratchpad_dir'>,
  env: NodeJS.ProcessEnv = process.env,
): OwnerApprovalPrompt {
  const claudeCode = harness === 'claude-code' || (harness === 'mcp-client' && env.CLAUDE_CODE_CHILD_SESSION === '1');
  if (!claudeCode) {
    return harness === 'codex'
      ? { available: false, unavailableReason: 'Codex hooks cannot prompt the owner' }
      : NO_OWNER_PROMPT;
  }
  const mode = typeof event.permission_mode === 'string' && /^[A-Za-z]{1,32}$/.test(event.permission_mode) ? event.permission_mode : '';
  if (!OWNER_PROMPT_PERMISSION_MODES.has(mode)) {
    return { available: false, unavailableReason: `Claude Code permission mode ${mode || 'unknown'} cannot guarantee an owner prompt` };
  }
  // Before Claude Code v2.1.211 the auto-mode classifier could approve a Bash
  // command outside the sandbox without the prompt a hook asked for. The hook
  // input carries scratchpad_dir only from v2.1.257, so it proves a fixed version.
  if (mode === 'auto' && !(typeof event.scratchpad_dir === 'string' && event.scratchpad_dir.trim())) {
    return { available: false, unavailableReason: 'this auto-mode session does not prove a Claude Code version whose classifier honors hook prompts' };
  }
  return { available: true, unavailableReason: '' };
}

type GateVerdict = { kind: 'block' | 'review' | 'arbitration_review' | 'denied'; reason: string };

function boundedText(value: unknown, limit: number): string {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, limit);
}

function asOptionalRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

// Arbitration review is satisfied only by an authenticated-dashboard receipt,
// never by a host prompt, so any arbitration signal keeps the denial.
function arbitrationReview(runtime: NonNullable<PreActionControlResult['runtime']>): boolean {
  const completion = runtime.completion_contract;
  const approval = asOptionalRecord(completion?.owner_approval);
  return Boolean(runtime.arbitration)
    || completion?.arbitration_receipt_required === true
    || approval?.dashboard_receipt_required === true
    || (approval?.mode !== undefined && approval.mode !== 'ordinary_non_arbitrated');
}

/** The runtime, not the hook, decides whether its gate is enforced (Team+ hard enforcement). */
export function runtimeGateEnforced(runtime: PreActionControlResult['runtime']): boolean {
  const gate = runtime?.risk_gate as (NonNullable<PreActionControlResult['runtime']>['risk_gate'] & { permit_required?: unknown }) | undefined;
  return Boolean(gate && (gate.enforced === true || gate.gate_required === true || gate.permit_required === true));
}

function gateReason(runtime: NonNullable<PreActionControlResult['runtime']>): string {
  const why = boundedText(runtime.risk_gate.reasons?.[0]?.message, 240);
  const next = boundedText(runtime.exact_next_action, 240);
  return why && next && why !== next ? `${why}${/[.!?]$/.test(why) ? '' : '.'} Next: ${next}` : why || next;
}

/** A warning for a non-allow gate the runtime does not enforce on this plan. */
export function advisoryGateNotice(runtime: PreActionControlResult['runtime']): string | null {
  const gate = runtime?.risk_gate;
  if (!runtime || !gate || runtimeGateEnforced(runtime) || gate.decision === 'block') return null;
  const decision = String(gate.decision || '');
  if (gate.allow !== false && !['warn', 'review_required', 'owner_approval_required'].includes(decision)) return null;
  const reason = gateReason(runtime);
  return boundedText(`Marrow advisory: this plan does not enforce the pre-action gate, so the action is allowed. Gate decision: ${decision}.${reason ? ` Reason: ${reason}` : ''}`, 500);
}

export function runtimeGateVerdict(runtime: PreActionControlResult['runtime']): GateVerdict | null {
  const gate = runtime?.risk_gate;
  if (!runtime || !gate) return null;
  const decision = String(gate.decision || '');
  const review = decision === 'review_required' || decision === 'owner_approval_required';
  if (decision !== 'block' && !review && gate.allow !== false) return null;
  // An advisory gate warns; only an enforced gate (or any block) stops the action.
  if (decision !== 'block' && !runtimeGateEnforced(runtime)) return null;
  const reason = gateReason(runtime);
  if (decision === 'block') return { kind: 'block', reason };
  if (review) return { kind: arbitrationReview(runtime) ? 'arbitration_review' : 'review', reason };
  return { kind: 'denied', reason };
}

// Fixed wording leads so a long service reason can never truncate what happened.
export function gateDecisionMessage(verdict: GateVerdict, ask: boolean, prompt: OwnerApprovalPrompt = NO_OWNER_PROMPT): string {
  const headline = verdict.kind === 'block'
    ? 'Marrow blocked this action under the current policy.'
    : verdict.kind === 'arbitration_review'
    ? 'Marrow arbitration requires owner approval in the authenticated Marrow dashboard before this action.'
    : verdict.kind === 'denied'
    ? 'Marrow did not allow this action.'
    : ask
    ? 'Marrow requires owner review before this action. Approve only if you authorize this exact action.'
    : `Marrow requires owner review before this action, and no owner approval prompt is available (${prompt.unavailableReason}), so it was denied. Ask the owner to approve or run it.`;
  return boundedText(verdict.reason ? `${headline} Reason: ${verdict.reason}` : headline, 500);
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

async function readStdin(): Promise<{ raw: string; bytes: number }> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  process.stdin.resume();
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk);
    bytes += buffer.length;
    // Keep draining so the host never sees a broken pipe, but stop buffering past the bound.
    if (bytes <= MAX_PRE_ACTION_INPUT_BYTES) chunks.push(buffer);
  }
  return { raw: bytes > MAX_PRE_ACTION_INPUT_BYTES ? '' : Buffer.concat(chunks).toString('utf8'), bytes };
}

function localControlDisabled(): boolean {
  try {
    return readLocalControlState().enabled === false;
  } catch {
    return false;
  }
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
  // Editing and task tools are judged by their target; shell-like words in the
  // content they write or the subject they record are not actions.
  const shellGoverned = isShellGovernedTool(event);
  const command = shellGoverned ? hookToolCommand(event) : '';
  const input = toolClassificationText(event).toLowerCase();
  const readOnly = isReadOnlyToolEvent(event);
  const secretAccess = isSecretMaterialAccess(event);
  const protectedShellCommand = shellGoverned && isProtectedShellMutation(command);
  const infrastructureDeployment = /\b(?:kubectl|terraform|pulumi|helm)\b/.test(command.toLowerCase())
    && protectedShellCommand;
  let type = 'process';
  if (/\b(?:publish|unpublish|deprecate)\b/.test(input)) type = 'publish';
  else if (/\b(?:deploy|release|wrangler)\b/.test(input) || infrastructureDeployment) type = 'deploy';
  else if (/\b(?:merge|pull request|git push)\b/.test(input) || /\bgit\b[^\n;&|]{0,240}\bpush\b/.test(command.toLowerCase())) type = 'review';
  else if (/\b(?:migration|schema|database|d1)\b/.test(input)) type = 'migration';
  else if (secretAccess || /\b(?:secret|credential|token|key|permission)\b/.test(input)) type = 'audit';
  else if (/\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input)) type = 'financial';
  const surfaces = [
    /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) || infrastructureDeployment ? 'production' : '',
    /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
    /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
    secretAccess || /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
    /\b(?:migration|schema|database|d1)\b/.test(input) ? 'database' : '',
    /\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input) ? 'financial' : '',
  ].filter(Boolean);
  const protectedAction = !readOnly && (
    secretAccess
    || (shellGoverned && /\b(?:deploy|release|publish|git\s+push|git\s+merge|gh\s+pr\s+merge|migration|migrate|secret|credential|rotate|revoke|payment|refund|charge|invoice|production|prod)\b/.test(input))
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
  const verdict = runtimeGateVerdict(runtime);
  if (verdict) {
    const denial = gateDecisionMessage(verdict, false);
    return { permission: 'deny', user_message: denial, agent_message: denial };
  }
  if (protectedRisk && (!runtime || !permit?.verified)) {
    const denial = boundedText(result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.', 500);
    return {
      permission: 'deny',
      user_message: denial,
      agent_message: denial,
    };
  }
  const advisory = advisoryGateNotice(runtime);
  return advisory ? { permission: 'allow', user_message: advisory, agent_message: advisory } : { permission: 'allow' };
}

export function clinePreActionHookOutput(result: PreActionControlResult): Record<string, unknown> {
  if (isMarrowOutage(result)) return { cancel: false };
  const verdict = runtimeGateVerdict(result.runtime);
  if (verdict) {
    return {
      cancel: true,
      errorMessage: verdict.kind === 'review' || verdict.kind === 'arbitration_review'
        ? 'Marrow requires operator review before this protected action.'
        : 'Marrow blocked this protected action under the current policy.',
    };
  }
  if (result.protectedRisk && (!result.runtime || !result.permit?.verified)) {
    const credentialsUnavailable = /credentials are unavailable/i.test(String(result.enforcementError || ''));
    return {
      cancel: true,
      errorMessage: credentialsUnavailable
        ? 'Marrow credentials are unavailable for this protected action. Restore the configured agent key and retry.'
        : result.failure === 'credential_scope'
        ? 'This Marrow API key is not authorized to obtain action permits for this agent. Use the API key issued to this agent and retry.'
        : result.failure === 'unavailable'
        ? 'Marrow is unavailable, so this protected action was denied. Retry when Marrow is reachable.'
        : 'Marrow could not verify the required action permit. Restore trusted governance and retry.',
    };
  }
  return { cancel: false };
}

export function windsurfPreActionDecision(result: PreActionControlResult): { exitCode: 0 | 2; stderr: string } {
  if (isMarrowOutage(result)) return { exitCode: 0, stderr: `${MARROW_OUTAGE_WARNING}\n` };
  const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
  const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
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
  const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
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
  const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
  return denied
    ? { decision: 'deny', reason: 'Marrow blocked this protected action.' }
    : { decision: 'allow' };
}

export function preActionHookOutput(
  result: PreActionControlResult,
  harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client' = 'claude-code',
  prompt: OwnerApprovalPrompt = NO_OWNER_PROMPT,
): Record<string, unknown> {
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
  const advisory = advisoryGateNotice(runtime);
  const context = runtime?.before_you_act || permit?.permit_id || advisory ? {
    additionalContext: [
      advisory,
      runtime?.before_you_act,
      permit?.permit_id ? `Marrow action permit verified: ${permit.permit_id}. Evidence and outcome closure remain required.` : null,
    ].filter(Boolean).join('\n'),
  } : {};
  const verdict = runtimeGateVerdict(runtime);
  if (verdict) {
    // Only an ordinary review in a session that shows the owner a prompt asks;
    // block, arbitration and every host where no person would see it deny.
    const ask = verdict.kind === 'review' && prompt.available && harness !== 'codex';
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: ask ? 'ask' : 'deny',
        permissionDecisionReason: gateDecisionMessage(verdict, ask, prompt),
        ...context,
      },
    };
  }
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
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      ...context,
    },
  };
}

type EmittedDecision = { denied: boolean; reason: string };

function emitDecision(
  result: PreActionControlResult,
  harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client' = 'claude-code',
  prompt: OwnerApprovalPrompt = NO_OWNER_PROMPT,
): EmittedDecision {
  if (harness === 'windsurf') {
    const decision = windsurfPreActionDecision(result);
    process.exitCode = decision.exitCode;
    if (decision.stderr) process.stderr.write(decision.stderr);
    return { denied: decision.exitCode === 2, reason: decision.stderr.trim() };
  }
  if (result.outage) process.stderr.write(`${MARROW_OUTAGE_WARNING}\n`);
  const output = preActionHookOutput(result, harness, prompt);
  process.stdout.write(JSON.stringify(output));
  const specific = asRecord(output.hookSpecificOutput);
  if (specific?.permissionDecision === 'deny') return { denied: true, reason: String(specific.permissionDecisionReason || '') };
  if (output.permission === 'deny') return { denied: true, reason: String(output.agent_message || '') };
  if (output.cancel === true) return { denied: true, reason: String(output.errorMessage || '') };
  if (output.decision === 'deny') return { denied: true, reason: String(output.reason || '') };
  return { denied: false, reason: '' };
}

type HeldDecision = { decisionId: string | null; gateReceiptId: string | null };

// Closing is best effort: the denial already stands, and the hook must not hang.
export const DENIED_DECISION_CLOSE_TIMEOUT_MS = 2_500;

/**
 * Records a decision the hook denied as a failed outcome, so it carries real
 * outcome data instead of being swept to a NULL outcome later. Never called for
 * an "ask": an approved prompt runs the action and its outcome is still open.
 */
export async function closeDeniedDecision(
  apiKey: string,
  baseUrl: string,
  held: HeldDecision,
  reason: string,
  sessionId: string,
  agentId?: string,
): Promise<boolean> {
  if (!held.decisionId) return false;
  const outcome = boundedText(`denied by Marrow pre-action gate: ${reason || 'no reason was returned'}`, 500);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const committed = await Promise.race([
      marrowCommit(apiKey, baseUrl, {
        decision_id: held.decisionId,
        success: false,
        outcome,
        auto_gate: false,
        ...(held.gateReceiptId ? { gate_receipt_id: held.gateReceiptId } : {}),
      }, sessionId, agentId, controller.signal,
      `mcp-hook-deny:${createHash('sha256').update(`${held.decisionId}\n${outcome}`).digest('hex').slice(0, 40)}`),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(null);
        }, DENIED_DECISION_CLOSE_TIMEOUT_MS);
      }),
    ]);
    return committed?.committed === true;
  } catch {
    return false;
  } finally {
    if (timer) clearTimeout(timer);
  }
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
  let inputFailure: string | null = null;
  if (event === undefined) {
    try {
      const stdin = await readStdin();
      if (stdin.bytes > MAX_PRE_ACTION_INPUT_BYTES) {
        inputFailure = `Marrow did not check this action because its hook input is ${stdin.bytes} bytes, over the ${MAX_PRE_ACTION_INPUT_BYTES}-byte pre-action limit, so it was denied. Split it into smaller tool calls and retry.`;
      } else {
        const raw = stdin.raw.trim();
        event = raw ? normalizeHookEventPayload(JSON.parse(raw)) : {};
      }
    } catch {
      inputFailure = 'Marrow rejected malformed pre-action input.';
    }
  }
  const source = inputFailure ? null : asRecord(normalizeHookEventPayload(event)) as PreToolUseEvent | null;
  if (!inputFailure && !source?.tool_name) inputFailure = 'Marrow could not classify this mutation-capable tool request.';
  if (inputFailure || !source) {
    // Owner-disabled local control allows every action, including input Marrow cannot read.
    if (localControlDisabled()) {
      const allow = localControlAllowOutput(identity.harness);
      if (allow === null) process.exitCode = 0;
      else process.stdout.write(JSON.stringify(allow));
      return;
    }
    emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: inputFailure || 'Marrow could not classify this mutation-capable tool request.' }, identity.harness);
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
  // The decision and gate receipt this control path holds, so a denial can close them.
  const held: HeldDecision = { decisionId: null, gateReceiptId: null };
  const control = async (signal: AbortSignal): Promise<PreActionControlResult> => {
    const runtime = await marrowAgentRuntime(resolved.apiKey, baseUrl, {
      action: classified.action,
      target: classified.target,
      type: classified.type,
      role: classified.role,
      surfaces: classified.surfaces,
      // Without a risk level the runtime may take its low-risk fast path, whose
      // non-durable fast_gate receipt can never back an action permit.
      ...(enforcementRequired ? { risk_level: classified.risk } : {}),
    }, sessionId, agentId, signal);
    const heldIds = [...new Set([runtime.decision_id, runtime.completion_contract?.decision_id, runtime.runtime_authorization?.decision_id]
      .filter((value): value is string => typeof value === 'string' && SAFE_DECISION_ID.test(value)))];
    held.decisionId = heldIds.length === 1 ? heldIds[0] : null;
    held.gateReceiptId = runtimeAuthorizationReceiptId(runtime) || null;
    const gate = runtime.risk_gate;
    if (gate?.decision === 'block') return { runtime, permit: null, protectedRisk: enforcementRequired };
    // Free and starter plans get an advisory gate (enforced:false) that warns
    // but never hard-stops, so no permit is demanded unless the runtime enforces.
    if (!runtimeGateEnforced(runtime)) return { runtime, permit: null, protectedRisk: false };
    if (runtimeGateVerdict(runtime)) {
      return { runtime, permit: null, protectedRisk: enforcementRequired };
    }
    // Only enforced actions need a decision and permit; creating them for every
    // unprotected tool call would record a decision per edit.
    if (!enforcementRequired) return { runtime, permit: null, protectedRisk: false };
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
        // Think rejects any source_meta key outside channel, client, agent_id, task_depth and
        // user_intent with HTTP 400. The gate receipt and correlation bind on the permit below.
        ...(identity.harness !== 'mcp-client' ? { source_meta: { client: identity.harness } } : {}),
      }, sessionId, agentId, signal);
      decisionId = SAFE_DECISION_ID.test(decision.decision_id) ? decision.decision_id : null;
      // The runtime receipt is not bound to a decision Think creates; closing with it is a scope mismatch.
      held.decisionId = decisionId;
      held.gateReceiptId = null;
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
      // Verify must declare the permit's protocol; issue defaults to version 1.
      protocol_version: issued.protocol_version === 2 ? 2 : 1,
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
          enforcementError: controlRejectionMessage(error, agentId),
          ...(controlFailureKind(error) ? { failure: controlFailureKind(error) } : {}),
        }
    )),
    lifecycle,
  ]);
  const emitted = emitDecision(result, identity.harness, ownerApprovalPrompt(identity.harness, source));
  if (emitted.denied && !result.outage) {
    await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
  }
}
