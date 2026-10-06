import { createHash, randomUUID } from 'node:crypto';
import { marrowAgentRuntime, marrowCommit, marrowEnforcement, marrowThink, validateBaseUrl } from './index';
import { MarrowRequestError } from './request-reliability';
import { recordLifecycleEvent } from './lifecycle-spool';
import { CONTROL_BYPASS_ACTION, readLocalControlState } from './control-state';
import { arbitrationApprovalGuidance, ordinaryApprovalGuidance, ownerReceiptRequired, runtimeAuthorizationReceiptId } from './runtime-contract';
import {
  approvalHostFor,
  arbitrationHoldGuidance,
  cursorSessionEvidence,
  finalizeOwnerRequest,
  HEADLESS_CLAUDE_ENTRYPOINTS as HEADLESS_ENTRYPOINTS,
  flushHoldOutbox,
  HELD_UNREACHABLE_TEXT,
  hostSessionIdFor,
  planArbitrationHold,
  planHeldAction,
  preToolDeadline,
  protectedAmong,
  remainingMs,
  rememberHold,
  rememberProtection,
  requestOwnerLink,
  resumeWaitingHold,
  typedReplyAvailable,
  typedReplyUserText,
  type HoldContext,
  type HoldPlan,
  type OwnerLinkOutcome,
} from './host-approval';
import type { HoldRecord } from './host-approval-state';
import { localInteractiveSession } from './host-session';
import { normalizedHookAction } from './normalized-action';
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

/**
 * A timeout (the hook's own budget, or a request that did not answer in time):
 * Marrow is slow, not known to be down. It is never treated as an outage.
 */
export function isMarrowControlTimeout(error: unknown): boolean {
  if (error instanceof PreActionControlTimeoutError) return true;
  if (error instanceof MarrowRequestError) return error.code === 'request_timeout';
  if (!error || typeof error !== 'object') return false;
  const named = error as { name?: unknown };
  return named.name === 'AbortError' || named.name === 'TimeoutError';
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

type HookHarness = 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client';

/** Fixed, privacy-preserving hold texts for hosts whose adapters accept only fixed strings. */
export const HOLD_OWNER_DENIAL = 'Marrow is holding this action for approval. Retry it after approval.';
/** Marrow did not answer within the hook's time limit: an action that can be held stays held. */
export const HELD_SLOW_TEXT = 'Marrow did not answer in time, so this action is held. Retry it in a moment.';
/** The only denial @getmarrow/install's Grok guard passes through (any other output blocks with a launch failure). */
export const GROK_FIXED_DENIAL = 'Marrow blocked this protected action.';

/**
 * The hook's answer for an ordinary held action, per host. A Claude Code "ask"
 * reason is shown to the user only; a Cursor user_message is shown only in the
 * client; neither ever reaches the agent with an approval code.
 */
export function heldActionHookOutput(
  harness: HookHarness,
  plan: HoldPlan,
  code: string | null = null,
): Record<string, unknown> | null {
  if (harness === 'windsurf') return null;
  if (plan.kind === 'ask') {
    if (harness === 'cursor') return { permission: 'ask', user_message: plan.promptText, agent_message: 'Marrow asked the user to approve this held action in Cursor.' };
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: plan.promptText } };
  }
  // The approval code goes only to a user-only channel: Cursor user_message,
  // Codex and Gemini CLI systemMessage. The agent's text never contains it.
  if (harness === 'cursor') {
    return {
      permission: 'deny',
      user_message: code ? typedReplyUserText(plan.userText, code) : plan.userText,
      agent_message: plan.agentText,
    };
  }
  if (harness === 'cline') return { cancel: true, errorMessage: plan.agentText };
  if (harness === 'gemini') {
    // Without a typed reply the Gemini adapter's fixed denial text is kept.
    return code
      ? { decision: 'deny', reason: plan.agentText, systemMessage: typedReplyUserText(plan.userText, code) }
      : { decision: 'deny', reason: 'Marrow blocked this action because required governance approval or proof is unavailable.' };
  }
  if (harness === 'grok') return { decision: 'deny', reason: GROK_FIXED_DENIAL };
  return {
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: plan.agentText },
    ...(harness === 'codex' && code ? { systemMessage: typedReplyUserText(plan.userText, code) } : {}),
  };
}

/** The hook's answer when a waited hold was approved and the same action is retried. */
export function approvedHoldHookOutput(harness: HookHarness, contextText: string): Record<string, unknown> | null {
  if (harness === 'windsurf') return null;
  if (harness === 'cursor') return { permission: 'allow' };
  if (harness === 'cline') return { cancel: false };
  if (harness === 'gemini' || harness === 'grok') return { decision: 'allow' };
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: contextText } };
}

function emitHookOutput(harness: HookHarness, output: Record<string, unknown> | null, deniedText?: string): void {
  if (harness === 'windsurf') {
    process.exitCode = deniedText ? 2 : 0;
    if (deniedText) process.stderr.write(`${deniedText}\n`);
    return;
  }
  if (output) process.stdout.write(JSON.stringify(output));
}

type PreActionControlResult = {
  runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null;
  permit: Awaited<ReturnType<typeof marrowEnforcement>> | null;
  protectedRisk: boolean;
  enforcementError?: string;
  failure?: 'credential_scope' | 'unavailable';
  outage?: boolean;
  /** Marrow did not answer inside the hook's time budget (slow, not down). */
  timedOut?: boolean;
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

export type OwnerApprovalPrompt = { available: boolean; unavailableReason: string; headless?: boolean };

/** Claude Code entrypoints with no one at a dialog (claude -p and the Agent SDKs); hooks inherit it. */
const HEADLESS_CLAUDE_ENTRYPOINTS = HEADLESS_ENTRYPOINTS;

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
  const entrypoint = typeof env.CLAUDE_CODE_ENTRYPOINT === 'string' ? env.CLAUDE_CODE_ENTRYPOINT : '';
  if (HEADLESS_CLAUDE_ENTRYPOINTS.has(entrypoint)) {
    return { available: false, unavailableReason: `${entrypoint}, no one sees a dialog`, headless: true };
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

// Arbitration review is satisfied only by the account owner's choice of a
// proposal (one-tap link), never by a host prompt, so any arbitration signal keeps the denial.
function arbitrationReview(runtime: NonNullable<PreActionControlResult['runtime']>): boolean {
  const completion = runtime.completion_contract;
  const approval = asOptionalRecord(completion?.owner_approval);
  return Boolean(runtime.arbitration)
    || completion?.arbitration_receipt_required === true
    || ownerReceiptRequired(approval)
    || (approval?.mode !== undefined && approval.mode !== 'ordinary_non_arbitrated');
}

/**
 * True only for the runtime's positive advisory contract. On a plan without
 * production_action_enforcement the backend gate (agent-runtime.service.ts,
 * the hardGateEnforcement branch) carries enforced:false with
 * enforcement_decision:'advisory', and gate_required, owner_approval_required
 * and gate_receipt.required are false; the slim shape the MCP client receives
 * carries risk_gate_enforced:false instead. Missing, malformed or conflicting
 * enforcement fields are never advisory, so a protected action fails closed.
 */
export function runtimeGateAdvisory(runtime: PreActionControlResult['runtime']): boolean {
  const gate = runtime?.risk_gate;
  if (!runtime || !gate) return false;
  const slim = runtime.response_mode === 'slim';
  const completion = runtime.completion_contract;
  const plan = runtime.plan_capability;
  return gate.enforced === false
    && gate.enforcement_decision === 'advisory'
    && String(gate.decision) !== 'block'
    // A slim response has no allow field; the client derives it from the decision.
    && (slim ? runtime.risk_gate_enforced === false : gate.allow === true && runtime.risk_gate_enforced == null)
    && (runtime.enforcement_decision == null || runtime.enforcement_decision === 'advisory')
    && (runtime.authorization_state === undefined || runtime.authorization_state === 'advisory_only')
    && runtime.hard_gate_obtained !== true
    && gate.gate_required !== true
    && gate.owner_approval_required !== true
    && runtime.gate_receipt?.required !== true
    && runtime.gate_receipt?.owner_approval_required !== true
    && completion?.gate_receipt_required !== true
    && completion?.owner_approval_required !== true
    && completion?.owner_approval == null
    && !arbitrationReview(runtime)
    && plan?.production_enforcement_entitled !== true
    && plan?.mode !== 'enforced';
}

/** Every gate is enforced unless the runtime positively declares it advisory. */
export function runtimeGateEnforced(runtime: PreActionControlResult['runtime']): boolean {
  return !runtimeGateAdvisory(runtime);
}

// Why the gate held or blocked the action. The runtime's exact_next_action is
// written for API clients (endpoints to call) and is never relayed by a hook.
function gateReason(runtime: NonNullable<PreActionControlResult['runtime']>): string {
  return boundedText(runtime.risk_gate.reasons?.[0]?.message, 240);
}

/** A warning for a non-allow gate the runtime does not enforce on this plan. */
export function advisoryGateNotice(runtime: PreActionControlResult['runtime']): string | null {
  const gate = runtime?.risk_gate;
  if (!runtime || !gate || !runtimeGateAdvisory(runtime)) return null;
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
  if (decision !== 'block' && runtimeGateAdvisory(runtime)) return null;
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
    ? 'Marrow is holding this action for arbitration review: the account owner picks and approves one proposal before it runs. Do not run it yet.'
    : verdict.kind === 'denied'
    ? 'Marrow did not allow this action.'
    : ask
    ? 'Marrow requires owner review before this action. Approve only if you authorize this exact action.'
    : `Marrow requires owner review before this action, and no owner approval prompt is available (${prompt.unavailableReason}), so it was denied. Tell the operator it is waiting for the account owner's approval.`;
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
  /** An older service without host approvals: Claude Code asks in its dialog exactly as 3.9.98 did. */
  legacyServiceAsk = false,
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
  if (verdict && legacyServiceAsk && verdict.kind === 'review' && prompt.available && harness !== 'codex') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: gateDecisionMessage(verdict, true, prompt),
        ...context,
      },
    };
  }
  if (verdict) {
    // An ordinary hold the server lets the host approve is answered by
    // heldActionHookOutput. Here every gate denies: block, arbitration, and a
    // review the server offered no chat or terminal approval for.
    const reason = verdict.kind === 'review' && prompt.available && !legacyServiceAsk
      ? { available: false, unavailableReason: 'this Marrow service did not offer a chat or terminal approval for this hold' }
      : prompt;
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: gateDecisionMessage(verdict, false, reason),
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
  legacyServiceAsk = false,
): EmittedDecision {
  if (harness === 'windsurf') {
    const decision = windsurfPreActionDecision(result);
    process.exitCode = decision.exitCode;
    if (decision.stderr) process.stderr.write(decision.stderr);
    return { denied: decision.exitCode === 2, reason: decision.stderr.trim() };
  }
  if (result.outage) process.stderr.write(`${MARROW_OUTAGE_WARNING}\n`);
  const output = preActionHookOutput(result, harness, prompt, legacyServiceAsk);
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

async function withTimeout<T>(operation: (signal: AbortSignal) => Promise<T>, timeoutMs = PRE_ACTION_CONTROL_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation(controller.signal),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new PreActionControlTimeoutError());
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * The gate's risk categories for this classified action, as the server
 * derives them from the same action, type and surfaces (risk-categories.ts).
 * Used only while Marrow cannot be reached, to keep owner-protected actions held.
 */
const LOCAL_CATEGORY_PATTERNS: Array<[string, RegExp]> = [
  ['production_deploy', /\b(deploy|release|rollback|rollout|production|prod)\b/i],
  ['source_control', /\b(merge|pull request|pr|github|main|master)\b/i],
  ['data_migration', /\b(migration|migrate|schema|database|sql|table|column)\b/i],
  ['secrets_security', /\b(secret|token|key|credential|rotate|revoke|security|waf|auth)\b/i],
  ['billing_access', /\b(billing|payment|invoice|subscription|plan|tier|permission|access)\b/i],
  ['destructive_action', /\b(?:delete|drop|truncate|purge|destroy|remove all|wipe)\b/i],
];

export function localApprovalCategories(action: { action: string; type: string; surfaces: string[] }): string[] {
  const text = `${action.action} ${action.type} ${action.surfaces.join(' ')}`;
  const categories = LOCAL_CATEGORY_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([category]) => category);
  // Broader than the server's package-publish check on purpose: it only keeps an action held.
  if (action.type.toLowerCase() === 'publish' || /\bpublish\b/i.test(text)) categories.unshift('package_publish');
  return categories;
}

/**
 * Nobody is in this run: headless Claude Code (sdk-*, its GitHub Action), a
 * scripted Codex or Gemini CLI run (`codex exec`, `gemini -p`), or a Cursor
 * background agent. Missing evidence is not unattended.
 */
function unattendedRun(ctx: HoldContext, claudePrompt: OwnerApprovalPrompt, cursorInteractive: boolean | null): boolean {
  if (ctx.host === 'claude-code') return claudePrompt.headless === true;
  if (ctx.host === 'codex' || ctx.host === 'gemini') return localInteractiveSession(ctx.host) === false;
  // Cursor: sessionStart reports local sessions; without it (cloud agents) or as a background agent, nobody is there.
  if (ctx.host === 'cursor') return cursorInteractive !== true;
  return false;
}

/** The hook's answer for a held action on any host (Windsurf answers through its exit code). */
function emitHeldPlan(harness: HookHarness, plan: HoldPlan, code: string | null = null): void {
  emitHookOutput(harness, heldActionHookOutput(harness, plan, code), plan.kind === 'deny' ? plan.agentText : undefined);
}

/** Work that does not decide the answer, done after it is written and inside the hook's budget. */
async function afterAnswer(ctx: HoldContext, work: { link?: HoldRecord | null }): Promise<void> {
  try {
    if (work.link) await requestOwnerLink(ctx, work.link, 0);
    if (remainingMs(ctx) > 800) await flushHoldOutbox(ctx, 2, Math.min(4_000, remainingMs(ctx) - 200));
  } catch { /* best effort: a later hook resends queued work */ }
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
  const holdContext: HoldContext = {
    apiKey: resolved.apiKey,
    baseUrl,
    sessionId,
    agentId,
    harness: identity.harness,
    host: approvalHostFor(identity.harness),
    hostSessionId: hostSessionIdFor([source.session_id, source.conversation_id, source.task_id], sessionId),
    // One total budget for this hook's answer and its follow-up work.
    deadlineAt: preToolDeadline(approvalHostFor(identity.harness)),
  };
  const toolUseId = typeof source.tool_use_id === 'string' ? source.tool_use_id : null;
  const generationId = typeof source.generation_id === 'string' ? source.generation_id : null;
  // Cursor runs an MCP call through preToolUse and then beforeMCPExecution, the
  // only event where Cursor shows its own approval prompt. In a local
  // interactive session preToolUse defers to it; cloud agents never run
  // beforeMCPExecution, so there preToolUse is the gate and holds quietly.
  const cursorMcpPreToolUse = holdContext.host === 'cursor' && String(source.hook_event_name || '').toLowerCase() === 'pretooluse'
    && /^MCP:/i.test(String(source.tool_name || ''));
  if (cursorMcpPreToolUse && cursorSessionEvidence(holdContext).interactive === true) {
    process.stdout.write(JSON.stringify({ permission: 'allow' }));
    return;
  }
  // The same action retried after a hold that waited for approval: its status decides.
  const dialogAvailable = holdContext.host === 'claude-code' && ownerApprovalPrompt(identity.harness, source).available;
  const waited = await resumeWaitingHold(holdContext, { correlation, toolUseId, generationId, dialogAvailable }).catch(() => null);
  if (waited?.kind === 'allow') {
    emitHookOutput(identity.harness, approvedHoldHookOutput(identity.harness, waited.contextText));
    await afterAnswer(holdContext, {});
    return;
  }
  if (waited?.kind === 'ask') {
    emitHookOutput(identity.harness, heldActionHookOutput(identity.harness, { kind: 'ask', promptText: waited.promptText }, null));
    await afterAnswer(holdContext, {});
    return;
  }
  if (waited?.kind === 'deny') {
    emitHeldPlan(identity.harness, { kind: 'deny', agentText: waited.agentText, userText: waited.userText, code: Boolean(waited.hold.code) }, waited.hold.code);
    await afterAnswer(holdContext, { link: waited.deferredLink ? waited.hold : null });
    return;
  }
  // One lifecycle record per attempt: a retried action is a new attempt, and a
  // hold names the record of the attempt that created it.
  const attempt = createHash('sha256').update(toolUseId || generationId || randomUUID()).digest('hex').slice(0, 12);
  const preActionEventId = `pretool-${correlation}-${attempt}`;
  const lifecycle = recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_id: preActionEventId,
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
  const normalizedAction = normalizedHookAction(source);
  // The decision and gate receipt this control path holds, so a denial can close them.
  const held: HeldDecision = { decisionId: null, gateReceiptId: null };
  const control = async (signal: AbortSignal): Promise<PreActionControlResult> => {
    const runtime = await marrowAgentRuntime(resolved.apiKey, baseUrl, {
      action: classified.action,
      target: classified.target,
      type: classified.type,
      role: classified.role,
      surfaces: classified.surfaces,
      // The exact command or tool call (secrets removed), so Marrow binds the
      // gate and any approval to this action, not to its coarse class.
      normalized_action: normalizedAction,
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
    // Free and starter plans get a positively advisory gate that warns but never
    // hard-stops; every other gate, including an unclear one, keeps enforcement.
    if (runtimeGateAdvisory(runtime)) return { runtime, permit: null, protectedRisk: false };
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
  // Codex and Cursor stop the hook at 5 s (and Codex then lets the call run):
  // the control path ends inside the hook's budget, leaving time to answer.
  const controlTimeoutMs = Math.max(1_000, Math.min(PRE_ACTION_CONTROL_TIMEOUT_MS, remainingMs(holdContext) - 400));
  const [result] = await Promise.all([
    withTimeout(control, controlTimeoutMs).catch((error: unknown): PreActionControlResult => (
      isMarrowControlTimeout(error)
        ? {
          runtime: null,
          permit: null,
          protectedRisk: enforcementRequired,
          timedOut: true,
          enforcementError: MARROW_OUTAGE_WARNING,
        }
        : isMarrowControlOutage(error)
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
  const claudePrompt = ownerApprovalPrompt(identity.harness, source);
  if (result.timedOut) {
    // Marrow is slow, not down: a self-imposed budget is never an outage. An
    // action that can be held stays held; routine actions keep flowing.
    const holdable = classified.protected || classified.risk === 'high'
      || protectedAmong(holdContext, localApprovalCategories(classified)).length > 0;
    if (holdable) {
      emitHeldPlan(identity.harness, { kind: 'deny', agentText: HELD_SLOW_TEXT, userText: HELD_SLOW_TEXT, code: false });
      return;
    }
    emitDecision({ ...result, outage: true, timedOut: false }, identity.harness, claudePrompt);
    return;
  }
  if (result.outage) {
    // Marrow cannot be reached. An action in a category the account owner
    // protects stays held on every host; everything else keeps the outage policy.
    const protectedNow = protectedAmong(holdContext, localApprovalCategories(classified));
    if (protectedNow.length) {
      emitHeldPlan(identity.harness, { kind: 'deny', agentText: HELD_UNREACHABLE_TEXT, userText: HELD_UNREACHABLE_TEXT, code: false });
      return;
    }
  }
  const verdict = result.outage ? null : runtimeGateVerdict(result.runtime);
  const guidance = verdict?.kind === 'review' ? ordinaryApprovalGuidance(result.runtime) : null;
  const arbitration = verdict?.kind === 'arbitration_review' ? arbitrationApprovalGuidance(result.runtime) : null;
  if (verdict && guidance && !guidance.hostApprovalSupported && holdContext.host === 'claude-code') {
    // An older service without host approvals: exactly as released 3.9.98 —
    // ask in Claude Code's dialog (the close stays unverified), never wait.
    const emitted = emitDecision(result, identity.harness, claudePrompt, true);
    if (emitted.denied) await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
    return;
  }
  if (verdict && (guidance || arbitration)) {
    // A hold: ask in the host's own prompt where it counts and is shown,
    // otherwise deny and wait for the approval. Never close the decision here;
    // that would spend the receipt the operator or owner is about to approve.
    const hookEvent = typeof source.hook_event_name === 'string' ? source.hook_event_name : 'PreToolUse';
    let plan: HoldPlan;
    if (guidance) {
      rememberProtection(holdContext, guidance);
      const cursor = holdContext.host === 'cursor' ? cursorSessionEvidence(holdContext) : null;
      plan = planHeldAction({
        unattended: cursorMcpPreToolUse || unattendedRun(holdContext, claudePrompt, cursor?.interactive ?? null),
        guidance,
        host: holdContext.host,
        hookEvent,
        // Only why it is held: the server's next-action text is written for API
        // clients and names endpoints, so it is never relayed.
        reason: boundedText(result.runtime?.risk_gate?.reasons?.[0]?.message, 240),
        claudePrompt,
        cursorInteractive: cursor?.interactive ?? null,
        typedReply: typedReplyAvailable(holdContext),
      });
    } else {
      plan = planArbitrationHold(arbitration!);
    }
    let code: string | null = null;
    let effective: HoldPlan = plan;
    let linkOutcome: OwnerLinkOutcome = { kind: 'none' };
    let laterLink: HoldRecord | null = null;
    try {
      // An unreadable approval state leaves nothing to wait on: the next attempt starts over.
      const hold = plan.kind === 'deny' && plan.retryFresh ? null : rememberHold(holdContext, {
        guidance: guidance || arbitrationHoldGuidance(arbitration!),
        correlation,
        toolUseId,
        generationId,
        toolName: String(source.tool_name || 'tool'),
        hookEvent,
        mode: plan.kind === 'ask' ? 'ask' : 'wait',
        withCode: plan.kind === 'deny' && plan.code,
        preActionEventId,
        action: { action: classified.action, target: classified.target, type: classified.type, surfaces: classified.surfaces },
        ...(plan.kind === 'deny' && plan.ownerLink ? { ownerLink: plan.ownerLink } : {}),
        ...(plan.kind === 'deny' && plan.dialogLater ? { dialogLater: true, laterPrompt: plan.laterPrompt } : {}),
        ...(plan.kind === 'deny' && plan.quiet ? { quiet: plan.quiet } : {}),
      });
      code = hold?.code ?? null;
      if (hold && plan.kind === 'deny' && plan.ownerLink === 'now') {
        linkOutcome = await requestOwnerLink(holdContext, hold);
        if (linkOutcome.kind === 'deferred') laterLink = hold;
      }
    } catch {
      // Without local state the answer could not be linked to this hold, so it is not asked for.
      if (plan.kind === 'ask') {
        const text = `Marrow is holding this action for approval (gate receipt ${guidance?.gateReceiptId || arbitration?.gateReceiptId}), so it did not run. Tell the operator it is waiting for approval; local approval state is unavailable on this machine.`;
        effective = { kind: 'deny', agentText: text, userText: text, code: false };
      }
    }
    effective = finalizeOwnerRequest(effective, linkOutcome);
    emitHeldPlan(identity.harness, effective, code);
    await afterAnswer(holdContext, { link: laterLink });
    return;
  }
  const emitted = emitDecision(result, identity.harness, claudePrompt);
  if (emitted.denied && !result.outage) {
    await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
  }
}
