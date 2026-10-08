import { marrowAgentRuntime, marrowEnforcement } from './index';
import { type HoldPlan } from './host-approval';
import { MARROW_OUTAGE_WARNING } from './hook-contract';
/** A protected action with no Marrow key anywhere this machine keeps one (MARROW_API_KEY, ~/.marrow/env.local or ~/.marrow/env, owner-only). */
export declare const NO_KEY_TEXT = "Marrow can't find your key: run `npx @getmarrow/install` once in this machine's terminal.";
export { MARROW_OUTAGE_WARNING };
export declare const MAX_PRE_ACTION_INPUT_BYTES: number;
export declare const PRE_ACTION_CONTROL_TIMEOUT_MS = 8000;
export declare class PreActionControlTimeoutError extends Error {
    readonly code = "request_timeout";
    constructor();
}
/**
 * A timeout (the hook's own budget, or a request that did not answer in time):
 * Marrow is slow, not known to be down. It is never treated as an outage.
 */
export declare function isMarrowControlTimeout(error: unknown): boolean;
export declare function isMarrowControlOutage(error: unknown): boolean;
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
export declare const HOLD_OWNER_DENIAL = "Marrow is holding this action for approval. Retry it after approval.";
/** Marrow did not answer within the hook's time limit: an action that can be held stays held. */
export declare const HELD_SLOW_TEXT = "Marrow did not answer in time, so this action is held. Retry it in a moment.";
/** The only denial @getmarrow/install's Grok guard passes through (any other output blocks with a launch failure). */
export declare const GROK_FIXED_DENIAL = "Marrow blocked this protected action.";
/**
 * The hook's answer for an ordinary held action, per host. A Claude Code "ask"
 * reason is shown to the user only; a Cursor user_message is shown only in the
 * client; neither ever reaches the agent with an approval code.
 */
export declare function heldActionHookOutput(harness: HookHarness, plan: HoldPlan, code?: string | null): Record<string, unknown> | null;
/**
 * The hook's answer when the host's own approval step decides (owner rule):
 * neutral, never an explicit allow, so the host's normal permission flow runs.
 * Codex: no permissionDecision (only context for the agent); Cline: not
 * cancelled; Windsurf: exit 0 (emitted by the caller). Any other host has no
 * neutral answer here and never gets a pass plan.
 */
export declare function passHookOutput(harness: HookHarness, contextText: string): Record<string, unknown> | null;
/** The hook's answer when a waited hold was approved and the same action is retried. */
export declare function approvedHoldHookOutput(harness: HookHarness, contextText: string): Record<string, unknown> | null;
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
export declare function isMarrowOutage(result: PreActionControlResult): boolean;
export declare function controlFailureKind(error: unknown): PreActionControlResult['failure'];
export declare function controlRejectionMessage(error: unknown, agentId?: string): string;
export type OwnerApprovalPrompt = {
    available: boolean;
    unavailableReason: string;
    headless?: boolean;
};
/**
 * Whether a PreToolUse "ask" from this hook reaches a person who can approve.
 * Only Claude Code asks; the generic entrypoint counts as Claude Code only when
 * Claude Code itself spawned the hook (CLAUDE_CODE_CHILD_SESSION, v2.1.172+).
 */
export declare function ownerApprovalPrompt(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', event: Pick<PreToolUseEvent, 'permission_mode' | 'scratchpad_dir'>, env?: NodeJS.ProcessEnv): OwnerApprovalPrompt;
type GateVerdict = {
    kind: 'block' | 'review' | 'arbitration_review' | 'denied';
    reason: string;
};
/**
 * True only for the runtime's positive advisory contract. On a plan without
 * production_action_enforcement the backend gate (agent-runtime.service.ts,
 * the hardGateEnforcement branch) carries enforced:false with
 * enforcement_decision:'advisory', and gate_required, owner_approval_required
 * and gate_receipt.required are false; the slim shape the MCP client receives
 * carries risk_gate_enforced:false instead. Missing, malformed or conflicting
 * enforcement fields are never advisory, so a protected action fails closed.
 */
export declare function runtimeGateAdvisory(runtime: PreActionControlResult['runtime']): boolean;
/** Every gate is enforced unless the runtime positively declares it advisory. */
export declare function runtimeGateEnforced(runtime: PreActionControlResult['runtime']): boolean;
/** A warning for a non-allow gate the runtime does not enforce on this plan. */
export declare function advisoryGateNotice(runtime: PreActionControlResult['runtime']): string | null;
export declare function runtimeGateVerdict(runtime: PreActionControlResult['runtime']): GateVerdict | null;
export declare function gateDecisionMessage(verdict: GateVerdict, ask: boolean, prompt?: OwnerApprovalPrompt): string;
export declare function localControlAllowOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client'): Record<string, unknown> | null;
export declare function localLoopGuardDenyOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', reason: string): Record<string, unknown> | null;
export declare function classifyTool(event: PreToolUseEvent): {
    action: string;
    target: string;
    type: string;
    role: string;
    surfaces: string[];
    risk: 'low' | 'medium' | 'high';
    protected: boolean;
    readOnly: boolean;
};
export declare function cursorPreActionHookOutput(result: PreActionControlResult): Record<string, unknown>;
export declare function clinePreActionHookOutput(result: PreActionControlResult): Record<string, unknown>;
export declare function windsurfPreActionDecision(result: PreActionControlResult): {
    exitCode: 0 | 2;
    stderr: string;
};
export declare function geminiPreActionHookOutput(result: PreActionControlResult): {
    decision: 'allow' | 'deny';
    reason?: string;
};
export declare function grokPreActionHookOutput(result: PreActionControlResult): {
    decision: 'allow' | 'deny';
    reason?: string;
};
export declare function preActionHookOutput(result: PreActionControlResult, harness?: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', prompt?: OwnerApprovalPrompt, 
/** An older service without host approvals: Claude Code asks in its dialog exactly as 3.9.98 did. */
legacyServiceAsk?: boolean): Record<string, unknown>;
type HeldDecision = {
    decisionId: string | null;
    gateReceiptId: string | null;
};
export declare const DENIED_DECISION_CLOSE_TIMEOUT_MS = 2500;
/**
 * Records a decision the hook denied as a failed outcome, so it carries real
 * outcome data instead of being swept to a NULL outcome later. Never called for
 * an "ask": an approved prompt runs the action and its outcome is still open.
 */
export declare function closeDeniedDecision(apiKey: string, baseUrl: string, held: HeldDecision, reason: string, sessionId: string, agentId?: string): Promise<boolean>;
export declare function localApprovalCategories(action: {
    action: string;
    type: string;
    surfaces: string[];
}): string[];
export declare function installPreActionHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-pre-action.d.ts.map