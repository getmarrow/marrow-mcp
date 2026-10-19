import { marrowAgentRuntime, marrowEnforcement } from './index';
import { type HoldPlan } from './host-approval';
import { MARROW_OUTAGE_WARNING } from './hook-contract';
/** A protected action with no Marrow key anywhere this machine keeps one (MARROW_API_KEY, ~/.marrow/env.local or ~/.marrow/env, owner-only). */
export declare const NO_KEY_TEXT = "Marrow has no API key on this machine, so it held this action. To approve actions like this, create a key at getmarrow.ai/signup and add it: getmarrow.ai/docs#start-here (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins). Agent: do not retry this action.";
/** Seatbelt mode `claimed_no_key` (spec §1.1): account evidence on the machine but no usable key. Same text as src/seatbelt/hook.ts. */
export declare const CLAIMED_NO_KEY_TEXT = "Marrow is linked to an account but has no working key; owner: run `npx -y @getmarrow/install@latest doctor`.";
/**
 * `claimed_no_key` without account evidence (a mode fallback): the same holds, never an account claim.
 * This constant is the generic wording; the hold names its reason (setupUnconfirmedText). Same text as src/seatbelt/hook.ts.
 */
export declare const SETUP_UNCONFIRMED_TEXT = "Marrow stopped this action: there is no Marrow key on this machine, and Marrow uses its stricter no-key mode here because it could not confirm this machine's setup. Fix (for the person at this machine, not the agent): run npx -y @getmarrow/install@latest doctor, or add a Marrow key (getmarrow.ai/docs#start-here). Agent: do not retry it another way and do not edit Marrow settings; tell the user why it was stopped. Code: setup_unconfirmed.";
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
/** Marrow cannot be reached (a real outage): a high-risk action fails closed; routine actions keep the outage allow. */
export declare const HELD_OFFLINE_TEXT = "Marrow cannot be reached right now, so this high-risk action is held; routine actions keep running. Retry it when Marrow is back.";
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
    /** The hold is because this machine has no usable key (NO_KEY_TEXT, CLAIMED_NO_KEY_TEXT or SETUP_UNCONFIRMED_TEXT); set where those texts are set. */
    credentialsUnavailable?: boolean;
    failure?: 'credential_scope' | 'unavailable';
    outage?: boolean;
    /** Marrow did not answer inside the hook's time budget (slow, not down). */
    timedOut?: boolean;
};
export declare function isMarrowOutage(result: PreActionControlResult): boolean;
export declare function controlFailureKind(error: unknown): PreActionControlResult['failure'];
export declare function controlRejectionMessage(error: unknown, agentId?: string, kind?: PreActionControlResult['failure']): string;
export type OwnerApprovalPrompt = {
    available: boolean;
    unavailableReason: string;
    headless?: boolean; /** Static, one-sentence README fix for the person; never built from input. */
    fix?: string;
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
/** Keyless seatbelt: a host that cannot hand this action to its own approval prompt holds it (no account to approve it). */
export declare const SEATBELT_HELD_TEXT = "MARROW SEATBELT held this action: this host cannot show its own approval prompt here, and no Marrow account is linked to approve it. If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was held. For approval prompts, add a Marrow key: getmarrow.ai/docs#start-here.";
export declare const SEATBELT_CURSOR_ASK_USER_TEXT = "Marrow seatbelt (no account linked): approve this action here only if you expected it.";
export declare const SEATBELT_CURSOR_ASK_AGENT_TEXT = "Cursor is asking the user to approve this action (Marrow seatbelt, no account linked). Wait for the answer; do not retry it another way.";
/**
 * The keyless seatbelt's answer for an action it does not stop (spec §1.3 "pass": Marrow adds no
 * decision and the host's own permission flow runs). `heldBefore`: the 3.9.103 keyless hook held this
 * action (protected, or not read-only on Windsurf, Gemini or Grok). `null` means exit 0, no output.
 * - Not held before: exactly the answer 3.9.103 gave (its read-only and unprotected passes).
 * - Held before: never an explicit allow that could skip the host's own approval step.
 *   Claude Code and Codex `{}` (no permissionDecision), Cline `{cancel:false}`, Windsurf no output:
 *   the hosts' neutral answers (see PASS_THROUGH_HOSTS), so their own approval step runs.
 *   Gemini CLI `{"decision":"allow"}`: the installed guard passes only that or a fixed denial (no
 *   output is a launch failure that blocks), and Gemini applies its own policy and confirmation
 *   after the BeforeTool hook whatever an "allow" says, so it is Gemini's neutral answer.
 *   Cursor beforeShellExecution / beforeMCPExecution: "ask", so Cursor's own approval prompt decides.
 *   Cursor preToolUse (no neutral answer, "ask" not enforced) and Grok (its guard passes only an
 *   explicit allow or the fixed denial, and nothing shows an allow keeps Grok's own approval): held,
 *   as 3.9.103 did. Any other or missing Cursor event name is treated as preToolUse.
 */
export declare function seatbeltPassOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', hookEventName: unknown, heldBefore: boolean): Record<string, unknown> | null;
export declare function localLoopGuardDenyOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', reason: string): Record<string, unknown> | null;
/**
 * `ownUnproven`: the label is one of Marrow's own, but the host's server
 * identity check did not prove the official server (Codex, Cursor). Such a
 * call is classified as a protected MCP tool of another server, never
 * read-only (it imitates Marrow's names, so a read verb proves nothing).
 */
export type ToolClassification = {
    action: string;
    target: string;
    type: string;
    role: string;
    surfaces: string[];
    risk: 'low' | 'medium' | 'high';
    protected: boolean;
    readOnly: boolean;
};
/**
 * The classification of one tool call. A Monitor command (and a native git
 * equivalent such as EnterWorktree) is classified exactly as Bash running it;
 * any other call carrying a command or script string gets the stricter of its
 * own classification and Bash's for that text (its own classification,
 * unchanged, when that is already at least as strict). A PowerShell call is
 * one of those, with Bash's reading in the PowerShell dialect (no read-only
 * allowlist) and never read-only. See toolPolicyReading.
 */
export declare function classifyTool(event: PreToolUseEvent, options?: {
    ownUnproven?: boolean;
}): ToolClassification;
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
/**
 * `marrow-mcp seatbelt-status`: exactly one line of JSON, exit 0. Read-only. On any error the unknown line.
 * The installer's doctor reads it; it is not a user feature.
 */
export declare function runSeatbeltStatusCommand(): void;
/**
 * I3: whether a real outage (the gate never answered) holds this action. Never looser than master,
 * which allowed every action in an outage. A shell command is read by the seatbelt mapper: held for an
 * S0-S5/S-x hit or a program on the outage list (git push, publish, deploy, remote delete), allowed
 * when the mapper read all of it and found neither (words in a message, a path or a comment never hold
 * it). Anything else, or a mapper that could not finish, keeps `classifiedHighRisk` (F2).
 */
export declare function outageHolds(classifiedHighRisk: boolean, read: () => {
    shell: boolean;
    risk: 'high' | 'not_high' | 'unknown';
}): boolean;
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-pre-action.d.ts.map