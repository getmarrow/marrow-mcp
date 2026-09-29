import { marrowAgentRuntime, marrowEnforcement } from './index';
import { MARROW_OUTAGE_WARNING } from './hook-contract';
export { MARROW_OUTAGE_WARNING };
export declare const MAX_PRE_ACTION_INPUT_BYTES: number;
export declare const PRE_ACTION_CONTROL_TIMEOUT_MS = 8000;
export declare class PreActionControlTimeoutError extends Error {
    readonly code = "request_timeout";
    constructor();
}
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
type PreActionControlResult = {
    runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null;
    permit: Awaited<ReturnType<typeof marrowEnforcement>> | null;
    protectedRisk: boolean;
    enforcementError?: string;
    failure?: 'credential_scope' | 'unavailable';
    outage?: boolean;
};
export declare function isMarrowOutage(result: PreActionControlResult): boolean;
export declare function controlFailureKind(error: unknown): PreActionControlResult['failure'];
export declare function controlRejectionMessage(error: unknown, agentId?: string): string;
export type OwnerApprovalPrompt = {
    available: boolean;
    unavailableReason: string;
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
/** The runtime, not the hook, decides whether its gate is enforced (Team+ hard enforcement). */
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
export declare function preActionHookOutput(result: PreActionControlResult, harness?: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client', prompt?: OwnerApprovalPrompt): Record<string, unknown>;
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
export declare function installPreActionHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-pre-action.d.ts.map