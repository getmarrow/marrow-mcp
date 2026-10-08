import { resolveMarrowEnv, type ResolvedMarrowEnv } from './env';
export declare const MCP_ADAPTER_VERSION = "3.9.100";
export declare const NATIVE_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|functions\\.(?!mcp__marrow__marrow_).*|mcp__(?!marrow__marrow_).*";
export declare const GROK_NATIVE_HOOK_MATCHER = "run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video";
export declare const MCP_PACKAGE_SPEC = "@getmarrow/mcp@3.9.100";
export declare const CONTEXT_HOOK_COMMAND: string;
export declare const PRE_ACTION_HOOK_COMMAND: string;
export declare const ACTION_RESULT_HOOK_COMMAND: string;
export declare const SESSION_END_HOOK_COMMAND: string;
/**
 * Pass-through PermissionRequest hook: notes that Claude Code is about to show
 * its own permission dialog for a held call, so the operator's answer can be
 * labelled an operator approval. It never returns a decision and is installed
 * with async: true, so it cannot answer or delay the dialog.
 */
export declare const PERMISSION_REQUEST_HOOK_COMMAND: string;
export declare const GROK_CONTEXT_HOOK_COMMAND: string;
export declare const GROK_PRE_ACTION_HOOK_COMMAND: string;
export declare const GROK_ACTION_RESULT_HOOK_COMMAND: string;
export declare const GROK_SESSION_END_HOOK_COMMAND: string;
export declare const GROK_FIXED_DENIAL = "Marrow blocked this protected action.";
export declare const GROK_LAUNCH_FAILURE = "Marrow governance adapter was unavailable; this action is blocked.";
export declare const MARROW_OUTAGE_WARNING = "Marrow is offline. This action is allowed. The record stays queued locally and is sent when Marrow is back.";
export declare const GROK_PRE_ACTION_GUARD_COMMAND: string;
export declare const CURSOR_PRE_ACTION_HOOK_COMMAND: string;
export declare const CURSOR_ACTION_RESULT_HOOK_COMMAND: string;
export declare const CURSOR_SESSION_END_HOOK_COMMAND: string;
export declare const CURSOR_CONTEXT_HOOK_COMMAND: string;
export declare const CLINE_PRE_ACTION_HOOK_COMMAND: string;
export declare const CLINE_ACTION_RESULT_HOOK_COMMAND: string;
export declare const CLINE_SESSION_END_HOOK_COMMAND: string;
export declare const WINDSURF_PRE_ACTION_HOOK_COMMAND: string;
export declare const WINDSURF_ACTION_RESULT_HOOK_COMMAND: string;
export declare const WINDSURF_SESSION_END_HOOK_COMMAND: string;
export declare const GEMINI_PRE_ACTION_HOOK_COMMAND: string;
export declare const GEMINI_ACTION_RESULT_HOOK_COMMAND: string;
export declare const GEMINI_SESSION_END_HOOK_COMMAND: string;
export declare const GEMINI_CONTEXT_HOOK_COMMAND: string;
export type NativeHookHarness = 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client';
export interface NativeHookIdentity {
    harness: NativeHookHarness;
    identity_source: 'public_cli_entrypoint' | 'generic_fallback';
    client_self_reported: true;
    agent_id?: string;
    environment: ResolvedMarrowEnv;
}
/**
 * Label client-reported hook activity from the public CLI entrypoint. The
 * entrypoint is not host provenance and cannot certify coverage. Hook JSON is
 * deliberately not an identity input, and the authenticated service remains
 * authoritative for the credential-bound agent identity.
 */
export declare function resolveNativeHookIdentity(entrypoint: unknown, options?: Parameters<typeof resolveMarrowEnv>[0]): NativeHookIdentity;
export declare function clientReportedHookLifecycleIdentity(identity: NativeHookIdentity): Pick<import('./lifecycle-spool').LifecycleEvent, 'harness' | 'agent_id' | 'source'>;
type PrivateHookLoopGuardPayload = {
    toolInput?: unknown;
    toolResult?: unknown;
};
export declare function privateHookLoopGuardPayload(event: object): PrivateHookLoopGuardPayload;
export declare function normalizeHookEventPayload(value: unknown): Record<string, unknown>;
type HookSettings = Record<string, unknown>;
export declare function findHookSettingsPath(startDir?: string): string;
export declare function readHookSettings(startDir?: string): HookSettings;
export declare function readHookSettingsForInstall(startDir?: string): HookSettings;
/**
 * The npx form of an installer local-runtime hook command, or the command
 * unchanged when it is not exactly one (another shape, a suffix, a different
 * runtime path, or versions that differ anywhere in it).
 */
export declare function delocalizeMarrowHookCommand(command: unknown): unknown;
/** Whether a hook command is `canonical` itself or the installer's local form of it. */
export declare function isMarrowHookCommand(command: unknown, canonical: string): boolean;
export type MarrowHookSubcommand = 'context-hook' | 'pre-action-hook' | 'hook' | 'session-hook' | 'permission-request-hook';
export declare function reconcileMarrowCommandHook(settings: HookSettings, eventName: string, subcommand: MarrowHookSubcommand, command: string, matcher?: string, handlerFields?: Record<string, unknown>): {
    entries: unknown[];
    changed: boolean;
};
export declare function hasExactCommandHook(settings: HookSettings, eventName: string, command: string, matcher?: string): boolean;
export declare function localHookConfigurationFingerprint(startDir?: string): string;
/**
 * The correlation of one tool call (pre- and post-tool events, holds): the
 * session, the tool and the call's normalized action. Calls that differ only
 * in a secret share it; a retry of the same call keeps it.
 */
export declare function stableToolCorrelation(event: {
    session_id?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
}): string;
/**
 * The correlation of one submitted prompt: the session and the host's own
 * prompt, turn or generation id, never the prompt text (it may hold a secret). A host
 * that gives no id gets a fresh one per prompt event.
 */
export declare function stablePromptCorrelation(event: {
    session_id?: string;
    prompt_id?: unknown;
    turn_id?: unknown;
    generation_id?: unknown;
}): string;
export declare function stableSessionWorkflowId(sessionId?: string, fallback?: unknown): string;
export declare function grokHookSettingsPath(home?: string): string;
export declare function installGrokNativeHooks(home?: string): {
    settingsPath: string;
    installed: boolean;
};
export {};
//# sourceMappingURL=hook-contract.d.ts.map