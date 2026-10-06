/**
 * The exact action a hook-classified tool call performs, in the service's
 * normalized_action shape (marrow.gate.v1 `action`), so Marrow binds a gate,
 * a hold and an approval to that exact command or tool call, not to the
 * coarse classification ("deploy on production") the hook also sends.
 *
 * Secrets never leave: environment assignment values, credentials in URLs,
 * token-like strings and secret-named fields are replaced before anything is
 * sent. The value is deterministic, so a retry of the same command produces
 * the same normalized action.
 */
export type NormalizedHookAction = {
    tool_kind: 'shell' | 'edit' | 'mcp' | 'other';
    tool_name: string;
    commands?: string[];
    programs?: string[];
    paths?: string[];
    tool_input?: Record<string, unknown>;
    truncated?: boolean;
};
type ToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
/** A shell command with secret values removed and whitespace collapsed. */
export declare function normalizeShellCommand(command: string): {
    text: string;
    truncated: boolean;
};
export declare function normalizedHookAction(event: ToolEvent): NormalizedHookAction;
export {};
//# sourceMappingURL=normalized-action.d.ts.map