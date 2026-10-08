/**
 * The exact action a hook-classified tool call performs, in the service's
 * normalized_action shape (marrow.gate.v1 `action`), so Marrow binds a gate,
 * a hold and an approval to that exact command or tool call, not to the
 * coarse classification ("deploy on production") the hook also sends.
 *
 * What leaves the machine: the tool kind, the host's tool name, the program
 * names of a shell command, file paths of an edit, and a SHA-256 of the
 * command or tool input. The command text and tool input themselves are never
 * sent. Before hashing, secret-bearing values are replaced (environment
 * values, credentials in URLs, values after password, token, OTP and key flags
 * and in known secret positions, text piped into a command, here-strings and
 * heredoc bodies, and any argument shaped like a key), so the hash is of a
 * secret-free form: the same command gives the same hash on every machine and
 * on every retry, and two commands that differ only in a secret value give
 * the same hash. A program name or path that looks like a key is dropped.
 */
export type NormalizedHookAction = {
    tool_kind: 'shell' | 'edit' | 'mcp' | 'other';
    tool_name: string;
    programs?: string[];
    paths?: string[];
    tool_input: {
        command_sha256: string;
    } | {
        input_sha256: string;
    } | Record<string, never>;
};
type ToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
/** A value shaped like a key, token or password hash (mixed-case random text, long hex, known prefixes). */
export declare function looksLikeKey(value: string): boolean;
/**
 * The secret-free normalized form of a shell command: whitespace and quoting
 * normalized, secret values replaced (see the module comment). Exported for
 * tests; it is hashed and never sent.
 */
export declare function normalizeShellCommand(command: string): {
    text: string;
    programs: string[];
};
export declare function normalizedHookAction(event: ToolEvent): NormalizedHookAction;
export {};
//# sourceMappingURL=normalized-action.d.ts.map