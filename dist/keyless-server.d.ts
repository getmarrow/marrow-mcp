/**
 * Keyless start of the MCP server. With no Marrow key anywhere the server reads
 * one, the server used to print "MARROW_API_KEY environment variable is
 * required" and exit 1, which hosts show as a broken server. It now answers the
 * MCP protocol with zero tools and an `instructions` string that says how the
 * owner connects a key.
 *
 * Fail closed: keylessStart is true only for a clear "no key". A key, anything
 * key-shaped, a refused owner key file, a base URL the server would refuse, or
 * any doubt runs the real server path exactly as before.
 *
 * The keyless server judges, checks and records nothing. It starts no child
 * process, opens no network and no file, reads no environment, and writes only
 * to stdout and stderr. Hooks are separate entrypoints and are not touched.
 * Protocol handling matches the plugin launcher's keyless stub
 * (marrow-plugins plugins/<plugin>/scripts/marrow-launch.cjs, serveKeyless).
 *
 * Never looser than the exit 1 it replaces: until a valid `initialize` request has
 * been answered, a frame that is not JSON-RPC 2.0 (a Cursor or Claude hook payload
 * piped to the entry, a parse error, an oversize line) or an end of stdin ends the
 * process with the no-key refusal on stderr, nothing on stdout, and exit 1. After
 * an initialize, the end of stdin is exit 0.
 *
 * The key text (URL, activate command, plugin steps, the refusal) is owned by cli.ts
 * and passed in; this file holds no second copy of it.
 */
export interface KeylessInstructionParts {
    getKeyUrl: string;
    activateCommand: string;
    /** Set when the server runs under the Claude Code plugin: its key steps replace the activate command. */
    pluginSteps?: string;
}
/** The `instructions` string of the initialize answer. */
export declare function keylessInstructions(parts: KeylessInstructionParts): string;
export interface KeylessTexts {
    instructions: string;
    /** Written to stderr once, when the first initialize is answered. */
    notice: string;
    /** The server's own no-key refusal, written to stderr before the exit 1 that a non-MCP first frame or an early end of stdin gets. */
    refusal: string;
}
export declare const KEYLESS_NOTICE = "Marrow: no Marrow key on this machine, so the Marrow MCP server started with no tools. Marrow hooks, where they are set up, keep their free keyless seatbelt.";
/**
 * Whether the MCP server starts keyless. `resolved` must be the server's own resolveMarrowEnv() result.
 * True only when it found no key (an empty MARROW_API_KEY or MARROW_KEY counts as none, a whitespace one does
 * not), no owner key file was refused, no `--key` argument is given in any form, no fleet key
 * (MARROW_KEY_<SUFFIX>) is set, and the base URL passes the server's own check.
 */
export declare function keylessStart(resolved: unknown, argv: readonly unknown[], env: Record<string, string | undefined>): boolean;
export declare function keylessProtocolVersion(params: unknown): string;
/** Newline-delimited JSON-RPC 2.0 on stdio with zero tools. Exits 0 when stdin ends after an initialize, 1 for a non-MCP start. */
export declare function serveKeylessMcp(serverVersion: string, texts: KeylessTexts): void;
//# sourceMappingURL=keyless-server.d.ts.map