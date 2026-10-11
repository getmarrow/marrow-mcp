/**
 * Marrow's own MCP tools skip the pre-action gate. A tool is Marrow's own only
 * when its server is exactly `marrow` and its tool is exactly a name this
 * package registers (any profile). Case, padding, NUL, suffixes and look-alike
 * servers are never own, so they go down the normal gate path.
 *
 * Host forms (the exact names each host emits for the `marrow` server):
 *   mcp__marrow__<tool>            Claude Code, Codex; the form the Windsurf,
 *                                  Cursor, Grok and Gemini adapters normalise to
 *   functions.mcp__marrow__<tool>  Codex function namespace
 *   MCP:<tool>                     Cursor preToolUse (no server part; see below)
 *   MCP:marrow:<tool>              Cursor preToolUse look-alike (see below)
 *   use_mcp_tool / use_tool (+ mcp, mcp_tool) with serverName and toolName
 *                                  Cline and Grok nested calls
 *
 * Gemini's label `mcp_<server>_<tool>` is ambiguous (server `marrow_marrow` +
 * tool `commit` gives the same label as server `marrow` + tool
 * `marrow_commit`), so it is never own by itself: the Gemini adapter decides
 * from the payload's separate `mcp_context.server_name` / `tool_name`
 * (isOfficialMarrowGeminiCall) and normalises an own call to
 * `mcp__marrow__<tool>`.
 *
 * Cursor preToolUse carries no server (`MCP:<tool>`), so `MCP:<own>` from any
 * server still counts as own there. That is an open owner decision: no rule is
 * both exact and free of lockout (cloud agents never run beforeMCPExecution).
 */
export declare const MARROW_OWN_SERVER_NAME = "marrow";
export declare const MARROW_OWN_TOOL_NAMES: ReadonlySet<string>;
type OwnToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
export declare function isMarrowOwnTool(server: unknown, tool: unknown): boolean;
export declare function isOfficialMarrowMcpTool(value: unknown): boolean;
/**
 * Gemini's separate server and tool (`mcp_context.server_name`/`tool_name`,
 * the mcpServers key and the server's own tool name), when the host sent both
 * as strings. Only these two fields: the context's command, args, cwd and url
 * are never kept.
 */
export declare function geminiMcpTarget(value: unknown): {
    server_name: string;
    tool_name: string;
} | null;
/**
 * A Gemini call is Marrow's own only when its mcp_context proves server
 * `marrow` and an exact registered tool, and the host's label is that call's
 * label (`mcp_marrow_<tool>`, or the normalised `mcp__marrow__<tool>` on the
 * second read). Without mcp_context it is never own.
 */
export declare function isOfficialMarrowGeminiCall(label: unknown, context: unknown): boolean;
/** Gemini's label for a Marrow tool, as the label alone would claim it (never proof). */
export declare function isGeminiOwnLabel(value: unknown): boolean;
export declare function isOfficialMarrowNestedInput(input: unknown): boolean;
export declare function isOfficialMarrowMcpEvent(event: OwnToolEvent): boolean;
/**
 * The Claude Code hook matcher (marrow-install writes the identical bytes): every
 * built-in it covers, and every label holding `mcp__` or `functions.` anywhere,
 * except exactly `mcp__marrow__<registered name>`. Claude Code's label proves
 * server `marrow` (it maps every other character to `_`, without trimming);
 * no other host form is skipped. Hosts test it unanchored (search) or as a
 * full match; with no m flag `^` and `$` are the start and end of the label,
 * and every consuming part is `[\s\S]*`, so a label padded anywhere (line
 * terminators, NUL, spaces) reaches the hook either way.
 */
export declare function nativeHookMatcher(names?: Iterable<string>): string;
/** The never-released r2 matcher (c5354487): `.*` tails and a `functions.` exemption. A hook carrying it is repaired. */
export declare function r2NativeHookMatcher(names?: Iterable<string>): string;
/**
 * The normalised name of a host MCP call that came with a separate server and
 * tool (Cursor beforeMCPExecution, Windsurf, Grok use_tool). Every distinct
 * (raw server, raw tool) pair gets a distinct name, so it never shares an
 * action, a correlation or an approval with another target:
 *   own                            mcp__marrow__<tool>
 *   exact names, colon-free server MCP:<server>:<tool>   (unchanged form)
 *   anything else                  MCP:<"server" | ?type>:<"tool" | ?type>
 * The plain server has no `"`, `?` or `:`, so the forms cannot be confused,
 * and JSON string literals are self-delimiting. Nothing is cut: a long name
 * stays whole here (normalizedHookAction marks one over 128 never bound).
 */
export declare function normalizedMcpToolName(own: boolean, tool: string, server: string, rawServer: unknown, rawTool: unknown): string;
export {};
//# sourceMappingURL=own-tool.d.ts.map