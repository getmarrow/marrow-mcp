/**
 * Marrow's own MCP tools skip the pre-action gate. A tool is Marrow's own only
 * when its server is exactly `marrow` and its tool is exactly a name this
 * package registers (any profile). Case, padding, NUL, suffixes and look-alike
 * servers are never own, so they go down the normal gate path.
 *
 * Host forms (the exact names each host emits for the `marrow` server):
 *   mcp__marrow__<tool>            Claude Code, Codex; the form the Windsurf,
 *                                  Cursor and Grok adapters normalise to
 *   functions.mcp__marrow__<tool>  Codex function namespace
 *   mcp_marrow_<tool>              Gemini CLI (mcp_<server>_<tool>)
 *   MCP:<tool>                     Cursor preToolUse (no server part)
 *   MCP:marrow:<tool>              Cursor MCP events
 *   use_mcp_tool / use_tool (+ mcp, mcp_tool) with serverName and toolName
 *                                  Cline and Grok nested calls
 */
export declare const MARROW_OWN_SERVER_NAME = "marrow";
export declare const MARROW_OWN_TOOL_NAMES: ReadonlySet<string>;
type OwnToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
export declare function isMarrowOwnTool(server: unknown, tool: unknown): boolean;
export declare function isOfficialMarrowMcpTool(value: unknown): boolean;
export declare function isOfficialMarrowNestedInput(input: unknown): boolean;
export declare function isOfficialMarrowMcpEvent(event: OwnToolEvent): boolean;
/**
 * The Claude Code / Codex hook matcher: every built-in it covers, and every MCP
 * or `functions.` tool except exactly Marrow's own registered names on server
 * `marrow`. Hosts full-match it (`^(?:matcher)$`), so the `$` inside each
 * lookahead skips only an exact own name; a suffix, padding or a different
 * case reaches the hook. marrow-install must write the identical string.
 */
export declare function nativeHookMatcher(names?: Iterable<string>): string;
export declare function normalizedMcpToolName(own: boolean, tool: string, server: string, rawServer: unknown, rawTool: unknown): string;
export {};
//# sourceMappingURL=own-tool.d.ts.map