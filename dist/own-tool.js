"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.MARROW_OWN_TOOL_NAMES = exports.MARROW_OWN_SERVER_NAME = void 0;
exports.isMarrowOwnTool = isMarrowOwnTool;
exports.isOfficialMarrowMcpTool = isOfficialMarrowMcpTool;
exports.isOfficialMarrowNestedInput = isOfficialMarrowNestedInput;
exports.isOfficialMarrowMcpEvent = isOfficialMarrowMcpEvent;
exports.nativeHookMatcher = nativeHookMatcher;
exports.normalizedMcpToolName = normalizedMcpToolName;
const tool_catalog_1 = require("./tool-catalog");
exports.MARROW_OWN_SERVER_NAME = 'marrow';
exports.MARROW_OWN_TOOL_NAMES = new Set(tool_catalog_1.TOOLS.map((tool) => tool.name));
const OWN_TOOL_PREFIXES = ['mcp__marrow__', 'functions.mcp__marrow__', 'mcp_marrow_', 'MCP:marrow:', 'MCP:'];
const NESTED_MCP_TOOLS = new Set(['use_mcp_tool', 'use_tool', 'mcp', 'mcp_tool']);
function isMarrowOwnTool(server, tool) {
    return server === exports.MARROW_OWN_SERVER_NAME && typeof tool === 'string' && exports.MARROW_OWN_TOOL_NAMES.has(tool);
}
function isOfficialMarrowMcpTool(value) {
    if (typeof value !== 'string')
        return false;
    return OWN_TOOL_PREFIXES.some((prefix) => value.startsWith(prefix)
        && exports.MARROW_OWN_TOOL_NAMES.has(value.slice(prefix.length)));
}
/** Every alias the host sent must agree; a conflicting pair is never own. */
function soleAlias(input, keys) {
    const present = keys.filter((key) => input[key] !== undefined).map((key) => input[key]);
    return present.length > 0 && present.every((value) => value === present[0]) ? present[0] : undefined;
}
function isOfficialMarrowNestedInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input))
        return false;
    const record = input;
    return isMarrowOwnTool(soleAlias(record, ['serverName', 'server_name']), soleAlias(record, ['toolName', 'tool_name']));
}
function isOfficialMarrowMcpEvent(event) {
    if (isOfficialMarrowMcpTool(event.tool_name))
        return true;
    return typeof event.tool_name === 'string'
        && NESTED_MCP_TOOLS.has(event.tool_name)
        && isOfficialMarrowNestedInput(event.tool_input);
}
/**
 * Hook adapters that see a separate server and tool name. `own` is the exact
 * decision on the raw host values; `server` and `tool` are the bounded
 * (trimmed) names. An inexact `marrow` call (padding, a padded wrapper,
 * conflicting aliases) never normalises into an own form: it keeps its quoted
 * raw names, so it stays a distinct, gated MCP action.
 */
const NATIVE_HOOK_BUILTIN_TOOLS = 'Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task';
/**
 * The Claude Code / Codex hook matcher: every built-in it covers, and every MCP
 * or `functions.` tool except exactly Marrow's own registered names on server
 * `marrow`. Hosts full-match it (`^(?:matcher)$`), so the `$` inside each
 * lookahead skips only an exact own name; a suffix, padding or a different
 * case reaches the hook. marrow-install must write the identical string.
 */
function nativeHookMatcher(names = exports.MARROW_OWN_TOOL_NAMES) {
    const own = [...names].sort().map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    return `${NATIVE_HOOK_BUILTIN_TOOLS}|functions\\.(?!mcp__marrow__(?:${own})$).*|mcp__(?!marrow__(?:${own})$).*`;
}
function normalizedMcpToolName(own, tool, server, rawServer, rawTool) {
    if (own)
        return `mcp__marrow__${tool}`;
    const name = `MCP:${server}:${tool}`;
    return isOfficialMarrowMcpTool(name)
        ? `MCP:${JSON.stringify(String(rawServer).slice(0, 128))}:${JSON.stringify(String(rawTool).slice(0, 128))}`
        : name;
}
//# sourceMappingURL=own-tool.js.map