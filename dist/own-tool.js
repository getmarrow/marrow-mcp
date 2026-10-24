"use strict";
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
 * These functions decide on the label alone. The Codex and Cursor hooks do not
 * trust the label: Codex builds it from the user's server name (servers
 * `mcp__marrow`, `marrow-` and `marrow_` also give `mcp__marrow__<tool>`) and
 * Cursor's preToolUse `MCP:<tool>` has no server. Those hooks skip only after
 * own-server-identity.ts proves, from the host's MCP config, that exactly one
 * server can produce the label and it starts the official package
 * (isOfficialMarrowMcpEventOnHost); every other host keeps this label rule.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS = exports.MARROW_OWN_TOOL_NAMES = exports.MARROW_OWN_SERVER_NAME = void 0;
exports.isMarrowOwnTool = isMarrowOwnTool;
exports.isOfficialMarrowMcpTool = isOfficialMarrowMcpTool;
exports.geminiMcpTarget = geminiMcpTarget;
exports.isOfficialMarrowGeminiCall = isOfficialMarrowGeminiCall;
exports.isGeminiOwnLabel = isGeminiOwnLabel;
exports.isOfficialMarrowNestedInput = isOfficialMarrowNestedInput;
exports.isOfficialMarrowMcpEvent = isOfficialMarrowMcpEvent;
exports.nativeHookMatcher = nativeHookMatcher;
exports.listNativeHookMatcher = listNativeHookMatcher;
exports.r2NativeHookMatcher = r2NativeHookMatcher;
exports.normalizedMcpToolName = normalizedMcpToolName;
const tool_catalog_1 = require("./tool-catalog");
exports.MARROW_OWN_SERVER_NAME = 'marrow';
exports.MARROW_OWN_TOOL_NAMES = new Set(tool_catalog_1.TOOLS.map((tool) => tool.name));
const OWN_TOOL_PREFIXES = ['mcp__marrow__', 'functions.mcp__marrow__', 'MCP:marrow:', 'MCP:'];
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
/** The exact own-property string, never an inherited or coerced value. */
function ownString(record, key) {
    return Object.prototype.hasOwnProperty.call(record, key) && typeof record[key] === 'string' ? record[key] : undefined;
}
/**
 * Gemini's separate server and tool (`mcp_context.server_name`/`tool_name`,
 * the mcpServers key and the server's own tool name), when the host sent both
 * as strings. Only these two fields: the context's command, args, cwd and url
 * are never kept.
 */
function geminiMcpTarget(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const record = value;
    const server = ownString(record, 'server_name');
    const tool = ownString(record, 'tool_name');
    return server === undefined || tool === undefined ? null : { server_name: server, tool_name: tool };
}
/**
 * A Gemini call is Marrow's own only when its mcp_context proves server
 * `marrow` and an exact registered tool, and the host's label is that call's
 * label (`mcp_marrow_<tool>`, or the normalised `mcp__marrow__<tool>` on the
 * second read). Without mcp_context it is never own.
 */
function isOfficialMarrowGeminiCall(label, context) {
    const target = geminiMcpTarget(context);
    if (!target || !isMarrowOwnTool(target.server_name, target.tool_name))
        return false;
    return label === `mcp_marrow_${target.tool_name}` || label === `mcp__marrow__${target.tool_name}`;
}
/** Gemini's label for a Marrow tool, as the label alone would claim it (never proof). */
function isGeminiOwnLabel(value) {
    return typeof value === 'string' && value.startsWith('mcp_marrow_') && exports.MARROW_OWN_TOOL_NAMES.has(value.slice('mcp_marrow_'.length));
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
 * Read-only Claude Code tools that no released matcher sent to the hook (they list names, never
 * content), so they stay unhooked by exact label. A tool any released matcher hooked is never here.
 */
exports.NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS = ['LS', 'ListMcpResourcesTool'];
function ownAlternation(names) {
    return [...names].sort().map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
}
/**
 * The Claude Code hook matcher (marrow-install writes the identical bytes): every
 * label except exactly `mcp__marrow__<registered name>` and the exact read-only
 * labels above. Unknown and future tools (Monitor, PowerShell, WebFetch, Agent and
 * any tool Claude Code adds later) reach the hook by default. Claude Code's label
 * proves server `marrow` (it maps every other character to `_`, without
 * trimming); no other host form is skipped. Hosts test it unanchored (search) or
 * as a full match; with no m flag `^` and `$` are the start and end of the label,
 * and the consuming part is `[\s\S]*`, so a label padded anywhere (line
 * terminators, NUL, spaces) reaches the hook either way.
 */
function nativeHookMatcher(names = exports.MARROW_OWN_TOOL_NAMES) {
    return `^(?!(?:mcp__marrow__(?:${ownAlternation(names)})|${exports.NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS.join('|')})$)[\\s\\S]*`;
}
/** The matcher @getmarrow/mcp 3.9.102 and 3.9.103 wrote: a fixed list of built-ins, so Monitor, PowerShell, WebFetch and Agent were skipped. A hook carrying it is repaired. */
function listNativeHookMatcher(names = exports.MARROW_OWN_TOOL_NAMES) {
    return `${NATIVE_HOOK_BUILTIN_TOOLS}|^(?!mcp__marrow__(?:${ownAlternation(names)})$)[\\s\\S]*(?:functions\\.|mcp__)[\\s\\S]*`;
}
/** The never-released r2 matcher (c5354487): `.*` tails and a `functions.` exemption. A hook carrying it is repaired. */
function r2NativeHookMatcher(names = exports.MARROW_OWN_TOOL_NAMES) {
    const own = ownAlternation(names);
    return `${NATIVE_HOOK_BUILTIN_TOOLS}|functions\\.(?!mcp__marrow__(?:${own})$).*|mcp__(?!marrow__(?:${own})$).*`;
}
/** A server the plain form can carry: exact host name, no `:` (so the first `:` after `MCP:` always ends it). */
const PLAIN_MCP_SERVER = /^[A-Za-z0-9._-]{1,128}$/;
const PLAIN_MCP_TOOL = /^[A-Za-z0-9._:-]{1,128}$/;
/** One raw name in the escaped form: a JSON string literal (self-delimiting), or `?<type>` for a value that is not a string. */
function escapedPart(value) {
    return typeof value === 'string' ? JSON.stringify(value) : `?${value === null ? 'null' : typeof value}`;
}
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
function normalizedMcpToolName(own, tool, server, rawServer, rawTool) {
    if (own)
        return `mcp__marrow__${tool}`;
    if (typeof rawServer === 'string' && typeof rawTool === 'string' && rawServer === server && rawTool === tool
        && PLAIN_MCP_SERVER.test(rawServer) && PLAIN_MCP_TOOL.test(rawTool)) {
        const plain = `MCP:${rawServer}:${rawTool}`;
        if (!isOfficialMarrowMcpTool(plain))
            return plain;
    }
    return `MCP:${escapedPart(rawServer)}:${escapedPart(rawTool)}`;
}
//# sourceMappingURL=own-tool.js.map