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

import { TOOLS } from './tool-catalog';

export const MARROW_OWN_SERVER_NAME = 'marrow';

export const MARROW_OWN_TOOL_NAMES: ReadonlySet<string> = new Set(TOOLS.map((tool) => tool.name));

const OWN_TOOL_PREFIXES = ['mcp__marrow__', 'functions.mcp__marrow__', 'MCP:marrow:', 'MCP:'] as const;

const NESTED_MCP_TOOLS = new Set(['use_mcp_tool', 'use_tool', 'mcp', 'mcp_tool']);

type OwnToolEvent = { tool_name?: unknown; tool_input?: unknown };

export function isMarrowOwnTool(server: unknown, tool: unknown): boolean {
  return server === MARROW_OWN_SERVER_NAME && typeof tool === 'string' && MARROW_OWN_TOOL_NAMES.has(tool);
}

export function isOfficialMarrowMcpTool(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return OWN_TOOL_PREFIXES.some((prefix) => value.startsWith(prefix)
    && MARROW_OWN_TOOL_NAMES.has(value.slice(prefix.length)));
}

/** Every alias the host sent must agree; a conflicting pair is never own. */
function soleAlias(input: Record<string, unknown>, keys: readonly string[]): unknown {
  const present = keys.filter((key) => input[key] !== undefined).map((key) => input[key]);
  return present.length > 0 && present.every((value) => value === present[0]) ? present[0] : undefined;
}

/** The exact own-property string, never an inherited or coerced value. */
function ownString(record: Record<string, unknown>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(record, key) && typeof record[key] === 'string' ? record[key] as string : undefined;
}

/**
 * Gemini's separate server and tool (`mcp_context.server_name`/`tool_name`,
 * the mcpServers key and the server's own tool name), when the host sent both
 * as strings. Only these two fields: the context's command, args, cwd and url
 * are never kept.
 */
export function geminiMcpTarget(value: unknown): { server_name: string; tool_name: string } | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
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
export function isOfficialMarrowGeminiCall(label: unknown, context: unknown): boolean {
  const target = geminiMcpTarget(context);
  if (!target || !isMarrowOwnTool(target.server_name, target.tool_name)) return false;
  return label === `mcp_marrow_${target.tool_name}` || label === `mcp__marrow__${target.tool_name}`;
}

/** Gemini's label for a Marrow tool, as the label alone would claim it (never proof). */
export function isGeminiOwnLabel(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith('mcp_marrow_') && MARROW_OWN_TOOL_NAMES.has(value.slice('mcp_marrow_'.length));
}

export function isOfficialMarrowNestedInput(input: unknown): boolean {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const record = input as Record<string, unknown>;
  return isMarrowOwnTool(soleAlias(record, ['serverName', 'server_name']), soleAlias(record, ['toolName', 'tool_name']));
}

export function isOfficialMarrowMcpEvent(event: OwnToolEvent): boolean {
  if (isOfficialMarrowMcpTool(event.tool_name)) return true;
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

function ownAlternation(names: Iterable<string>): string {
  return [...names].sort().map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
}

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
export function nativeHookMatcher(names: Iterable<string> = MARROW_OWN_TOOL_NAMES): string {
  return `${NATIVE_HOOK_BUILTIN_TOOLS}|^(?!mcp__marrow__(?:${ownAlternation(names)})$)[\\s\\S]*(?:functions\\.|mcp__)[\\s\\S]*`;
}

/** The never-released r2 matcher (c5354487): `.*` tails and a `functions.` exemption. A hook carrying it is repaired. */
export function r2NativeHookMatcher(names: Iterable<string> = MARROW_OWN_TOOL_NAMES): string {
  const own = ownAlternation(names);
  return `${NATIVE_HOOK_BUILTIN_TOOLS}|functions\\.(?!mcp__marrow__(?:${own})$).*|mcp__(?!marrow__(?:${own})$).*`;
}

/** A server the plain form can carry: exact host name, no `:` (so the first `:` after `MCP:` always ends it). */
const PLAIN_MCP_SERVER = /^[A-Za-z0-9._-]{1,128}$/;
const PLAIN_MCP_TOOL = /^[A-Za-z0-9._:-]{1,128}$/;

/** One raw name in the escaped form: a JSON string literal (self-delimiting), or `?<type>` for a value that is not a string. */
function escapedPart(value: unknown): string {
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
export function normalizedMcpToolName(own: boolean, tool: string, server: string, rawServer: unknown, rawTool: unknown): string {
  if (own) return `mcp__marrow__${tool}`;
  if (typeof rawServer === 'string' && typeof rawTool === 'string' && rawServer === server && rawTool === tool
    && PLAIN_MCP_SERVER.test(rawServer) && PLAIN_MCP_TOOL.test(rawTool)) {
    const plain = `MCP:${rawServer}:${rawTool}`;
    if (!isOfficialMarrowMcpTool(plain)) return plain;
  }
  return `MCP:${escapedPart(rawServer)}:${escapedPart(rawTool)}`;
}
