import { createHash } from 'node:crypto';
import { redactSensitiveText, redactSensitiveValue } from './redact';
import {
  hookToolCommand,
  isMcpHookTool,
  isShellGovernedTool,
  normalizeHookToolName,
  parseShellSegments,
  toolTargetPaths,
} from './hook-tool-policy';

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

const MAX_COMMAND = 4_000;
const MAX_INPUT_JSON = 8_192;
const EDIT_TOOLS = /^(?:edit|write|multiedit|apply_patch|notebookedit|replace|write_file|edit_file|delete_file|search_replace|delete|create_file)$/i;

type ToolEvent = { tool_name?: unknown; tool_input?: unknown };

/** A shell command with secret values removed and whitespace collapsed. */
export function normalizeShellCommand(command: string): { text: string; truncated: boolean } {
  let text = command
    // Environment assignment values (FOO=bar cmd, export FOO=bar): names stay, values go.
    .replace(/(^|[\s;&|(`])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|)`]+)/g, '$1$2=[redacted]')
    // Credentials in URLs (scheme://user:secret@host).
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:'"]+(?::[^\s/@'"]*)?@/gi, '$1[redacted]@');
  text = redactSensitiveText(text).replace(/\s+/g, ' ').trim();
  const truncated = text.length > MAX_COMMAND;
  return { text: truncated ? text.slice(0, MAX_COMMAND) : text, truncated };
}

function programsOf(command: string): string[] {
  const segments = parseShellSegments(command);
  const words = segments ? segments.map((segment) => segment.words[0]).filter(Boolean) : [command.split(/\s+/)[0]];
  return [...new Set(words.map((word) => word.replace(/^.*\//, '').slice(0, 64)).filter((word) => /^[A-Za-z0-9._+-]+$/.test(word)))].slice(0, 16);
}

function sortedValue(value: unknown, depth = 0): unknown {
  if (depth > 6 || !value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => sortedValue(item, depth + 1));
  return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort()
    .map((key) => [key, sortedValue((value as Record<string, unknown>)[key], depth + 1)]));
}

/** A tool input with secrets removed; large inputs are represented by a hash of the redacted input. */
function boundedInput(input: unknown): { tool_input?: Record<string, unknown>; truncated?: boolean } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const redacted = sortedValue(redactSensitiveValue(input)) as Record<string, unknown>;
  const json = JSON.stringify(redacted);
  if (json.length <= MAX_INPUT_JSON) return { tool_input: redacted };
  return { tool_input: { input_sha256: createHash('sha256').update(json).digest('hex') }, truncated: true };
}

export function normalizedHookAction(event: ToolEvent): NormalizedHookAction {
  // The host's own tool name (stable across retries); the policy name decides the kind.
  const toolName = normalizeHookToolName(event.tool_name) || 'tool';
  const hostToolName = (typeof event.tool_name === 'string' && event.tool_name.trim() ? event.tool_name.trim() : toolName).slice(0, 128);
  if (isMcpHookTool(event.tool_name) || /^MCP:/i.test(hostToolName)) {
    return { tool_kind: 'mcp', tool_name: hostToolName, ...boundedInput(event.tool_input) };
  }
  if (isShellGovernedTool(event as Parameters<typeof isShellGovernedTool>[0])) {
    const raw = hookToolCommand(event as Parameters<typeof hookToolCommand>[0]);
    const { text, truncated } = normalizeShellCommand(raw);
    return {
      tool_kind: 'shell',
      tool_name: hostToolName,
      commands: text ? [text] : [],
      programs: programsOf(text),
      ...(truncated ? { truncated: true } : {}),
    };
  }
  if (EDIT_TOOLS.test(toolName)) {
    const paths = toolTargetPaths(event as Parameters<typeof toolTargetPaths>[0]).map((path) => redactSensitiveText(path).slice(0, 512)).slice(0, 64);
    return { tool_kind: 'edit', tool_name: hostToolName, paths };
  }
  return { tool_kind: 'other', tool_name: hostToolName, ...boundedInput(event.tool_input) };
}
