"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeShellCommand = normalizeShellCommand;
exports.normalizedHookAction = normalizedHookAction;
const node_crypto_1 = require("node:crypto");
const redact_1 = require("./redact");
const hook_tool_policy_1 = require("./hook-tool-policy");
const MAX_COMMAND = 4_000;
const MAX_INPUT_JSON = 8_192;
const EDIT_TOOLS = /^(?:edit|write|multiedit|apply_patch|notebookedit|replace|write_file|edit_file|delete_file|search_replace|delete|create_file)$/i;
/** A shell command with secret values removed and whitespace collapsed. */
function normalizeShellCommand(command) {
    let text = command
        // Environment assignment values (FOO=bar cmd, export FOO=bar): names stay, values go.
        .replace(/(^|[\s;&|(`])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|)`]+)/g, '$1$2=[redacted]')
        // Credentials in URLs (scheme://user:secret@host).
        .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:'"]+(?::[^\s/@'"]*)?@/gi, '$1[redacted]@');
    text = (0, redact_1.redactSensitiveText)(text).replace(/\s+/g, ' ').trim();
    const truncated = text.length > MAX_COMMAND;
    return { text: truncated ? text.slice(0, MAX_COMMAND) : text, truncated };
}
function programsOf(command) {
    const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
    const words = segments ? segments.map((segment) => segment.words[0]).filter(Boolean) : [command.split(/\s+/)[0]];
    return [...new Set(words.map((word) => word.replace(/^.*\//, '').slice(0, 64)).filter((word) => /^[A-Za-z0-9._+-]+$/.test(word)))].slice(0, 16);
}
function sortedValue(value, depth = 0) {
    if (depth > 6 || !value || typeof value !== 'object')
        return value;
    if (Array.isArray(value))
        return value.map((item) => sortedValue(item, depth + 1));
    return Object.fromEntries(Object.keys(value).sort()
        .map((key) => [key, sortedValue(value[key], depth + 1)]));
}
/** A tool input with secrets removed; large inputs are represented by a hash of the redacted input. */
function boundedInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input))
        return {};
    const redacted = sortedValue((0, redact_1.redactSensitiveValue)(input));
    const json = JSON.stringify(redacted);
    if (json.length <= MAX_INPUT_JSON)
        return { tool_input: redacted };
    return { tool_input: { input_sha256: (0, node_crypto_1.createHash)('sha256').update(json).digest('hex') }, truncated: true };
}
function normalizedHookAction(event) {
    // The host's own tool name (stable across retries); the policy name decides the kind.
    const toolName = (0, hook_tool_policy_1.normalizeHookToolName)(event.tool_name) || 'tool';
    const hostToolName = (typeof event.tool_name === 'string' && event.tool_name.trim() ? event.tool_name.trim() : toolName).slice(0, 128);
    if ((0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) || /^MCP:/i.test(hostToolName)) {
        return { tool_kind: 'mcp', tool_name: hostToolName, ...boundedInput(event.tool_input) };
    }
    if ((0, hook_tool_policy_1.isShellGovernedTool)(event)) {
        const raw = (0, hook_tool_policy_1.hookToolCommand)(event);
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
        const paths = (0, hook_tool_policy_1.toolTargetPaths)(event).map((path) => (0, redact_1.redactSensitiveText)(path).slice(0, 512)).slice(0, 64);
        return { tool_kind: 'edit', tool_name: hostToolName, paths };
    }
    return { tool_kind: 'other', tool_name: hostToolName, ...boundedInput(event.tool_input) };
}
//# sourceMappingURL=normalized-action.js.map