"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeHookToolName = normalizeHookToolName;
exports.hookToolCommand = hookToolCommand;
exports.isReadOnlyToolEvent = isReadOnlyToolEvent;
const READ_ONLY_TOOLS = new Set([
    'read',
    'grep',
    'glob',
    'ls',
    'notebookread',
    'todoread',
    'tasklist',
    'taskget',
    'sessions_list',
    'sessions_history',
    'session_status',
    'marrow_list_memories',
    'marrow_retrieve_memories',
    'marrow_get_memory',
    'marrow_dashboard',
    'marrow_digest',
    'marrow_status',
    'marrow_orient',
    'marrow_ask',
]);
const READ_ONLY_BASH_COMMANDS = new Set([
    'read', 'grep', 'rg', 'ls', 'cat', 'find', 'tail', 'head', 'wc', 'file',
    'stat', 'which', 'type', 'echo', 'printf', 'pwd', 'date', 'env', 'printenv',
    'whoami', 'uname',
]);
const MUTATION_TOOL_VERB = /(?:^|__|_)(?:create|update|delete|remove|write|edit|send|post|put|patch|execute|run|deploy|publish|merge|push|commit|revoke|rotate|charge|refund|cancel|approve)(?:_|$)/;
const READ_ONLY_TOOL_VERB = /(?:^|__|_)(?:get|list|read|search|find|fetch|status|inspect|query)(?:_|$)/;
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function stringValue(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
function normalizeHookToolName(value) {
    return String(value || '').replace(/^mcp__/, '').trim().toLowerCase();
}
function hookToolCommand(event) {
    if (typeof event.tool_input === 'string')
        return event.tool_input.trim();
    const input = asRecord(event.tool_input);
    if (!input)
        return '';
    for (const key of ['command', 'description', 'query', 'path', 'file_path', 'url', 'name']) {
        const value = stringValue(input[key]);
        if (value)
            return value;
    }
    try {
        return JSON.stringify(input).slice(0, 4096);
    }
    catch {
        return '';
    }
}
function hasWriteLikeShellSyntax(command) {
    return /(^|[^>])>(?!>)|>>|\b(?:tee|touch|mkdir|rm|mv|cp|install|uninstall|publish|deploy|release)\b|\bsed\s+-i\b|\bperl\s+-i\b/i.test(command)
        || /\b(?:curl|wget|nc|ncat|netcat|scp|rsync|ssh|ftp|tftp)\b/i.test(command)
        || /\bgit\s+(?:push|merge|commit|rebase|reset|checkout|switch|tag)\b/i.test(command);
}
function hasCompoundShellSyntax(command) {
    return /[|;&`\n\r]|\$\(|\$\{/.test(command);
}
function pathOnlyInput(value) {
    const input = asRecord(value);
    if (!input)
        return false;
    const keys = Object.keys(input);
    return keys.length > 0
        && keys.every((key) => ['path', 'file_path', 'filename', 'target_file'].includes(key))
        && Object.values(input).every((item) => typeof item === 'string' && item.trim().length > 0);
}
function isReadOnlyToolEvent(event) {
    const tool = normalizeHookToolName(event.tool_name);
    if (!tool)
        return false;
    if (READ_ONLY_TOOLS.has(tool))
        return true;
    if (MUTATION_TOOL_VERB.test(tool))
        return false;
    if (READ_ONLY_TOOL_VERB.test(tool))
        return true;
    const command = hookToolCommand(event).replace(/\s+/g, ' ').trim();
    if (tool === 'bash' && command && !hasCompoundShellSyntax(command) && !hasWriteLikeShellSyntax(command)) {
        if (/^(?:node|npm)\s+(?:-v|--version)$/i.test(command))
            return true;
        if (/^git\s+(?:status|diff|show|log|branch|rev-parse|ls-files|ls-remote)(?:\s|$)/i.test(command))
            return true;
        const firstToken = command.split(/[\s|;&]+/, 1)[0]?.toLowerCase();
        if (firstToken && READ_ONLY_BASH_COMMANDS.has(firstToken))
            return true;
    }
    return !['edit', 'write', 'multiedit'].includes(tool) && pathOnlyInput(event.tool_input);
}
//# sourceMappingURL=hook-tool-policy.js.map