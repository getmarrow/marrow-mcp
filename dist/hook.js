"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTO_HOOK_MATCHER = exports.AUTO_HOOK_COMMAND = void 0;
exports.shouldSkipAutoLog = shouldSkipAutoLog;
exports.installPostToolUseHook = installPostToolUseHook;
exports.runHookCommand = runHookCommand;
const index_1 = require("./index");
const SKIP_TOOLS = new Set([
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
    'read',
    'grep',
    'ls',
    'cat',
    'find',
    'tail',
    'head',
    'wc',
    'file',
    'stat',
    'which',
    'type',
    'echo',
    'pwd',
    'date',
    'env',
    'whoami',
    'uname',
]);
exports.AUTO_HOOK_COMMAND = 'npx -y @getmarrow/mcp hook';
exports.AUTO_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow_).*';
const HOOK_DEBUG = process.env.MARROW_HOOK_DEBUG === 'true';
function debug(msg) {
    if (HOOK_DEBUG)
        process.stderr.write(msg + '\n');
}
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function getString(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
function normalizeToolName(toolName) {
    return toolName.replace(/^mcp__/, '').trim().toLowerCase();
}
function truncate(value, max) {
    if (value.length <= max)
        return value;
    return value.slice(0, Math.max(0, max - 1)).trimEnd() + '…';
}
function normalizeWhitespace(value) {
    return value.replace(/\s+/g, ' ').trim();
}
function safeStringify(value, max) {
    try {
        return truncate(normalizeWhitespace(JSON.stringify(value)), max);
    }
    catch {
        return truncate(String(value), max);
    }
}
function extractFilePath(toolInput) {
    for (const key of ['file_path', 'path', 'target_file', 'filename']) {
        const value = getString(toolInput[key]);
        if (value)
            return value;
    }
    return undefined;
}
function extractDescription(toolInput) {
    return getString(toolInput.description);
}
function isPathOnlyInput(toolInput) {
    const record = asRecord(toolInput);
    if (!record)
        return false;
    const keys = Object.keys(record);
    if (keys.length === 0)
        return false;
    if (!keys.every((key) => ['path', 'file_path', 'filename', 'target_file'].includes(key))) {
        return false;
    }
    return Object.values(record).every((value) => typeof value === 'string' && value.trim().length > 0);
}
function hasWriteLikeShellSyntax(command) {
    if (/(^|[^>])>(?!>)|>>|\btee\b|\btouch\b|\bmkdir\b|\brm\b|\bmv\b|\bcp\b|\binstall\b|\buninstall\b|\bpublish\b|\bsed\s+-i\b|\bperl\s+-i\b/i.test(command)) {
        return true;
    }
    if (/\b(curl|wget|nc|ncat|netcat|scp|rsync|ssh|ftp|tftp)\b/i.test(command)) {
        return true;
    }
    return false;
}
function shouldSkipBashCommand(command) {
    const normalized = normalizeWhitespace(command);
    if (!normalized || hasWriteLikeShellSyntax(normalized))
        return false;
    if (/^node\s+-v(?:ersion)?$/i.test(normalized) || /^npm\s+-v(?:ersion)?$/i.test(normalized)) {
        return true;
    }
    const firstToken = normalized.split(/[\s|;&]+/, 1)[0]?.toLowerCase();
    return !!firstToken && READ_ONLY_BASH_COMMANDS.has(firstToken);
}
function shouldSkipAutoLog(event) {
    const rawToolName = getString(event.tool_name);
    if (!rawToolName)
        return true;
    const toolName = normalizeToolName(rawToolName);
    if (SKIP_TOOLS.has(toolName))
        return true;
    if (toolName.startsWith('marrow_') && SKIP_TOOLS.has(toolName))
        return true;
    const toolInput = asRecord(event.tool_input) || {};
    const command = getString(toolInput.command) || extractDescription(toolInput) || extractFirstArg(event.tool_input);
    if (toolName === 'bash' && command && shouldSkipBashCommand(command)) {
        return true;
    }
    if (toolName !== 'edit' && toolName !== 'write' && toolName !== 'multiedit' && isPathOnlyInput(event.tool_input)) {
        return true;
    }
    return false;
}
function extractFirstArg(toolInput) {
    if (typeof toolInput === 'string')
        return toolInput;
    if (Array.isArray(toolInput)) {
        for (const item of toolInput) {
            if (typeof item === 'string' && item.trim())
                return item;
            if (typeof item === 'number' || typeof item === 'boolean')
                return String(item);
            const record = asRecord(item);
            if (record)
                return safeStringify(record, 120);
        }
        return undefined;
    }
    const record = asRecord(toolInput);
    if (!record)
        return undefined;
    for (const key of ['command', 'path', 'file_path', 'pattern', 'query', 'text', 'url', 'slug', 'name']) {
        const value = getString(record[key]);
        if (value)
            return value;
    }
    for (const value of Object.values(record)) {
        if (typeof value === 'string' && value.trim())
            return value;
        if (typeof value === 'number' || typeof value === 'boolean')
            return String(value);
    }
    return safeStringify(record, 120);
}
function buildMcpArgsSummary(toolInput) {
    const record = asRecord(toolInput);
    if (!record) {
        const first = extractFirstArg(toolInput);
        return first ? truncate(normalizeWhitespace(first), 120) : undefined;
    }
    const clone = { ...record };
    delete clone.description;
    const keys = Object.keys(clone);
    if (keys.length === 0)
        return undefined;
    return safeStringify(clone, 120);
}
function deriveAction(event) {
    const toolName = getString(event.tool_name);
    if (!toolName || shouldSkipAutoLog(event))
        return null;
    if (toolName.startsWith('mcp__marrow_'))
        return null;
    const toolInput = asRecord(event.tool_input) || {};
    const description = extractDescription(toolInput);
    const firstArg = extractFirstArg(event.tool_input);
    let action = null;
    if (toolName === 'Bash') {
        action = `ran: ${truncate(normalizeWhitespace(description || getString(toolInput.command) || firstArg || 'bash command'), 120)}`;
    }
    else if (toolName === 'Edit') {
        action = `edited: ${extractFilePath(toolInput) || truncate(normalizeWhitespace(description || firstArg || 'unknown file'), 120)}`;
    }
    else if (toolName === 'Write') {
        action = `wrote: ${extractFilePath(toolInput) || truncate(normalizeWhitespace(description || firstArg || 'unknown file'), 120)}`;
    }
    else if (toolName === 'MultiEdit') {
        action = `multi-edited: ${extractFilePath(toolInput) || truncate(normalizeWhitespace(description || firstArg || 'unknown file'), 120)}`;
    }
    else if (toolName.startsWith('mcp__')) {
        const tool = toolName.slice('mcp__'.length);
        if (tool.startsWith('marrow_'))
            return null;
        const args = buildMcpArgsSummary(event.tool_input);
        action = args ? `called MCP tool: ${tool} with ${args}` : `called MCP tool: ${tool}`;
    }
    else if (description) {
        action = description;
    }
    else {
        action = `${toolName}: ${truncate(normalizeWhitespace(firstArg || 'no args'), 120)}`;
    }
    return truncate(normalizeWhitespace(action), 500);
}
function deriveOutcome(event) {
    const response = event.tool_response ?? event.tool_result;
    const responseRecord = asRecord(response);
    const errorValue = responseRecord?.error;
    if (errorValue !== undefined && errorValue !== null) {
        return {
            success: false,
            outcome: truncate(`failed: ${normalizeWhitespace(safeStringify(errorValue, 240))}`, 500),
        };
    }
    return {
        success: true,
        outcome: 'completed successfully',
    };
}
async function readStdin() {
    const chunks = [];
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) {
        chunks.push(chunk);
    }
    return chunks.join('');
}
function getHomeDir() {
    return process.env.HOME || process.env.USERPROFILE || process.cwd();
}
function looksLikeProjectRoot(dir) {
    const fs = require('fs');
    const path = require('path');
    return ['.git', 'package.json', 'CLAUDE.md'].some((name) => fs.existsSync(path.join(dir, name)));
}
function findSettingsPath(startDir) {
    const fs = require('fs');
    const path = require('path');
    let dir = startDir;
    let fallbackProjectDir = null;
    while (true) {
        const claudeDir = path.join(dir, '.claude');
        const settingsPath = path.join(claudeDir, 'settings.json');
        if (fs.existsSync(settingsPath) || fs.existsSync(claudeDir)) {
            return settingsPath;
        }
        if (!fallbackProjectDir && looksLikeProjectRoot(dir)) {
            fallbackProjectDir = dir;
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    if (fallbackProjectDir) {
        return path.join(fallbackProjectDir, '.claude', 'settings.json');
    }
    return path.join(getHomeDir(), '.claude', 'settings.json');
}
function installPostToolUseHook(startDir = process.cwd()) {
    const fs = require('fs');
    const path = require('path');
    const settingsPath = findSettingsPath(startDir);
    let settings = {};
    if (fs.existsSync(settingsPath)) {
        const raw = fs.readFileSync(settingsPath, 'utf8').trim();
        if (raw) {
            const parsed = JSON.parse(raw);
            const record = asRecord(parsed);
            if (!record) {
                throw new Error(`Existing settings file is not a JSON object: ${settingsPath}`);
            }
            settings = record;
        }
    }
    const hooks = asRecord(settings.hooks) || {};
    const postToolUse = Array.isArray(hooks.PostToolUse) ? [...hooks.PostToolUse] : [];
    const alreadyInstalled = postToolUse.some((entry) => {
        const record = asRecord(entry);
        if (!record || !Array.isArray(record.hooks))
            return false;
        return record.hooks.some((hook) => {
            const hookRecord = asRecord(hook);
            return !!(hookRecord && typeof hookRecord.command === 'string' && hookRecord.command.includes(exports.AUTO_HOOK_COMMAND));
        });
    });
    if (!alreadyInstalled) {
        postToolUse.push({
            matcher: exports.AUTO_HOOK_MATCHER,
            hooks: [{ type: 'command', command: exports.AUTO_HOOK_COMMAND }],
        });
    }
    settings.hooks = {
        ...hooks,
        PostToolUse: postToolUse,
    };
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    return {
        settingsPath,
        installed: !alreadyInstalled,
    };
}
async function runHookCommand() {
    if (process.env.MARROW_AUTO_HOOK === 'false') {
        process.exit(0);
        return;
    }
    try {
        const raw = (await readStdin()).trim();
        if (!raw) {
            process.exit(0);
            return;
        }
        let event;
        try {
            event = JSON.parse(raw);
        }
        catch {
            debug('[marrow-hook] skipped invalid JSON');
            process.exit(0);
            return;
        }
        if (shouldSkipAutoLog(event)) {
            debug('[marrow-hook] skipped read-only tool');
            process.exit(0);
            return;
        }
        const action = deriveAction(event);
        if (!action) {
            process.exit(0);
            return;
        }
        const apiKey = process.env.MARROW_API_KEY || '';
        if (!apiKey) {
            debug('[marrow-hook] skipped missing MARROW_API_KEY');
            process.exit(0);
            return;
        }
        const baseUrl = (0, index_1.validateBaseUrl)(process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai');
        const sessionId = process.env.MARROW_SESSION_ID || getString(event.session_id);
        const agentId = process.env.MARROW_FLEET_AGENT_ID || undefined;
        const { success, outcome } = deriveOutcome(event);
        await (0, index_1.marrowAuto)(apiKey, baseUrl, { action, outcome, success, type: 'general' }, sessionId, agentId, 2000);
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        debug(`[marrow-hook] ${message}`);
    }
    process.exit(0);
}
//# sourceMappingURL=hook.js.map