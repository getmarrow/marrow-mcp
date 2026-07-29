"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTO_HOOK_MATCHER = exports.AUTO_HOOK_COMMAND = void 0;
exports.shouldSkipAutoLog = shouldSkipAutoLog;
exports.installPostToolUseHook = installPostToolUseHook;
exports.runHookCommand = runHookCommand;
const index_1 = require("./index");
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_contract_1 = require("./hook-contract");
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
exports.AUTO_HOOK_COMMAND = hook_contract_1.ACTION_RESULT_HOOK_COMMAND;
exports.AUTO_HOOK_MATCHER = hook_contract_1.NATIVE_HOOK_MATCHER;
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
function deriveAction(event) {
    const toolName = getString(event.tool_name);
    if (!toolName || shouldSkipAutoLog(event))
        return null;
    if (toolName.startsWith('mcp__marrow_'))
        return null;
    if (toolName === 'Bash') {
        return 'shell command execution observed; business outcome pending';
    }
    if (['Edit', 'Write', 'MultiEdit'].includes(toolName)) {
        return 'workspace mutation observed; business outcome pending';
    }
    if (toolName.startsWith('mcp__')) {
        const tool = normalizeToolName(toolName);
        if (tool.startsWith('marrow_'))
            return null;
        return `external MCP tool execution observed (${truncate(tool, 80)}); business outcome pending`;
    }
    return `${truncate(normalizeToolName(toolName), 80)} tool execution observed; business outcome pending`;
}
function deriveToolSuccess(event) {
    const response = event.tool_response ?? event.tool_result;
    const responseRecord = asRecord(response);
    const errorValue = responseRecord?.error;
    const failed = event.hook_event_name === 'PostToolUseFailure'
        || event.error != null
        || errorValue !== undefined && errorValue !== null
        || responseRecord?.is_error === true
        || responseRecord?.success === false
        || (typeof responseRecord?.exit_code === 'number' && responseRecord.exit_code !== 0)
        || /^(?:failed|error|blocked)$/i.test(String(responseRecord?.status || ''));
    return !failed;
}
async function readStdin() {
    const chunks = [];
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) {
        chunks.push(chunk);
    }
    return chunks.join('');
}
function installPostToolUseHook(startDir = process.cwd()) {
    const fs = require('fs');
    const path = require('path');
    const settingsPath = (0, hook_contract_1.findHookSettingsPath)(startDir);
    const settings = (0, hook_contract_1.readHookSettings)(startDir);
    const hooks = asRecord(settings.hooks) || {};
    const postToolUse = Array.isArray(hooks.PostToolUse) ? [...hooks.PostToolUse] : [];
    const postToolUseFailure = Array.isArray(hooks.PostToolUseFailure) ? [...hooks.PostToolUseFailure] : [];
    const successInstalled = (0, hook_contract_1.hasExactCommandHook)(settings, 'PostToolUse', exports.AUTO_HOOK_COMMAND, exports.AUTO_HOOK_MATCHER);
    const failureInstalled = (0, hook_contract_1.hasExactCommandHook)(settings, 'PostToolUseFailure', exports.AUTO_HOOK_COMMAND, exports.AUTO_HOOK_MATCHER);
    if (!successInstalled) {
        postToolUse.push({
            matcher: exports.AUTO_HOOK_MATCHER,
            hooks: [{ type: 'command', command: exports.AUTO_HOOK_COMMAND }],
        });
    }
    if (!failureInstalled) {
        postToolUseFailure.push({
            matcher: exports.AUTO_HOOK_MATCHER,
            hooks: [{ type: 'command', command: exports.AUTO_HOOK_COMMAND }],
        });
    }
    settings.hooks = {
        ...hooks,
        PostToolUse: postToolUse,
        PostToolUseFailure: postToolUseFailure,
    };
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    return {
        settingsPath,
        installed: !successInstalled || !failureInstalled,
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
        const resolvedEnv = (0, env_1.resolveMarrowEnv)();
        const apiKey = resolvedEnv.apiKey || '';
        if (!apiKey) {
            debug(`[marrow-hook] skipped missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
            process.exit(0);
            return;
        }
        const baseUrl = (0, index_1.validateBaseUrl)(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
        const sessionId = resolvedEnv.sessionId || getString(event.session_id);
        const agentId = resolvedEnv.agentId || undefined;
        const success = deriveToolSuccess(event);
        const toolName = normalizeToolName(getString(event.tool_name) || 'tool');
        const eventType = toolName === 'bash'
            ? success ? 'command_completed' : 'command_failed'
            : success ? 'tool_completed' : 'tool_failed';
        const lifecycleCorrelation = (0, hook_contract_1.stableToolCorrelation)({ ...event, session_id: sessionId });
        await (0, lifecycle_spool_1.recordLifecycleEvent)({
            apiKey,
            baseUrl,
            event: {
                event_id: `posttool-${lifecycleCorrelation}`,
                event_type: eventType,
                harness: 'claude-code',
                agent_id: agentId,
                session_id: sessionId,
                workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, event.tool_use_id),
                correlation_id: lifecycleCorrelation,
                ...(0, hook_contract_1.nativeHookEvidence)('action_result'),
                action,
                success,
                outcome_state: 'pending',
            },
        });
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        debug(`[marrow-hook] ${message}`);
    }
    process.exit(0);
}
//# sourceMappingURL=hook.js.map