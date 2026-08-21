"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NATIVE_EXPECTED_HOOKS = exports.SESSION_END_HOOK_COMMAND = exports.ACTION_RESULT_HOOK_COMMAND = exports.PRE_ACTION_HOOK_COMMAND = exports.CONTEXT_HOOK_COMMAND = exports.MCP_PACKAGE_SPEC = exports.GROK_NATIVE_HOOK_MATCHER = exports.NATIVE_HOOK_MATCHER = exports.MCP_ADAPTER_VERSION = void 0;
exports.normalizeHookEventPayload = normalizeHookEventPayload;
exports.findHookSettingsPath = findHookSettingsPath;
exports.readHookSettings = readHookSettings;
exports.readHookSettingsForInstall = readHookSettingsForInstall;
exports.reconcileMarrowCommandHook = reconcileMarrowCommandHook;
exports.hasExactCommandHook = hasExactCommandHook;
exports.nativeHookConfigurationFingerprint = nativeHookConfigurationFingerprint;
exports.nativeHookEvidence = nativeHookEvidence;
exports.stableToolCorrelation = stableToolCorrelation;
exports.stablePromptCorrelation = stablePromptCorrelation;
exports.stableSessionWorkflowId = stableSessionWorkflowId;
exports.grokHookSettingsPath = grokHookSettingsPath;
exports.installGrokNativeHooks = installGrokNativeHooks;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
exports.MCP_ADAPTER_VERSION = '3.9.71';
exports.NATIVE_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*';
exports.GROK_NATIVE_HOOK_MATCHER = 'run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video';
exports.MCP_PACKAGE_SPEC = `@getmarrow/mcp@${exports.MCP_ADAPTER_VERSION}`;
exports.CONTEXT_HOOK_COMMAND = `npx -y --package=${exports.MCP_PACKAGE_SPEC} marrow-mcp context-hook`;
exports.PRE_ACTION_HOOK_COMMAND = `npx -y --package=${exports.MCP_PACKAGE_SPEC} marrow-mcp pre-action-hook`;
exports.ACTION_RESULT_HOOK_COMMAND = `npx -y --package=${exports.MCP_PACKAGE_SPEC} marrow-mcp hook`;
exports.SESSION_END_HOOK_COMMAND = `npx -y --package=${exports.MCP_PACKAGE_SPEC} marrow-mcp session-hook`;
exports.NATIVE_EXPECTED_HOOKS = ['prompt', 'pre_action', 'action_result', 'session_end'];
const HOOK_CAMEL_TO_SNAKE = {
    hookEventName: 'hook_event_name',
    sessionId: 'session_id',
    toolName: 'tool_name',
    toolInput: 'tool_input',
    toolResponse: 'tool_response',
    toolResult: 'tool_result',
    toolUseId: 'tool_use_id',
    transcriptPath: 'transcript_path',
};
function normalizeHookEventPayload(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return {};
    const source = value;
    const normalized = { ...source };
    for (const [camel, snake] of Object.entries(HOOK_CAMEL_TO_SNAKE)) {
        if (normalized[snake] == null && normalized[camel] != null)
            normalized[snake] = normalized[camel];
    }
    return normalized;
}
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function findHookSettingsPath(startDir = process.cwd()) {
    let dir = startDir;
    let fallback = null;
    for (let depth = 0; depth < 8; depth += 1) {
        const candidate = (0, node_path_1.join)(dir, '.claude', 'settings.json');
        if ((0, node_fs_1.existsSync)(candidate) || (0, node_fs_1.existsSync)((0, node_path_1.join)(dir, '.claude')))
            return candidate;
        if (!fallback && (0, node_fs_1.existsSync)((0, node_path_1.join)(dir, '.git')))
            fallback = candidate;
        const parent = (0, node_path_1.dirname)(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return fallback || (0, node_path_1.join)(startDir, '.claude', 'settings.json');
}
function readHookSettings(startDir = process.cwd()) {
    const path = findHookSettingsPath(startDir);
    if (!(0, node_fs_1.existsSync)(path))
        return {};
    try {
        return asRecord(JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'))) || {};
    }
    catch {
        return {};
    }
}
function readHookSettingsForInstall(startDir = process.cwd()) {
    const path = findHookSettingsPath(startDir);
    if (!(0, node_fs_1.existsSync)(path))
        return {};
    let parsed;
    try {
        parsed = JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'));
    }
    catch (error) {
        const detail = error instanceof Error ? error.message : 'invalid JSON';
        throw new Error(`Cannot update Claude hook settings at ${path}: ${detail}`);
    }
    const settings = asRecord(parsed);
    if (!settings) {
        throw new Error(`Cannot update Claude hook settings at ${path}: root must be a JSON object`);
    }
    return settings;
}
function marrowHookSubcommand(command) {
    if (typeof command !== 'string')
        return null;
    const match = command.trim().match(/^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+(context-hook|pre-action-hook|hook|session-hook)$/);
    return match?.[1] || null;
}
function reconcileMarrowCommandHook(settings, eventName, subcommand, command, matcher) {
    const hooks = asRecord(settings.hooks);
    const original = Array.isArray(hooks?.[eventName]) ? hooks[eventName] : [];
    let preferredHandler = null;
    const retained = [];
    for (const entry of original) {
        const record = asRecord(entry);
        if (!record || !Array.isArray(record.hooks)) {
            retained.push(entry);
            continue;
        }
        const remaining = [];
        for (const hook of record.hooks) {
            const handler = asRecord(hook);
            const detected = marrowHookSubcommand(handler?.command);
            if (handler?.type === 'command' && detected) {
                const exactMatcher = matcher === undefined
                    ? record.matcher === undefined
                    : record.matcher === matcher;
                if (detected === subcommand && (!preferredHandler || (handler.command === command && exactMatcher))) {
                    preferredHandler = handler;
                }
                continue;
            }
            remaining.push(hook);
        }
        if (remaining.length > 0)
            retained.push({ ...record, hooks: remaining });
    }
    const handler = { ...(preferredHandler || {}), type: 'command', command };
    const canonicalEntry = { hooks: [handler] };
    if (matcher !== undefined)
        canonicalEntry.matcher = matcher;
    retained.push(canonicalEntry);
    return {
        entries: retained,
        changed: JSON.stringify(original) !== JSON.stringify(retained),
    };
}
function marrowHookDescriptors(settings, eventName, subcommand) {
    const hooks = asRecord(settings.hooks);
    const entries = hooks?.[eventName];
    if (!Array.isArray(entries))
        return [];
    return entries.flatMap((entry) => {
        const record = asRecord(entry);
        if (!record || !Array.isArray(record.hooks))
            return [];
        return record.hooks.flatMap((hook) => {
            const handler = asRecord(hook);
            const detected = marrowHookSubcommand(handler?.command);
            if (handler?.type !== 'command' || !detected || (subcommand && detected !== subcommand))
                return [];
            return [{
                    matcher: typeof record.matcher === 'string' ? record.matcher : null,
                    command: String(handler.command).trim(),
                    timeout: typeof handler.timeout === 'number' && Number.isFinite(handler.timeout)
                        ? handler.timeout
                        : null,
                }];
        });
    });
}
function hasExactCommandHook(settings, eventName, command, matcher) {
    const hooks = asRecord(settings.hooks);
    const entries = hooks?.[eventName];
    if (!Array.isArray(entries))
        return false;
    return entries.some((entry) => {
        const record = asRecord(entry);
        if (!record || (matcher !== undefined && record.matcher !== matcher) || !Array.isArray(record.hooks))
            return false;
        return record.hooks.some((hook) => {
            const handler = asRecord(hook);
            return handler?.type === 'command'
                && typeof handler.command === 'string'
                && handler.command.trim() === command;
        });
    });
}
function exactHookDescriptors(settings, eventName, command, matcher) {
    const hooks = asRecord(settings.hooks);
    const entries = hooks?.[eventName];
    if (!Array.isArray(entries))
        return [];
    return entries.flatMap((entry) => {
        const record = asRecord(entry);
        if (!record || (matcher !== undefined && record.matcher !== matcher) || !Array.isArray(record.hooks))
            return [];
        return record.hooks.flatMap((hook) => {
            const handler = asRecord(hook);
            if (handler?.type !== 'command' || typeof handler.command !== 'string' || handler.command.trim() !== command)
                return [];
            return [{
                    matcher: typeof record.matcher === 'string' ? record.matcher : null,
                    command,
                    timeout: typeof handler.timeout === 'number' && Number.isFinite(handler.timeout)
                        ? handler.timeout
                        : null,
                }];
        });
    });
}
function nativeHookConfigurationFingerprint(startDir = process.cwd()) {
    const settings = readHookSettings(startDir);
    const contract = {
        schema: 'marrow-claude-native-hooks.v3',
        adapter_version: exports.MCP_ADAPTER_VERSION,
        expected_hooks: exports.NATIVE_EXPECTED_HOOKS,
        configured: {
            prompt: hasExactCommandHook(settings, 'UserPromptSubmit', exports.CONTEXT_HOOK_COMMAND),
            pre_action: hasExactCommandHook(settings, 'PreToolUse', exports.PRE_ACTION_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            action_result_success: hasExactCommandHook(settings, 'PostToolUse', exports.ACTION_RESULT_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            action_result_failure: hasExactCommandHook(settings, 'PostToolUseFailure', exports.ACTION_RESULT_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            session_end: hasExactCommandHook(settings, 'Stop', exports.SESSION_END_HOOK_COMMAND),
        },
        descriptors: {
            prompt: exactHookDescriptors(settings, 'UserPromptSubmit', exports.CONTEXT_HOOK_COMMAND),
            pre_action: exactHookDescriptors(settings, 'PreToolUse', exports.PRE_ACTION_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            action_result_success: exactHookDescriptors(settings, 'PostToolUse', exports.ACTION_RESULT_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            action_result_failure: exactHookDescriptors(settings, 'PostToolUseFailure', exports.ACTION_RESULT_HOOK_COMMAND, exports.NATIVE_HOOK_MATCHER),
            session_end: exactHookDescriptors(settings, 'Stop', exports.SESSION_END_HOOK_COMMAND),
        },
        active_marrow_handlers: {
            prompt: marrowHookDescriptors(settings, 'UserPromptSubmit'),
            pre_action: marrowHookDescriptors(settings, 'PreToolUse'),
            action_result_success: marrowHookDescriptors(settings, 'PostToolUse'),
            action_result_failure: marrowHookDescriptors(settings, 'PostToolUseFailure'),
            session_end: marrowHookDescriptors(settings, 'Stop'),
        },
    };
    return (0, node_crypto_1.createHash)('sha256').update(JSON.stringify(contract)).digest('hex');
}
function nativeHookEvidence(observedHook, startDir = process.cwd()) {
    return {
        adapter_version: exports.MCP_ADAPTER_VERSION,
        capability_level: 'native_hooks',
        config_fingerprint: nativeHookConfigurationFingerprint(startDir),
        expected_hooks: [...exports.NATIVE_EXPECTED_HOOKS],
        observed_hook: observedHook,
    };
}
function stableHash(value) {
    return (0, node_crypto_1.createHash)('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 32);
}
function stableToolCorrelation(event) {
    return stableHash([
        event.session_id || '',
        event.tool_use_id || '',
        event.tool_name || 'tool',
        event.tool_use_id ? null : event.tool_input ?? null,
    ]);
}
function stablePromptCorrelation(event) {
    return stableHash([event.session_id || '', event.prompt || '']);
}
function stableSessionWorkflowId(sessionId, fallback) {
    return `session-${stableHash([sessionId || '', sessionId ? null : fallback ?? null])}`;
}
function grokHookSettingsPath(home = process.env.HOME || (0, node_os_1.homedir)()) {
    return (0, node_path_1.join)(home, '.grok', 'hooks', 'marrow.json');
}
function installGrokNativeHooks(home = process.env.HOME || (0, node_os_1.homedir)()) {
    const settingsPath = grokHookSettingsPath(home);
    const command = (subcommand) => (subcommand === 'context-hook' ? exports.CONTEXT_HOOK_COMMAND
        : subcommand === 'pre-action-hook' ? exports.PRE_ACTION_HOOK_COMMAND
            : subcommand === 'session-hook' ? exports.SESSION_END_HOOK_COMMAND
                : exports.ACTION_RESULT_HOOK_COMMAND);
    const handler = (subcommand) => ({
        type: 'command',
        command: command(subcommand),
        timeout: 15,
    });
    const next = {
        hooks: {
            UserPromptSubmit: [{ hooks: [handler('context-hook')] }],
            PreToolUse: [{ matcher: exports.GROK_NATIVE_HOOK_MATCHER, hooks: [handler('pre-action-hook')] }],
            PostToolUse: [{ matcher: exports.GROK_NATIVE_HOOK_MATCHER, hooks: [handler('hook')] }],
            PostToolUseFailure: [{ matcher: exports.GROK_NATIVE_HOOK_MATCHER, hooks: [handler('hook')] }],
            Stop: [{ hooks: [handler('session-hook')] }],
            SessionEnd: [{ hooks: [handler('session-hook')] }],
        },
    };
    let previous = '';
    if ((0, node_fs_1.existsSync)(settingsPath)) {
        try {
            previous = (0, node_fs_1.readFileSync)(settingsPath, 'utf8');
        }
        catch {
            previous = '';
        }
    }
    const serialized = `${JSON.stringify(next, null, 2)}\n`;
    (0, node_fs_1.mkdirSync)((0, node_path_1.dirname)(settingsPath), { recursive: true, mode: 0o700 });
    (0, node_fs_1.writeFileSync)(settingsPath, serialized, { mode: 0o600 });
    return { settingsPath, installed: previous !== serialized };
}
//# sourceMappingURL=hook-contract.js.map