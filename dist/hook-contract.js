"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NATIVE_EXPECTED_HOOKS = exports.SESSION_END_HOOK_COMMAND = exports.ACTION_RESULT_HOOK_COMMAND = exports.PRE_ACTION_HOOK_COMMAND = exports.CONTEXT_HOOK_COMMAND = exports.MCP_PACKAGE_SPEC = exports.NATIVE_HOOK_MATCHER = exports.MCP_ADAPTER_VERSION = void 0;
exports.findHookSettingsPath = findHookSettingsPath;
exports.readHookSettings = readHookSettings;
exports.hasExactCommandHook = hasExactCommandHook;
exports.nativeHookConfigurationFingerprint = nativeHookConfigurationFingerprint;
exports.nativeHookEvidence = nativeHookEvidence;
exports.stableToolCorrelation = stableToolCorrelation;
exports.stablePromptCorrelation = stablePromptCorrelation;
exports.stableSessionWorkflowId = stableSessionWorkflowId;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
exports.MCP_ADAPTER_VERSION = '3.9.50';
exports.NATIVE_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow_).*';
exports.MCP_PACKAGE_SPEC = `@getmarrow/mcp@${exports.MCP_ADAPTER_VERSION}`;
exports.CONTEXT_HOOK_COMMAND = `npx -y ${exports.MCP_PACKAGE_SPEC} context-hook`;
exports.PRE_ACTION_HOOK_COMMAND = `npx -y ${exports.MCP_PACKAGE_SPEC} pre-action-hook`;
exports.ACTION_RESULT_HOOK_COMMAND = `npx -y ${exports.MCP_PACKAGE_SPEC} hook`;
exports.SESSION_END_HOOK_COMMAND = `npx -y ${exports.MCP_PACKAGE_SPEC} session-hook`;
exports.NATIVE_EXPECTED_HOOKS = ['prompt', 'pre_action', 'action_result', 'session_end'];
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
//# sourceMappingURL=hook-contract.js.map