"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WINDSURF_SESSION_END_HOOK_COMMAND = exports.WINDSURF_ACTION_RESULT_HOOK_COMMAND = exports.WINDSURF_PRE_ACTION_HOOK_COMMAND = exports.CLINE_SESSION_END_HOOK_COMMAND = exports.CLINE_ACTION_RESULT_HOOK_COMMAND = exports.CLINE_PRE_ACTION_HOOK_COMMAND = exports.CURSOR_SESSION_END_HOOK_COMMAND = exports.CURSOR_ACTION_RESULT_HOOK_COMMAND = exports.CURSOR_PRE_ACTION_HOOK_COMMAND = exports.GROK_SESSION_END_HOOK_COMMAND = exports.GROK_ACTION_RESULT_HOOK_COMMAND = exports.GROK_PRE_ACTION_HOOK_COMMAND = exports.GROK_CONTEXT_HOOK_COMMAND = exports.SESSION_END_HOOK_COMMAND = exports.ACTION_RESULT_HOOK_COMMAND = exports.PRE_ACTION_HOOK_COMMAND = exports.CONTEXT_HOOK_COMMAND = exports.MCP_PACKAGE_SPEC = exports.GROK_NATIVE_HOOK_MATCHER = exports.NATIVE_HOOK_MATCHER = exports.MCP_ADAPTER_VERSION = void 0;
exports.resolveNativeHookIdentity = resolveNativeHookIdentity;
exports.clientReportedHookLifecycleIdentity = clientReportedHookLifecycleIdentity;
exports.normalizeHookEventPayload = normalizeHookEventPayload;
exports.findHookSettingsPath = findHookSettingsPath;
exports.readHookSettings = readHookSettings;
exports.readHookSettingsForInstall = readHookSettingsForInstall;
exports.reconcileMarrowCommandHook = reconcileMarrowCommandHook;
exports.hasExactCommandHook = hasExactCommandHook;
exports.localHookConfigurationFingerprint = localHookConfigurationFingerprint;
exports.stableToolCorrelation = stableToolCorrelation;
exports.stablePromptCorrelation = stablePromptCorrelation;
exports.stableSessionWorkflowId = stableSessionWorkflowId;
exports.grokHookSettingsPath = grokHookSettingsPath;
exports.installGrokNativeHooks = installGrokNativeHooks;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const env_1 = require("./env");
exports.MCP_ADAPTER_VERSION = '3.9.75';
exports.NATIVE_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*';
exports.GROK_NATIVE_HOOK_MATCHER = 'run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video';
exports.MCP_PACKAGE_SPEC = `@getmarrow/mcp@${exports.MCP_ADAPTER_VERSION}`;
const hookCommand = (entrypoint) => `npx -y --package=${exports.MCP_PACKAGE_SPEC} marrow-mcp ${entrypoint}`;
exports.CONTEXT_HOOK_COMMAND = hookCommand('claude-context-hook');
exports.PRE_ACTION_HOOK_COMMAND = hookCommand('claude-pre-action-hook');
exports.ACTION_RESULT_HOOK_COMMAND = hookCommand('claude-hook');
exports.SESSION_END_HOOK_COMMAND = hookCommand('claude-session-hook');
exports.GROK_CONTEXT_HOOK_COMMAND = hookCommand('grok-context-hook');
exports.GROK_PRE_ACTION_HOOK_COMMAND = hookCommand('grok-pre-action-hook');
exports.GROK_ACTION_RESULT_HOOK_COMMAND = hookCommand('grok-hook');
exports.GROK_SESSION_END_HOOK_COMMAND = hookCommand('grok-session-hook');
exports.CURSOR_PRE_ACTION_HOOK_COMMAND = hookCommand('cursor-pre-action-hook');
exports.CURSOR_ACTION_RESULT_HOOK_COMMAND = hookCommand('cursor-hook');
exports.CURSOR_SESSION_END_HOOK_COMMAND = hookCommand('cursor-session-hook');
exports.CLINE_PRE_ACTION_HOOK_COMMAND = hookCommand('cline-pre-action-hook');
exports.CLINE_ACTION_RESULT_HOOK_COMMAND = hookCommand('cline-hook');
exports.CLINE_SESSION_END_HOOK_COMMAND = hookCommand('cline-session-hook');
exports.WINDSURF_PRE_ACTION_HOOK_COMMAND = hookCommand('windsurf-pre-action-hook');
exports.WINDSURF_ACTION_RESULT_HOOK_COMMAND = hookCommand('windsurf-hook');
exports.WINDSURF_SESSION_END_HOOK_COMMAND = hookCommand('windsurf-session-hook');
const LOCAL_CONFIGURED_HOOK_STAGES = ['prompt', 'pre_action', 'action_result', 'session_end'];
const RECOGNIZED_NATIVE_ENTRYPOINTS = {
    'claude-context-hook': 'claude-code',
    'claude-pre-action-hook': 'claude-code',
    'claude-hook': 'claude-code',
    'claude-session-hook': 'claude-code',
    'codex-context-hook': 'codex',
    'codex-pre-action-hook': 'codex',
    'codex-hook': 'codex',
    'codex-session-hook': 'codex',
    'grok-context-hook': 'grok',
    'grok-pre-action-hook': 'grok',
    'grok-hook': 'grok',
    'grok-session-hook': 'grok',
    'cursor-pre-action-hook': 'cursor',
    'cursor-hook': 'cursor',
    'cursor-session-hook': 'cursor',
    'cline-pre-action-hook': 'cline',
    'cline-hook': 'cline',
    'cline-session-hook': 'cline',
    'windsurf-pre-action-hook': 'windsurf',
    'windsurf-hook': 'windsurf',
    'windsurf-session-hook': 'windsurf',
};
/**
 * Label client-reported hook activity from the public CLI entrypoint. The
 * entrypoint is not host provenance and cannot certify coverage. Hook JSON is
 * deliberately not an identity input, and the authenticated service remains
 * authoritative for the credential-bound agent identity.
 */
function resolveNativeHookIdentity(entrypoint, options = {}) {
    const recognizedHarness = RECOGNIZED_NATIVE_ENTRYPOINTS[String(entrypoint || '').trim()];
    const harness = recognizedHarness || 'mcp-client';
    const environment = (0, env_1.resolveMarrowEnv)({ ...options, trustedOnly: true });
    const candidateAgentId = String(environment.agentId || '').trim();
    const agentId = /^[A-Za-z0-9._:-]{1,128}$/.test(candidateAgentId) ? candidateAgentId : undefined;
    return {
        harness,
        identity_source: recognizedHarness ? 'public_cli_entrypoint' : 'generic_fallback',
        client_self_reported: true,
        ...(agentId ? { agent_id: agentId } : {}),
        environment: { ...environment, agentId },
    };
}
function clientReportedHookLifecycleIdentity(identity) {
    return {
        harness: identity.harness,
        ...(identity.agent_id ? { agent_id: identity.agent_id } : {}),
        source: 'client_self_reported',
    };
}
const HOOK_CAMEL_TO_SNAKE = {
    hookEventName: 'hook_event_name',
    sessionId: 'session_id',
    toolName: 'tool_name',
    toolInput: 'tool_input',
    toolResponse: 'tool_response',
    toolResult: 'tool_result',
    toolOutput: 'tool_output',
    toolUseId: 'tool_use_id',
    conversationId: 'conversation_id',
    generationId: 'generation_id',
    errorMessage: 'error_message',
    failureType: 'failure_type',
    durationMs: 'duration_ms',
    eventName: 'hook_event_name',
    transcriptPath: 'transcript_path',
    taskId: 'task_id',
    hookName: 'hook_event_name',
};
const CURSOR_EVENT_NAMES = {
    preToolUse: 'PreToolUse',
    postToolUse: 'PostToolUse',
    postToolUseFailure: 'PostToolUseFailure',
    stop: 'Stop',
};
function boundedCorrelationId(value) {
    const candidate = typeof value === 'string' ? value.trim().slice(0, 128) : '';
    return candidate && /^[A-Za-z0-9._:-]+$/.test(candidate) ? candidate : undefined;
}
function boundedWindsurfName(value) {
    const candidate = typeof value === 'string' ? value.trim().slice(0, 128) : '';
    return candidate && /^[A-Za-z0-9._:-]+$/.test(candidate) ? candidate : undefined;
}
function normalizeWindsurfHookEvent(source) {
    const action = typeof source.agent_action_name === 'string' ? source.agent_action_name.trim() : '';
    const supported = new Set([
        'pre_write_code', 'pre_run_command', 'pre_mcp_tool_use',
        'post_write_code', 'post_run_command', 'post_mcp_tool_use',
        'post_cascade_response',
    ]);
    if (!supported.has(action))
        return {};
    const info = source.tool_info && typeof source.tool_info === 'object' && !Array.isArray(source.tool_info)
        ? source.tool_info
        : {};
    const normalized = { hook_event_name: action };
    const trajectoryId = boundedCorrelationId(source.trajectory_id);
    const executionId = boundedCorrelationId(source.execution_id);
    if (trajectoryId)
        normalized.session_id = trajectoryId;
    if (executionId)
        normalized.tool_use_id = executionId;
    if (action.endsWith('_run_command')) {
        normalized.tool_name = 'Bash';
        const command = typeof info.command_line === 'string' ? info.command_line.slice(0, 8192) : '';
        normalized.tool_input = { command };
    }
    else if (action.endsWith('_write_code')) {
        normalized.tool_name = 'Write';
        normalized.tool_input = {};
    }
    else if (action.endsWith('_mcp_tool_use')) {
        const server = boundedWindsurfName(info.mcp_server_name) || 'unknown';
        const tool = boundedWindsurfName(info.mcp_tool_name) || 'unknown';
        normalized.tool_name = server.toLowerCase() === 'marrow' && /^marrow_[a-z0-9_]+$/i.test(tool)
            ? `mcp__marrow__${tool}`
            : `MCP:${server}:${tool}`;
        normalized.tool_input = {};
    }
    if (action.startsWith('post_') && action !== 'post_cascade_response')
        normalized.success = true;
    return normalized;
}
function normalizeHookEventPayload(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return {};
    const source = value;
    if (typeof source.agent_action_name === 'string')
        return normalizeWindsurfHookEvent(source);
    const normalized = { ...source };
    for (const [camel, snake] of Object.entries(HOOK_CAMEL_TO_SNAKE)) {
        if (normalized[snake] == null && normalized[camel] != null)
            normalized[snake] = normalized[camel];
    }
    const clinePre = source.preToolUse && typeof source.preToolUse === 'object' && !Array.isArray(source.preToolUse)
        ? source.preToolUse
        : null;
    const clinePost = source.postToolUse && typeof source.postToolUse === 'object' && !Array.isArray(source.postToolUse)
        ? source.postToolUse
        : null;
    const clineTool = clinePre || clinePost;
    if (clineTool) {
        if (normalized.tool_name == null)
            normalized.tool_name = clineTool.toolName ?? clineTool.tool_name;
        if (normalized.tool_input == null)
            normalized.tool_input = clineTool.parameters;
        if (normalized.tool_result == null)
            normalized.tool_result = clineTool.result;
        if (normalized.success == null)
            normalized.success = clineTool.success;
        if (normalized.duration_ms == null)
            normalized.duration_ms = clineTool.durationMs ?? clineTool.duration_ms;
        if (normalized.hook_event_name == null)
            normalized.hook_event_name = clinePre ? 'PreToolUse' : 'PostToolUse';
    }
    if (normalized.hook_event_name == null && typeof normalized.event === 'string') {
        normalized.hook_event_name = normalized.event;
    }
    if (typeof normalized.hook_event_name === 'string') {
        normalized.hook_event_name = CURSOR_EVENT_NAMES[normalized.hook_event_name] || normalized.hook_event_name;
    }
    for (const field of ['session_id', 'tool_use_id', 'conversation_id', 'generation_id', 'task_id']) {
        const bounded = boundedCorrelationId(normalized[field]);
        if (bounded)
            normalized[field] = bounded;
        else
            delete normalized[field];
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
    const match = command.trim().match(/^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+(?:(?:claude|cline|codex|cursor|grok|windsurf)-)?(context-hook|pre-action-hook|hook|session-hook)$/);
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
function localHookConfigurationFingerprint(startDir = process.cwd()) {
    const settings = readHookSettings(startDir);
    const contract = {
        schema: 'marrow-claude-native-hooks.v3',
        adapter_version: exports.MCP_ADAPTER_VERSION,
        configured_stages: LOCAL_CONFIGURED_HOOK_STAGES,
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
    const command = (subcommand) => (subcommand === 'context-hook' ? exports.GROK_CONTEXT_HOOK_COMMAND
        : subcommand === 'pre-action-hook' ? exports.GROK_PRE_ACTION_HOOK_COMMAND
            : subcommand === 'session-hook' ? exports.GROK_SESSION_END_HOOK_COMMAND
                : exports.GROK_ACTION_RESULT_HOOK_COMMAND);
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