"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SESSION_HOOK_COMMAND = void 0;
exports.installSessionEndHook = installSessionEndHook;
exports.runSessionHookCommand = runSessionHookCommand;
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const index_1 = require("./index");
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
exports.SESSION_HOOK_COMMAND = 'npx -y @getmarrow/mcp session-hook';
const MAX_HOOK_INPUT_BYTES = 64 * 1024;
const SESSION_END_TIMEOUT_MS = 900;
function readStopHookSource(input) {
    let value = input;
    if (value === undefined) {
        try {
            const raw = (0, node_fs_1.readFileSync)(0, 'utf8').slice(0, MAX_HOOK_INPUT_BYTES);
            value = raw.trim() ? JSON.parse(raw) : {};
        }
        catch {
            value = {};
        }
    }
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return {};
    const source = value;
    const take = (field) => {
        const candidate = typeof source[field] === 'string' ? String(source[field]).trim().slice(0, 1024) : '';
        return candidate || undefined;
    };
    return {
        session_id: take('session_id'),
        transcript_path: take('transcript_path'),
        cwd: take('cwd'),
        hook_event_name: take('hook_event_name'),
    };
}
function stopCorrelation(source, sessionId) {
    const stableSource = sessionId || JSON.stringify([
        source.session_id || '',
        source.transcript_path || '',
        source.cwd || '',
        source.hook_event_name || 'Stop',
    ]);
    return (0, node_crypto_1.createHash)('sha256').update(stableSource).digest('hex').slice(0, 32);
}
async function boundedSessionEnd(apiKey, baseUrl, sessionId, agentId) {
    const controller = new AbortController();
    let timeout;
    try {
        await Promise.race([
            (0, index_1.marrowSessionEnd)(apiKey, baseUrl, false, sessionId, agentId, controller.signal),
            new Promise((_resolve, reject) => {
                timeout = setTimeout(() => {
                    controller.abort();
                    reject(new Error('session end timeout'));
                }, SESSION_END_TIMEOUT_MS);
            }),
        ]);
    }
    finally {
        if (timeout)
            clearTimeout(timeout);
    }
}
function settingsPath(startDir) {
    const fs = require('fs');
    const path = require('path');
    let dir = startDir;
    while (true) {
        const candidate = path.join(dir, '.claude', 'settings.json');
        if (fs.existsSync(candidate) || fs.existsSync(path.join(dir, '.git')))
            return candidate;
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return path.join(startDir, '.claude', 'settings.json');
}
function installSessionEndHook(startDir = process.cwd()) {
    const fs = require('fs');
    const path = require('path');
    const target = settingsPath(startDir);
    const settings = fs.existsSync(target) && fs.readFileSync(target, 'utf8').trim()
        ? JSON.parse(fs.readFileSync(target, 'utf8'))
        : {};
    const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
        ? settings.hooks
        : {};
    const stop = Array.isArray(hooks.Stop) ? [...hooks.Stop] : [];
    const installed = stop.some((entry) => JSON.stringify(entry).includes(exports.SESSION_HOOK_COMMAND));
    if (!installed)
        stop.push({ hooks: [{ type: 'command', command: exports.SESSION_HOOK_COMMAND }] });
    settings.hooks = { ...hooks, Stop: stop };
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(settings, null, 2) + '\n');
    return { settingsPath: target, installed: !installed };
}
async function runSessionHookCommand(input) {
    if (process.env.MARROW_AUTO_HOOK === 'false')
        return;
    const resolved = (0, env_1.resolveMarrowEnv)();
    if (!resolved.apiKey)
        return;
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const source = readStopHookSource(input);
    const sessionId = resolved.sessionId || source.session_id || undefined;
    const agentId = resolved.agentId || undefined;
    const correlation = stopCorrelation(source, sessionId);
    await (0, lifecycle_spool_1.recordLifecycleEvent)({
        apiKey: resolved.apiKey,
        baseUrl,
        event: {
            event_id: `session-stop-${correlation}`,
            event_type: 'session_completed',
            harness: 'claude-code',
            agent_id: agentId,
            session_id: sessionId,
            workflow_id: `session-${correlation}`,
            correlation_id: correlation,
            observed_hook: 'session_end',
            action: 'agent session ended',
            outcome_state: 'pending',
        },
    });
    try {
        await boundedSessionEnd(resolved.apiKey, baseUrl, sessionId, agentId);
    }
    catch {
        // The pending lifecycle receipt remains durable for later reconciliation.
    }
}
//# sourceMappingURL=hook-session.js.map