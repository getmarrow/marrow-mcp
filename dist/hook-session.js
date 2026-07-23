"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SESSION_HOOK_COMMAND = void 0;
exports.installSessionEndHook = installSessionEndHook;
exports.runSessionHookCommand = runSessionHookCommand;
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const index_1 = require("./index");
exports.SESSION_HOOK_COMMAND = 'npx -y @getmarrow/mcp session-hook';
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
async function runSessionHookCommand() {
    if (process.env.MARROW_AUTO_HOOK === 'false')
        return;
    const resolved = (0, env_1.resolveMarrowEnv)();
    if (!resolved.apiKey)
        return;
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const sessionId = resolved.sessionId || undefined;
    const agentId = resolved.agentId || undefined;
    await (0, lifecycle_spool_1.recordLifecycleEvent)({
        apiKey: resolved.apiKey,
        baseUrl,
        event: {
            event_type: 'session_completed',
            harness: 'claude-code',
            agent_id: agentId,
            session_id: sessionId,
            action: 'agent session ended',
            outcome_state: 'pending',
        },
    });
    try {
        await (0, index_1.marrowSessionEnd)(resolved.apiKey, baseUrl, false, sessionId, agentId);
    }
    catch {
        // The pending lifecycle receipt remains durable for later reconciliation.
    }
}
//# sourceMappingURL=hook-session.js.map