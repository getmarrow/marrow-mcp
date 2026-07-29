"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.preActionHookOutput = preActionHookOutput;
exports.installPreActionHook = installPreActionHook;
exports.runPreActionHookCommand = runPreActionHookCommand;
const index_1 = require("./index");
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_contract_1 = require("./hook-contract");
const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 900;
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
async function readStdin() {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of process.stdin) {
        const buffer = Buffer.from(chunk);
        bytes += buffer.length;
        if (bytes > MAX_INPUT_BYTES)
            throw new Error('pre-action hook input exceeds byte limit');
        chunks.push(buffer);
    }
    return Buffer.concat(chunks).toString('utf8');
}
function classifyTool(event) {
    const tool = String(event.tool_name || 'tool').slice(0, 64);
    const input = JSON.stringify(event.tool_input || {}).toLowerCase();
    let type = 'process';
    if (/\b(?:deploy|release|publish|wrangler)\b/.test(input))
        type = 'deploy';
    else if (/\b(?:merge|pull request|git push)\b/.test(input))
        type = 'review';
    else if (/\b(?:migration|schema|database|d1)\b/.test(input))
        type = 'migration';
    else if (/\b(?:secret|credential|token|key|permission)\b/.test(input))
        type = 'audit';
    const surfaces = [
        /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) ? 'production' : '',
        /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
        /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
        /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
    ].filter(Boolean);
    const risk = surfaces.includes('production') || surfaces.includes('secrets') ? 'high' : 'medium';
    return {
        action: `classified ${tool} action: ${type} on ${surfaces.join(', ') || 'workspace'}`,
        type,
        role: ['deploy', 'review', 'migration', 'audit'].includes(type) ? type : 'general',
        surfaces: surfaces.length ? surfaces : ['workspace'],
        risk,
    };
}
function preActionHookOutput(runtime) {
    if (!runtime?.risk_gate) {
        return {};
    }
    const gate = runtime.risk_gate;
    const reason = runtime.exact_next_action
        || gate.reasons?.[0]?.message
        || 'Marrow requires additional proof or operator review before this action.';
    const permissionDecision = gate.allow === false || gate.decision === 'block'
        ? 'deny'
        : gate.decision === 'review_required'
            ? 'ask'
            : null;
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            ...(permissionDecision ? { permissionDecision, permissionDecisionReason: reason } : {}),
            ...(runtime.before_you_act ? { additionalContext: runtime.before_you_act } : {}),
        },
    };
}
function emitDecision(runtime) {
    process.stdout.write(JSON.stringify(preActionHookOutput(runtime)));
}
async function withTimeout(operation) {
    const controller = new AbortController();
    let timer;
    try {
        return await Promise.race([
            operation(controller.signal),
            new Promise((resolve) => {
                timer = setTimeout(() => {
                    controller.abort();
                    resolve(null);
                }, RUNTIME_TIMEOUT_MS);
            }),
        ]);
    }
    catch {
        return null;
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
function installPreActionHook(startDir = process.cwd()) {
    const fs = require('node:fs');
    const path = (0, hook_contract_1.findHookSettingsPath)(startDir);
    const settings = (0, hook_contract_1.readHookSettings)(startDir);
    const hooks = asRecord(settings.hooks) || {};
    const preToolUse = Array.isArray(hooks.PreToolUse) ? [...hooks.PreToolUse] : [];
    const installed = (0, hook_contract_1.hasExactCommandHook)(settings, 'PreToolUse', hook_contract_1.PRE_ACTION_HOOK_COMMAND, hook_contract_1.NATIVE_HOOK_MATCHER);
    if (!installed) {
        preToolUse.push({
            matcher: hook_contract_1.NATIVE_HOOK_MATCHER,
            hooks: [{ type: 'command', command: hook_contract_1.PRE_ACTION_HOOK_COMMAND }],
        });
    }
    settings.hooks = { ...hooks, PreToolUse: preToolUse };
    fs.mkdirSync(require('node:path').dirname(path), { recursive: true });
    fs.writeFileSync(path, JSON.stringify(settings, null, 2) + '\n');
    return { settingsPath: path, installed: !installed };
}
async function runPreActionHookCommand(input) {
    if (process.env.MARROW_AUTO_HOOK === 'false')
        return;
    let event = input;
    if (event === undefined) {
        try {
            const raw = (await readStdin()).trim();
            event = raw ? JSON.parse(raw) : {};
        }
        catch {
            process.stdout.write('{}');
            return;
        }
    }
    const source = asRecord(event);
    if (!source?.tool_name) {
        process.stdout.write('{}');
        return;
    }
    const resolved = (0, env_1.resolveMarrowEnv)();
    if (!resolved.apiKey) {
        process.stdout.write('{}');
        return;
    }
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const sessionId = resolved.sessionId || source.session_id;
    const agentId = resolved.agentId || undefined;
    const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
    const classified = classifyTool(source);
    const lifecycle = (0, lifecycle_spool_1.recordLifecycleEvent)({
        apiKey: resolved.apiKey,
        baseUrl,
        event: {
            event_id: `pretool-${correlation}`,
            event_type: 'pre_action_checked',
            harness: 'claude-code',
            agent_id: agentId,
            session_id: sessionId,
            workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, source.tool_use_id),
            correlation_id: correlation,
            ...(0, hook_contract_1.nativeHookEvidence)('pre_action'),
            action: classified.action,
            risk_level: classified.risk,
            outcome_state: 'pending',
        },
    }).catch(() => null);
    const runtime = (signal) => (0, index_1.marrowAgentRuntime)(resolved.apiKey, baseUrl, {
        action: classified.action,
        type: classified.type,
        role: classified.role,
        surfaces: classified.surfaces,
    }, sessionId, agentId, signal);
    const [result] = await Promise.all([withTimeout(runtime), lifecycle]);
    emitDecision(result);
}
//# sourceMappingURL=hook-pre-action.js.map