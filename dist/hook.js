"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTO_HOOK_MATCHER = exports.AUTO_HOOK_COMMAND = void 0;
exports.shouldSkipAutoLog = shouldSkipAutoLog;
exports.deriveAction = deriveAction;
exports.deriveToolOutcome = deriveToolOutcome;
exports.installPostToolUseHook = installPostToolUseHook;
exports.runHookCommand = runHookCommand;
const index_1 = require("./index");
const habit_loop_copy_1 = require("./habit-loop-copy");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_pre_action_1 = require("./hook-pre-action");
const control_state_1 = require("./control-state");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
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
    return (0, hook_tool_policy_1.normalizeHookToolName)(toolName);
}
function shouldSkipAutoLog(event) {
    return (0, hook_tool_policy_1.isReadOnlyToolEvent)(event);
}
function deriveAction(event) {
    const toolName = getString(event.tool_name);
    if (!toolName || shouldSkipAutoLog(event))
        return null;
    if ((0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(event))
        return null;
    return (0, hook_pre_action_1.classifyTool)(event).action;
}
function deriveToolOutcome(event) {
    const response = event.tool_output ?? event.tool_response ?? event.tool_result;
    const responseRecord = asRecord(response);
    const errorValue = responseRecord?.error;
    const failed = event.hook_event_name === 'PostToolUseFailure'
        || event.error != null
        || event.error_message != null
        || event.failure_type != null
        || event.success === false
        || errorValue !== undefined && errorValue !== null
        || responseRecord?.is_error === true
        || responseRecord?.success === false
        || (typeof responseRecord?.exit_code === 'number' && responseRecord.exit_code !== 0)
        || /^(?:failed|error|blocked)$/i.test(String(responseRecord?.status || ''));
    const duration = typeof event.duration_ms === 'number' && Number.isFinite(event.duration_ms)
        ? Math.max(0, Math.min(300_000, Math.round(event.duration_ms)))
        : undefined;
    return { success: !failed, ...(duration === undefined ? {} : { duration_ms: duration }) };
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
    const settings = (0, hook_contract_1.readHookSettingsForInstall)(startDir);
    const hooks = asRecord(settings.hooks) || {};
    const success = (0, hook_contract_1.reconcileMarrowCommandHook)(settings, 'PostToolUse', 'hook', exports.AUTO_HOOK_COMMAND, exports.AUTO_HOOK_MATCHER);
    const failure = (0, hook_contract_1.reconcileMarrowCommandHook)(settings, 'PostToolUseFailure', 'hook', exports.AUTO_HOOK_COMMAND, exports.AUTO_HOOK_MATCHER);
    settings.hooks = {
        ...hooks,
        PostToolUse: success.entries,
        PostToolUseFailure: failure.entries,
    };
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    return {
        settingsPath,
        installed: success.changed || failure.changed,
    };
}
async function runHookCommand(input) {
    const identity = (0, hook_contract_1.resolveNativeHookIdentity)(process.argv[2]);
    if (process.env.MARROW_AUTO_HOOK === 'false') {
        if (identity.harness === 'gemini')
            process.stdout.write('{}');
        return;
    }
    try {
        if (!(0, control_state_1.readLocalControlState)().enabled) {
            if (identity.harness === 'gemini')
                process.stdout.write('{}');
            return;
        }
    }
    catch {
        if (identity.harness === 'gemini')
            process.stdout.write('{}');
        return;
    }
    try {
        let event;
        if (input === undefined) {
            const raw = (await readStdin()).trim();
            if (!raw)
                return;
            try {
                event = (0, hook_contract_1.normalizeHookEventPayload)(JSON.parse(raw));
            }
            catch {
                debug('[marrow-hook] skipped invalid JSON');
                return;
            }
        }
        else {
            event = (0, hook_contract_1.normalizeHookEventPayload)(input);
        }
        if (shouldSkipAutoLog(event)) {
            debug('[marrow-hook] skipped read-only tool');
            return;
        }
        const classified = (0, hook_pre_action_1.classifyTool)(event);
        const action = deriveAction(event);
        if (!action) {
            return;
        }
        const resolvedEnv = identity.environment;
        const apiKey = resolvedEnv.apiKey || '';
        if (!apiKey) {
            debug(`[marrow-hook] skipped missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
            return;
        }
        const baseUrl = (0, index_1.validateBaseUrl)(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
        const sessionId = resolvedEnv.sessionId || getString(event.session_id) || getString(event.conversation_id) || getString(event.task_id);
        const agentId = identity.agent_id;
        const { success } = deriveToolOutcome(event);
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
                ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                session_id: sessionId,
                workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, event.generation_id || event.tool_use_id || event.task_id),
                correlation_id: lifecycleCorrelation,
                action,
                target: classified.target,
                surfaces: classified.surfaces,
                risk_level: classified.risk,
                success,
                outcome_state: 'pending',
            },
        });
        if (identity.harness !== 'grok' && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
            const usage = (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_response)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_result)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_output)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event);
            if (usage && (usage.input_tokens || usage.output_tokens || usage.total_tokens || usage.cached_tokens)) {
                await (0, index_1.marrowModelUsage)(apiKey, baseUrl, {
                    ...usage,
                    source: 'mcp_post_tool_use',
                    marrow_intervention: 'passive_model_usage_capture',
                    success,
                    action_type: classified.type || 'tool',
                }, sessionId, agentId).catch(() => undefined);
            }
        }
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        debug(`[marrow-hook] ${message}`);
    }
    finally {
        if (identity.harness === 'gemini')
            process.stdout.write('{}');
    }
}
//# sourceMappingURL=hook.js.map