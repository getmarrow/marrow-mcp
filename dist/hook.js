"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTO_HOOK_MATCHER = exports.AUTO_HOOK_COMMAND = void 0;
exports.shouldSkipAutoLog = shouldSkipAutoLog;
exports.deriveAction = deriveAction;
exports.deriveToolOutcome = deriveToolOutcome;
exports.installPostToolUseHook = installPostToolUseHook;
exports.hookSpooledLifecycleEvent = hookSpooledLifecycleEvent;
exports.runHookCommand = runHookCommand;
exports.runPermissionRequestHookCommand = runPermissionRequestHookCommand;
exports.installPermissionRequestHook = installPermissionRequestHook;
const node_crypto_1 = require("node:crypto");
const codex_native_usage_1 = require("./codex-native-usage");
const index_1 = require("./index");
const habit_loop_copy_1 = require("./habit-loop-copy");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_pre_action_1 = require("./hook-pre-action");
const control_state_1 = require("./control-state");
const hook_tool_policy_1 = require("./hook-tool-policy");
const session_loop_guard_1 = require("./session-loop-guard");
const host_approval_1 = require("./host-approval");
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
    // A host that does not report the result (Cursor's after-execution events): unknown, unless it says it failed.
    const unknown = !failed && event.outcome_unknown === true;
    return { success: !failed, ...(unknown ? { unknown: true } : {}), ...(duration === undefined ? {} : { duration_ms: duration }) };
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
let spooledLifecycleEvent = false;
/** True only when the latest runHookCommand call spooled an event for background delivery. */
function hookSpooledLifecycleEvent() {
    return spooledLifecycleEvent;
}
function holdContextFor(identity, event, sessionIdOverride) {
    const apiKey = identity.environment.apiKey || '';
    if (!apiKey)
        return null;
    let baseUrl;
    try {
        baseUrl = (0, index_1.validateBaseUrl)(identity.environment.baseUrl || 'https://api.getmarrow.ai');
    }
    catch {
        return null;
    }
    const sessionId = sessionIdOverride || identity.environment.sessionId || getString(event.session_id) || getString(event.conversation_id)
        || getString(event.task_id) || (0, hook_contract_1.stableSessionWorkflowId)(undefined, [identity.harness, process.cwd()]);
    return {
        apiKey,
        baseUrl,
        sessionId,
        agentId: identity.agent_id,
        harness: identity.harness,
        host: (0, host_approval_1.approvalHostFor)(identity.harness),
        hostSessionId: (0, host_approval_1.hostSessionIdFor)([event.session_id, event.conversation_id, event.task_id], sessionId),
    };
}
/** Model-facing context for a held call that ran (never contains an approval code). */
let heldActionContext = null;
let lastHookEventName = null;
function emitHeldActionContext(identity, eventName) {
    const text = heldActionContext;
    heldActionContext = null;
    if (!text || !['claude-code', 'codex', 'mcp-client'].includes(identity.harness))
        return;
    process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
            hookEventName: eventName === 'PostToolUseFailure' ? 'PostToolUseFailure' : 'PostToolUse',
            additionalContext: text,
        },
    }));
}
async function runHookCommand(input) {
    spooledLifecycleEvent = false;
    heldActionContext = null;
    lastHookEventName = null;
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
        lastHookEventName = event.hook_event_name;
        const resolvedEnv = identity.environment;
        if (identity.harness === 'codex' && resolvedEnv.apiKey && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
            const context = (0, habit_loop_copy_1.modelUsageCaptureContextFromEnv)();
            const supplied = (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_response, context)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_result, context)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_output, context)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event, context);
            if (!supplied)
                await (0, codex_native_usage_1.captureCodexNativeUsage)(event, resolvedEnv.apiKey, (0, index_1.validateBaseUrl)(resolvedEnv.baseUrl || 'https://api.getmarrow.ai'), identity.agent_id);
        }
        if (event.hook_event_name === 'PostToolBatch') {
            // Claude Code, installed async: decides still-open asked calls of the batch.
            const batchContext = holdContextFor(identity, event);
            if (batchContext) {
                await (0, host_approval_1.settleToolBatch)(batchContext, { toolCalls: event.tool_calls, transcriptPath: event.transcript_path });
                await (0, host_approval_1.flushHoldOutbox)(batchContext);
            }
            return;
        }
        if ((0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(event)) {
            return;
        }
        const privateLoopPayload = (0, hook_contract_1.privateHookLoopGuardPayload)(event);
        const classified = (0, hook_pre_action_1.classifyTool)(event);
        const sessionId = resolvedEnv.sessionId || getString(event.session_id) || getString(event.conversation_id) || getString(event.task_id)
            || (0, hook_contract_1.stableSessionWorkflowId)(undefined, [identity.harness, process.cwd()]);
        const agentId = identity.agent_id;
        const outcome = deriveToolOutcome(event);
        const loopOperation = {
            sessionId,
            agentId,
            harness: identity.harness,
            toolName: event.tool_name,
            toolInput: privateLoopPayload.toolInput ?? event.tool_input,
            invocationId: event.tool_use_id,
            readOnly: classified.readOnly,
        };
        try {
            (0, session_loop_guard_1.recordSessionLoopOutcome)(loopOperation, outcome.success, privateLoopPayload.toolResult ?? event.tool_output ?? event.tool_response ?? event.tool_result
                ?? { success: event.success, error: event.error, failure_type: event.failure_type });
        }
        catch {
            debug('[marrow-hook] local loop guard state is unsafe');
        }
        // A held call that ran: the operator allowed it in the host prompt, or a
        // waited hold was approved and retried. Report and close, or hand off.
        const heldContext = holdContextFor(identity, event, sessionId);
        if (heldContext) {
            const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...event, session_id: sessionId });
            const handoff = await (0, host_approval_1.settleAfterTool)(heldContext, {
                correlation,
                toolUseId: getString(event.tool_use_id) || null,
                generationId: getString(event.generation_id) || null,
                success: outcome.unknown ? null : outcome.success,
            }).catch(() => null);
            if (handoff)
                heldActionContext = handoff;
            // Resend due queued reports only when this call did no held-call work (hook time limits).
            else
                await (0, host_approval_1.flushHoldOutbox)(heldContext, 1, 2_000).catch(() => undefined);
        }
        if (shouldSkipAutoLog(event)) {
            debug('[marrow-hook] recorded read-only result locally; skipped network event');
            return;
        }
        const action = deriveAction(event);
        if (!action)
            return;
        const apiKey = resolvedEnv.apiKey || '';
        if (!apiKey) {
            debug(`[marrow-hook] skipped missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
            return;
        }
        const baseUrl = (0, index_1.validateBaseUrl)(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
        const { success } = outcome;
        const toolName = normalizeToolName(getString(event.tool_name) || 'tool');
        const eventType = toolName === 'bash'
            ? success ? 'command_completed' : 'command_failed'
            : success ? 'tool_completed' : 'tool_failed';
        const lifecycleCorrelation = (0, hook_contract_1.stableToolCorrelation)({ ...event, session_id: sessionId });
        // One record per attempt: the same action run again in a session is a new attempt.
        const attemptSource = getString(event.tool_use_id) || getString(event.generation_id);
        const attempt = (0, node_crypto_1.createHash)('sha256').update(attemptSource || (0, node_crypto_1.randomUUID)()).digest('hex').slice(0, 12);
        // Spool only: PostToolUse runs on every tool call, so it must add ~no latency.
        // cli.ts launches a detached background nudge that delivers the spooled event.
        // With the nudge disabled (MARROW_HOOK_BACKGROUND_NUDGE=false) keep bounded inline delivery.
        const deferred = (0, lifecycle_spool_1.backgroundNudgeEnabled)();
        const receipt = await (0, lifecycle_spool_1.recordLifecycleEvent)({
            apiKey,
            baseUrl,
            deferDelivery: deferred,
            event: {
                event_id: `posttool-${lifecycleCorrelation}-${attempt}`,
                event_type: outcome.unknown ? 'tool_completed' : eventType,
                ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                session_id: sessionId,
                workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, event.generation_id || event.tool_use_id || event.task_id),
                correlation_id: lifecycleCorrelation,
                action,
                target: classified.target,
                surfaces: classified.surfaces,
                risk_level: classified.risk,
                // An unknown result is recorded as unknown, never as a success.
                ...(outcome.unknown ? { outcome_state: 'unknown' } : { success, outcome_state: 'pending' }),
            },
        });
        spooledLifecycleEvent = deferred && receipt.queued;
        if (identity.harness !== 'grok' && process.env.MARROW_PASSIVE_TOKEN_USAGE !== 'false') {
            const capture = (0, habit_loop_copy_1.modelUsageCaptureContextFromEnv)();
            const usage = (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_response, capture)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_result, capture)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event.tool_output, capture)
                || (0, habit_loop_copy_1.extractModelUsageFromUnknown)(event, capture);
            if (usage) {
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
        else
            emitHeldActionContext(identity, lastHookEventName);
    }
}
/**
 * Claude Code PermissionRequest, pass-through: notes that the host is about to
 * show its own permission dialog for an asked (held) call. It never prints a
 * decision, so it cannot answer the dialog; setup installs it with async: true.
 * PermissionRequest input has no tool_use_id, so the call is matched on the
 * session, the tool name and the tool input.
 */
async function runPermissionRequestHookCommand(input) {
    try {
        if (process.env.MARROW_AUTO_HOOK === 'false')
            return;
        try {
            if (!(0, control_state_1.readLocalControlState)().enabled)
                return;
        }
        catch {
            return;
        }
        const identity = (0, hook_contract_1.resolveNativeHookIdentity)(process.argv[2]);
        let event;
        if (input === undefined) {
            const raw = (await readStdin()).trim();
            if (!raw || raw.length > 4 * 1024 * 1024)
                return;
            event = (0, hook_contract_1.normalizeHookEventPayload)(JSON.parse(raw));
        }
        else {
            event = (0, hook_contract_1.normalizeHookEventPayload)(input);
        }
        if (event.hook_event_name !== undefined && event.hook_event_name !== 'PermissionRequest')
            return;
        if (!getString(event.tool_name))
            return;
        const context = holdContextFor(identity, event);
        if (!context || context.host !== 'claude-code')
            return;
        (0, host_approval_1.noteDialogShown)(context, (0, hook_contract_1.stableToolCorrelation)({ ...event, session_id: context.sessionId }));
    }
    catch {
        debug('[marrow-hook] permission request marker was not recorded');
    }
}
function installPermissionRequestHook(startDir = process.cwd()) {
    const fs = require('fs');
    const path = require('path');
    const settingsPath = (0, hook_contract_1.findHookSettingsPath)(startDir);
    const settings = (0, hook_contract_1.readHookSettingsForInstall)(startDir);
    const hooks = asRecord(settings.hooks) || {};
    // async: the marker never delays or answers the dialog. PostToolBatch runs
    // the result hook in the background to settle declines.
    const permission = (0, hook_contract_1.reconcileMarrowCommandHook)(settings, 'PermissionRequest', 'permission-request-hook', hook_contract_1.PERMISSION_REQUEST_HOOK_COMMAND, exports.AUTO_HOOK_MATCHER, { async: true });
    const batch = (0, hook_contract_1.reconcileMarrowCommandHook)(settings, 'PostToolBatch', 'hook', exports.AUTO_HOOK_COMMAND, undefined, { async: true });
    settings.hooks = {
        ...hooks,
        PermissionRequest: permission.entries,
        PostToolBatch: batch.entries,
    };
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    return { settingsPath, installed: permission.changed || batch.changed };
}
//# sourceMappingURL=hook.js.map