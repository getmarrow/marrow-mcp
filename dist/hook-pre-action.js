"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GOVERNED_WRAPPER_COMMAND = void 0;
exports.classifyTool = classifyTool;
exports.cursorPreActionHookOutput = cursorPreActionHookOutput;
exports.preActionHookOutput = preActionHookOutput;
exports.grokPreActionAdvisoryOutput = grokPreActionAdvisoryOutput;
exports.installPreActionHook = installPreActionHook;
exports.runPreActionHookCommand = runPreActionHookCommand;
const index_1 = require("./index");
const lifecycle_spool_1 = require("./lifecycle-spool");
const runtime_contract_1 = require("./runtime-contract");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 3000;
exports.GOVERNED_WRAPPER_COMMAND = 'npx @getmarrow/install run --agent <agent-id> -- -- <command>';
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
async function readStdin() {
    const chunks = [];
    let bytes = 0;
    process.stdin.resume();
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
    const normalizedTool = (0, hook_tool_policy_1.normalizeHookToolName)(tool);
    const command = (0, hook_tool_policy_1.hookToolCommand)(event);
    const input = `${normalizedTool} ${command} ${JSON.stringify(event.tool_input || {})}`.toLowerCase();
    const readOnly = (0, hook_tool_policy_1.isReadOnlyToolEvent)(event);
    const protectedShellCommand = (0, hook_tool_policy_1.isProtectedShellMutation)(command);
    const infrastructureDeployment = /\b(?:kubectl|terraform|pulumi|helm)\b/.test(command.toLowerCase())
        && protectedShellCommand;
    let type = 'process';
    if (/\b(?:publish|unpublish|deprecate)\b/.test(input))
        type = 'publish';
    else if (/\b(?:deploy|release|wrangler)\b/.test(input) || infrastructureDeployment)
        type = 'deploy';
    else if (/\b(?:merge|pull request|git push)\b/.test(input) || /\bgit\b[^\n;&|]{0,240}\bpush\b/.test(command.toLowerCase()))
        type = 'review';
    else if (/\b(?:migration|schema|database|d1)\b/.test(input))
        type = 'migration';
    else if (/\b(?:secret|credential|token|key|permission)\b/.test(input))
        type = 'audit';
    else if (/\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input))
        type = 'financial';
    const surfaces = [
        /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) || infrastructureDeployment ? 'production' : '',
        /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
        /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
        /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
        /\b(?:migration|schema|database|d1)\b/.test(input) ? 'database' : '',
        /\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input) ? 'financial' : '',
    ].filter(Boolean);
    const protectedAction = !readOnly && (/\b(?:deploy|release|publish|git\s+push|git\s+merge|gh\s+pr\s+merge|migration|migrate|secret|credential|rotate|revoke|payment|refund|charge|invoice|production|prod)\b/.test(input)
        || protectedShellCommand
        || ((0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) && !(0, hook_tool_policy_1.isOfficialMarrowMcpTool)(event.tool_name)));
    const risk = readOnly ? 'low' : protectedAction ? 'high' : 'medium';
    const target = surfaces.includes('npm') ? `npm:${type}`
        : surfaces.includes('github') ? `github:${type}`
            : surfaces.includes('production') ? `production:${type}`
                : surfaces.includes('database') ? `database:${type}`
                    : surfaces.includes('financial') ? `financial:${type}`
                        : surfaces.includes('secrets') ? `secrets:${type}`
                            : `workspace:${type}`;
    return {
        action: `classified ${tool} action: ${type} on ${surfaces.join(', ') || 'workspace'}`,
        target,
        type,
        role: type === 'publish' ? 'deploy' : ['deploy', 'review', 'migration', 'audit'].includes(type) ? type : 'general',
        surfaces: surfaces.length ? surfaces : ['workspace'],
        risk,
        protected: protectedAction,
        readOnly,
    };
}
function cursorPreActionHookOutput(result) {
    const { runtime, permit, protectedRisk } = result;
    const message = (value) => String(value || 'Marrow denied this action.')
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 500);
    if (protectedRisk && (!runtime || !permit?.verified)) {
        const denial = message(result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.');
        return {
            permission: 'deny',
            user_message: denial,
            agent_message: denial,
        };
    }
    const gate = runtime?.risk_gate;
    if (!gate)
        return { permission: 'allow' };
    const reason = runtime?.exact_next_action
        || gate.reasons?.[0]?.message
        || 'Marrow requires additional proof or operator review before this action.';
    if (gate.decision === 'review_required' || gate.decision === 'block' || gate.allow === false) {
        const denial = message(reason);
        return { permission: 'deny', user_message: denial, agent_message: denial };
    }
    return { permission: 'allow' };
}
function preActionHookOutput(result, harness = 'claude-code') {
    if (harness === 'cursor')
        return cursorPreActionHookOutput(result);
    const { runtime, permit, protectedRisk } = result;
    if (protectedRisk && (!runtime || !permit?.verified)) {
        return {
            hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'deny',
                permissionDecisionReason: result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.',
            },
        };
    }
    if (!runtime?.risk_gate) {
        return {};
    }
    const gate = runtime.risk_gate;
    const reason = runtime.exact_next_action
        || gate.reasons?.[0]?.message
        || 'Marrow requires additional proof or operator review before this action.';
    const permissionDecision = gate.decision === 'review_required'
        ? harness === 'codex' ? 'deny' : 'ask'
        : gate.decision === 'block' || gate.allow === false
            ? 'deny'
            : null;
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            ...(permissionDecision ? { permissionDecision, permissionDecisionReason: reason } : {}),
            ...(runtime.before_you_act || permit?.permit_id ? {
                additionalContext: [
                    runtime.before_you_act,
                    permit?.permit_id ? `Marrow action permit verified: ${permit.permit_id}. Evidence and outcome closure remain required.` : null,
                ].filter(Boolean).join('\n'),
            } : {}),
        },
    };
}
function emitDecision(result, harness = 'claude-code') {
    process.stdout.write(JSON.stringify(preActionHookOutput(result, harness)));
}
function grokPreActionAdvisoryOutput() {
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            additionalContext: [
                'This Grok hook is client-self-reported advisory context, not certified control or an enforcement boundary.',
                `Run consequential commands through the governed wrapper: ${exports.GOVERNED_WRAPPER_COMMAND}`,
            ].join('\n'),
        },
    };
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
    const settings = (0, hook_contract_1.readHookSettingsForInstall)(startDir);
    const hooks = asRecord(settings.hooks) || {};
    const reconciled = (0, hook_contract_1.reconcileMarrowCommandHook)(settings, 'PreToolUse', 'pre-action-hook', hook_contract_1.PRE_ACTION_HOOK_COMMAND, hook_contract_1.NATIVE_HOOK_MATCHER);
    settings.hooks = { ...hooks, PreToolUse: reconciled.entries };
    fs.mkdirSync(require('node:path').dirname(path), { recursive: true });
    fs.writeFileSync(path, JSON.stringify(settings, null, 2) + '\n');
    return { settingsPath: path, installed: reconciled.changed };
}
async function runPreActionHookCommand(input) {
    if (process.env.MARROW_AUTO_HOOK === 'false')
        return;
    const identity = (0, hook_contract_1.resolveNativeHookIdentity)(process.argv[2]);
    let event = input;
    if (event === undefined) {
        try {
            const raw = (await readStdin()).trim();
            event = raw ? (0, hook_contract_1.normalizeHookEventPayload)(JSON.parse(raw)) : {};
        }
        catch {
            emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow rejected malformed or oversized pre-action input.' }, identity.harness);
            return;
        }
    }
    const source = asRecord((0, hook_contract_1.normalizeHookEventPayload)(event));
    if (!source?.tool_name) {
        emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow could not classify this mutation-capable tool request.' }, identity.harness);
        return;
    }
    if ((0, hook_tool_policy_1.isOfficialMarrowMcpTool)(source.tool_name)) {
        process.stdout.write(JSON.stringify(identity.harness === 'cursor' ? { permission: 'allow' } : {}));
        return;
    }
    const classified = classifyTool(source);
    if (classified.readOnly) {
        process.stdout.write(JSON.stringify(identity.harness === 'cursor' ? { permission: 'allow' } : {}));
        return;
    }
    let resolved = identity.environment;
    const sessionId = resolved.sessionId || source.session_id || source.conversation_id;
    const agentId = identity.agent_id;
    const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
    if (identity.harness === 'grok') {
        if (resolved.apiKey) {
            try {
                const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
                await (0, lifecycle_spool_1.recordLifecycleEvent)({
                    apiKey: resolved.apiKey,
                    baseUrl,
                    event: {
                        event_id: `pretool-${correlation}`,
                        event_type: 'pre_action_checked',
                        ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                        session_id: sessionId,
                        workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, source.generation_id || source.tool_use_id),
                        correlation_id: correlation,
                        action: classified.action,
                        target: classified.target,
                        surfaces: classified.surfaces,
                        risk_level: classified.risk,
                        outcome_state: 'pending',
                    },
                }).catch(() => undefined);
            }
            catch {
                // Advisory output remains available when self-reported telemetry cannot be delivered.
            }
        }
        process.stdout.write(JSON.stringify(grokPreActionAdvisoryOutput()));
        return;
    }
    let baseUrl;
    try {
        baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    }
    catch {
        emitDecision({
            runtime: null,
            permit: null,
            protectedRisk: classified.protected,
            enforcementError: 'Marrow enforcement configuration is unavailable. Restore the trusted configuration before retrying this protected action.',
        }, identity.harness);
        return;
    }
    if (!resolved.apiKey) {
        emitDecision({
            runtime: null,
            permit: null,
            protectedRisk: classified.protected,
            enforcementError: 'Marrow credentials are unavailable for this protected action. Restore the configured agent key before retrying.',
        }, identity.harness);
        return;
    }
    const lifecycle = (0, lifecycle_spool_1.recordLifecycleEvent)({
        apiKey: resolved.apiKey,
        baseUrl,
        event: {
            event_id: `pretool-${correlation}`,
            event_type: 'pre_action_checked',
            ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
            session_id: sessionId,
            workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, source.generation_id || source.tool_use_id),
            correlation_id: correlation,
            action: classified.action,
            target: classified.target,
            surfaces: classified.surfaces,
            risk_level: classified.risk,
            outcome_state: 'pending',
        },
    }).catch(() => null);
    const control = async (signal) => {
        const runtime = await (0, index_1.marrowAgentRuntime)(resolved.apiKey, baseUrl, {
            action: classified.action,
            target: classified.target,
            type: classified.type,
            role: classified.role,
            surfaces: classified.surfaces,
        }, sessionId, agentId, signal);
        const gateReceiptId = (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtime);
        const decision = await (0, index_1.marrowThink)(resolved.apiKey, baseUrl, {
            action: classified.action,
            target: classified.target,
            surfaces: classified.surfaces,
            type: classified.type,
            source_kind: 'integration',
            source_meta: {
                harness: identity.harness,
                correlation_id: correlation,
                gate_receipt_id: gateReceiptId,
            },
        }, sessionId, agentId, signal);
        const issued = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'issue',
            action: classified.action,
            action_type: classified.type,
            target: classified.target,
            correlation_id: correlation,
            harness: identity.harness,
            decision_id: decision.decision_id,
            gate_receipt_id: gateReceiptId,
            proof_requirements: runtime.proof_pack?.fields || [],
            surfaces: classified.surfaces,
        }, sessionId, agentId, signal);
        const issuedPermitId = typeof issued.permit_id === 'string' ? issued.permit_id.trim() : '';
        if (!issued.permit || !issuedPermitId) {
            return { runtime, permit: { ...issued, verified: false }, protectedRisk: classified.protected, enforcementError: 'Marrow did not issue a complete action permit.' };
        }
        const verified = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'verify',
            permit: issued.permit,
            action: classified.action,
            action_type: classified.type,
            target: classified.target,
            surfaces: classified.surfaces,
            correlation_id: correlation,
            harness: identity.harness,
        }, sessionId, agentId, signal);
        const verifiedPermitId = typeof verified.permit_id === 'string' ? verified.permit_id.trim() : '';
        const verifiedExactly = verified.verified === true && verifiedPermitId === issuedPermitId;
        return {
            runtime,
            permit: { ...issued, ...verified, permit_id: issuedPermitId, permit: undefined, verified: verifiedExactly },
            protectedRisk: classified.protected,
            ...(verifiedExactly ? {} : { enforcementError: 'Marrow permit verification did not match the issued permit.' }),
        };
    };
    const [result] = await Promise.all([withTimeout(control), lifecycle]);
    emitDecision(result || {
        runtime: null,
        permit: null,
        protectedRisk: classified.protected,
        enforcementError: 'Marrow governance timed out before this protected action. Retry instead of bypassing the gate.',
    }, identity.harness);
}
//# sourceMappingURL=hook-pre-action.js.map