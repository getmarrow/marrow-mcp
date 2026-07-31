"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.classifyTool = classifyTool;
exports.preActionHookOutput = preActionHookOutput;
exports.installPreActionHook = installPreActionHook;
exports.runPreActionHookCommand = runPreActionHookCommand;
const index_1 = require("./index");
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
const MAX_INPUT_BYTES = 64 * 1024;
const RUNTIME_TIMEOUT_MS = 3000;
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
    const normalizedTool = (0, hook_tool_policy_1.normalizeHookToolName)(tool);
    const command = (0, hook_tool_policy_1.hookToolCommand)(event);
    const input = `${normalizedTool} ${command} ${JSON.stringify(event.tool_input || {})}`.toLowerCase();
    const readOnly = (0, hook_tool_policy_1.isReadOnlyToolEvent)(event);
    const protectedShellCommand = [
        /\b(?:npm|pnpm|yarn)\b[^\n;&|]{0,160}\b(?:publish|unpublish|deprecate|dist-tag\s+(?:add|rm)|owner\s+(?:add|rm)|access\s+set|token\s+(?:create|delete|revoke))\b/,
        /\bgit\b[^\n;&|]{0,240}\b(?:push|merge|commit|rebase|reset|tag)\b/,
        /\bgh\b[^\n;&|]{0,200}\b(?:pr\s+merge|release\s+(?:create|delete)|repo\s+(?:archive|delete)|api\b[^\n;&|]{0,100}(?:--method|-x)(?:=|\s+)(?:post|put|patch|delete))\b/,
        /\bkubectl\b[^\n;&|]{0,160}\b(?:apply|create|delete|edit|patch|replace|rollout|scale|set|drain|cordon|uncordon|taint|exec|cp)\b/,
        /\bterraform\b[^\n;&|]{0,160}\b(?:apply|destroy|import|taint|untaint|state\s+(?:mv|rm))\b/,
        /\bpulumi\b[^\n;&|]{0,160}\b(?:up|destroy|import|refresh|stack\s+rm)\b/,
        /\bhelm\b[^\n;&|]{0,160}\b(?:install|upgrade|uninstall|rollback)\b/,
        /\b(?:docker|podman)\b[^\n;&|]{0,160}\bpush\b/,
        /\bwrangler\b[^\n;&|]{0,240}\b(?:deploy|delete|rollback|execute|apply|put|bulk|secret)\b/,
        /\b(?:cargo\s+(?:publish|yank|owner)|twine\s+upload|gem\s+(?:push|yank|owner)|(?:dotnet\s+nuget|nuget)\s+(?:push|delete))\b/,
        /\bcurl\b[^\n;&|]{0,320}(?:-X\s*|--request(?:=|\s+))(?:POST|PUT|PATCH|DELETE)\b/i,
        /\b(?:http|xh)\b\s+(?:POST|PUT|PATCH|DELETE)\b/i,
        /\bcurl\b[^\n;&|]{0,320}(?:--data(?:-raw|-binary|-urlencode)?|-d|--form|-F)\b/,
        /\b(?:psql|mysql|sqlite3|duckdb)\b[^\n;&|]{0,320}\b(?:drop|delete|update|insert|alter|truncate|create|grant|revoke)\b/,
        /\bredis-cli\b[^\n;&|]{0,240}\b(?:del|set|mset|flushall|flushdb|shutdown|config\s+set|acl\s+setuser)\b/,
        /\baws\b[^\n;&|]{0,320}\b(?:s3\s+rm|s3api\s+delete|cloudformation\s+(?:deploy|delete)|secretsmanager\s+(?:create|put|update|delete|restore|rotate)|iam\s+(?:create|update|delete|attach|detach|put))\b/,
        /\bgcloud\b[^\n;&|]{0,320}\b(?:storage\s+rm|secrets\s+versions\s+(?:add|destroy|disable)|run\s+deploy|functions\s+deploy|projects\s+(?:add|remove)-iam-policy-binding)\b/,
        /\baz\b[^\n;&|]{0,320}\b(?:storage\b[^\n;&|]{0,80}\bdelete|keyvault\s+secret\s+(?:set|delete|backup|restore)|deployment\b[^\n;&|]{0,80}\b(?:create|delete))\b/,
        /\b(?:vault|op)\b[^\n;&|]{0,240}\b(?:write|put|patch|delete|edit|create|rotate|revoke|destroy)\b/,
    ].some((pattern) => pattern.test(command.toLowerCase()));
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
        || (String(event.tool_name || '').startsWith('mcp__') && !normalizedTool.startsWith('marrow_')));
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
function preActionHookOutput(result) {
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
        ? 'ask'
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
function emitDecision(result) {
    process.stdout.write(JSON.stringify(preActionHookOutput(result)));
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
    let event = input;
    if (event === undefined) {
        try {
            const raw = (await readStdin()).trim();
            event = raw ? JSON.parse(raw) : {};
        }
        catch {
            emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow rejected malformed or oversized pre-action input.' });
            return;
        }
    }
    const source = asRecord(event);
    if (!source?.tool_name) {
        emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow could not classify this mutation-capable tool request.' });
        return;
    }
    const classified = classifyTool(source);
    if (classified.readOnly) {
        process.stdout.write('{}');
        return;
    }
    const resolved = (0, env_1.resolveMarrowEnv)({ trustedOnly: true });
    if (!resolved.apiKey) {
        emitDecision({
            runtime: null,
            permit: null,
            protectedRisk: classified.protected,
            enforcementError: 'Marrow credentials are unavailable for this protected action. Restore the configured agent key before retrying.',
        });
        return;
    }
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const sessionId = resolved.sessionId || source.session_id;
    const agentId = resolved.agentId || undefined;
    const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
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
        const decision = await (0, index_1.marrowThink)(resolved.apiKey, baseUrl, {
            action: classified.action,
            target: classified.target,
            surfaces: classified.surfaces,
            type: classified.type,
            source_kind: 'integration',
            source_meta: {
                harness: 'claude-code',
                correlation_id: correlation,
                gate_receipt_id: runtime.gate_receipt?.id || runtime.gate_receipt_id || null,
            },
        }, sessionId, agentId, signal);
        const issued = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'issue',
            action: classified.action,
            action_type: classified.type,
            target: classified.target,
            correlation_id: correlation,
            harness: 'claude-code',
            decision_id: decision.decision_id,
            gate_receipt_id: runtime.gate_receipt?.id || runtime.gate_receipt_id || null,
            proof_requirements: runtime.proof_pack?.fields || [],
            surfaces: classified.surfaces,
        }, sessionId, agentId, signal);
        if (!issued.permit)
            return { runtime, permit: issued, protectedRisk: classified.protected, enforcementError: 'Marrow did not issue an action permit.' };
        const verified = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'verify',
            permit: issued.permit,
            action: classified.action,
            action_type: classified.type,
            target: classified.target,
            surfaces: classified.surfaces,
            correlation_id: correlation,
            harness: 'claude-code',
        }, sessionId, agentId, signal);
        return { runtime, permit: { ...issued, ...verified, permit: undefined }, protectedRisk: classified.protected };
    };
    const [result] = await Promise.all([withTimeout(control), lifecycle]);
    emitDecision(result || {
        runtime: null,
        permit: null,
        protectedRisk: classified.protected,
        enforcementError: 'Marrow governance timed out before this protected action. Retry instead of bypassing the gate.',
    });
}
//# sourceMappingURL=hook-pre-action.js.map