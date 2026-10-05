"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DENIED_DECISION_CLOSE_TIMEOUT_MS = exports.HOLD_OWNER_DENIAL = exports.PreActionControlTimeoutError = exports.PRE_ACTION_CONTROL_TIMEOUT_MS = exports.MAX_PRE_ACTION_INPUT_BYTES = exports.MARROW_OUTAGE_WARNING = void 0;
exports.isMarrowControlOutage = isMarrowControlOutage;
exports.heldActionHookOutput = heldActionHookOutput;
exports.approvedHoldHookOutput = approvedHoldHookOutput;
exports.isMarrowOutage = isMarrowOutage;
exports.controlFailureKind = controlFailureKind;
exports.controlRejectionMessage = controlRejectionMessage;
exports.ownerApprovalPrompt = ownerApprovalPrompt;
exports.runtimeGateAdvisory = runtimeGateAdvisory;
exports.runtimeGateEnforced = runtimeGateEnforced;
exports.advisoryGateNotice = advisoryGateNotice;
exports.runtimeGateVerdict = runtimeGateVerdict;
exports.gateDecisionMessage = gateDecisionMessage;
exports.localControlAllowOutput = localControlAllowOutput;
exports.localLoopGuardDenyOutput = localLoopGuardDenyOutput;
exports.classifyTool = classifyTool;
exports.cursorPreActionHookOutput = cursorPreActionHookOutput;
exports.clinePreActionHookOutput = clinePreActionHookOutput;
exports.windsurfPreActionDecision = windsurfPreActionDecision;
exports.geminiPreActionHookOutput = geminiPreActionHookOutput;
exports.grokPreActionHookOutput = grokPreActionHookOutput;
exports.preActionHookOutput = preActionHookOutput;
exports.closeDeniedDecision = closeDeniedDecision;
exports.installPreActionHook = installPreActionHook;
exports.runPreActionHookCommand = runPreActionHookCommand;
const node_crypto_1 = require("node:crypto");
const index_1 = require("./index");
const request_reliability_1 = require("./request-reliability");
const lifecycle_spool_1 = require("./lifecycle-spool");
const control_state_1 = require("./control-state");
const runtime_contract_1 = require("./runtime-contract");
const host_approval_1 = require("./host-approval");
const session_loop_guard_1 = require("./session-loop-guard");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
Object.defineProperty(exports, "MARROW_OUTAGE_WARNING", { enumerable: true, get: function () { return hook_contract_1.MARROW_OUTAGE_WARNING; } });
// Claude Code sends the whole tool input, and a Write of a long document grows
// further once JSON-escaped, so tens of kilobytes of markdown must still parse.
exports.MAX_PRE_ACTION_INPUT_BYTES = 4 * 1024 * 1024;
// Cold auth may already use 900ms plus a 1600ms in-flight grace before think
// and enforcement. Keep this above that budget so a slow store is not aborted
// and misread as an outage.
exports.PRE_ACTION_CONTROL_TIMEOUT_MS = 8_000;
const CONTROL_OUTAGE_CODES = new Set([
    'request_timeout',
    'dns_unavailable',
    'connection_reset',
    'service_unavailable',
]);
const NETWORK_ERROR_CODES = new Set([
    'ENOTFOUND',
    'ECONNRESET',
    'ECONNREFUSED',
    'EAI_AGAIN',
    'ETIMEDOUT',
    'EHOSTUNREACH',
    'ENETUNREACH',
    'UND_ERR_CONNECT_TIMEOUT',
    'UND_ERR_SOCKET',
]);
class PreActionControlTimeoutError extends Error {
    code = 'request_timeout';
    constructor() {
        super('Marrow control path timed out');
        this.name = 'PreActionControlTimeoutError';
    }
}
exports.PreActionControlTimeoutError = PreActionControlTimeoutError;
function isMarrowControlOutage(error) {
    if (error instanceof PreActionControlTimeoutError)
        return true;
    if (error instanceof request_reliability_1.MarrowRequestError)
        return CONTROL_OUTAGE_CODES.has(error.code);
    if (!error || typeof error !== 'object')
        return false;
    const named = error;
    if (named.name === 'AbortError' || named.name === 'TimeoutError')
        return true;
    if (typeof named.code === 'string' && NETWORK_ERROR_CODES.has(named.code))
        return true;
    return error instanceof TypeError && /fetch|network|getaddrinfo/i.test(String(named.message || ''));
}
/** Fixed, privacy-preserving hold texts for hosts whose adapters accept only fixed strings. */
exports.HOLD_OWNER_DENIAL = 'Marrow is holding this action for approval; the approval request goes to the account owner. Retry it after approval.';
/**
 * The hook's answer for an ordinary held action, per host. A Claude Code "ask"
 * reason is shown to the user only; a Cursor user_message is shown only in the
 * client; neither ever reaches the agent with an approval code.
 */
function heldActionHookOutput(harness, plan, code = null) {
    if (harness === 'windsurf')
        return null;
    if (plan.kind === 'ask') {
        if (harness === 'cursor')
            return { permission: 'ask', user_message: plan.promptText, agent_message: 'Marrow asked the user to approve this held action in Cursor.' };
        return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: plan.promptText } };
    }
    // The approval code goes only to a user-only channel: Cursor user_message,
    // Codex and Gemini CLI systemMessage. The agent's text never contains it.
    if (harness === 'cursor') {
        return {
            permission: 'deny',
            user_message: code ? (0, host_approval_1.typedReplyUserText)(plan.userText, code) : plan.userText,
            agent_message: plan.agentText,
        };
    }
    if (harness === 'cline')
        return { cancel: true, errorMessage: exports.HOLD_OWNER_DENIAL };
    if (harness === 'gemini') {
        // Without a typed reply the Gemini adapter's fixed denial text is kept.
        return code
            ? { decision: 'deny', reason: plan.agentText, systemMessage: (0, host_approval_1.typedReplyUserText)(plan.userText, code) }
            : { decision: 'deny', reason: 'Marrow blocked this action because required governance approval or proof is unavailable.' };
    }
    if (harness === 'grok')
        return { decision: 'deny', reason: exports.HOLD_OWNER_DENIAL };
    return {
        hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: plan.agentText },
        ...(harness === 'codex' && code ? { systemMessage: (0, host_approval_1.typedReplyUserText)(plan.userText, code) } : {}),
    };
}
/** The hook's answer when a waited hold was approved and the same action is retried. */
function approvedHoldHookOutput(harness, contextText) {
    if (harness === 'windsurf')
        return null;
    if (harness === 'cursor')
        return { permission: 'allow' };
    if (harness === 'cline')
        return { cancel: false };
    if (harness === 'gemini' || harness === 'grok')
        return { decision: 'allow' };
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: contextText } };
}
function emitHookOutput(harness, output, deniedText) {
    if (harness === 'windsurf') {
        process.exitCode = deniedText ? 2 : 0;
        if (deniedText)
            process.stderr.write(`${deniedText}\n`);
        return;
    }
    if (output)
        process.stdout.write(JSON.stringify(output));
}
function isMarrowOutage(result) {
    return result.outage === true;
}
const SAFE_FAILURE_CODE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/;
const SAFE_AGENT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
// The key is valid but not bound to the agent this hook acts as.
const AGENT_CREDENTIAL_SCOPE_CODES = new Set(['ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID', 'MARROW_AGENT_SCOPE_MISMATCH']);
// Marrow could not be used at all, as opposed to answering with a policy or credential decision.
const CONTROL_UNAVAILABLE_CODES = new Set(['tls_failure', 'invalid_response', 'edge_access_denied']);
function controlFailureKind(error) {
    if (!(error instanceof request_reliability_1.MarrowRequestError))
        return undefined;
    if (error.status === 403 && AGENT_CREDENTIAL_SCOPE_CODES.has(error.backendCode || ''))
        return 'credential_scope';
    return CONTROL_UNAVAILABLE_CODES.has(error.code) ? 'unavailable' : undefined;
}
// Names a reached control failure by HTTP status and stable failure code only, so the
// denial is diagnosable without echoing private service text into the agent transcript.
function controlRejectionMessage(error, agentId) {
    const detail = [];
    if (error instanceof request_reliability_1.MarrowRequestError) {
        if (typeof error.status === 'number' && Number.isInteger(error.status))
            detail.push(`HTTP ${error.status}`);
        const code = [error.backendCode, error.code].find((value) => typeof value === 'string' && SAFE_FAILURE_CODE.test(value));
        if (code)
            detail.push(code);
    }
    const suffix = detail.length ? ` (${detail.join(' ')})` : '';
    const kind = controlFailureKind(error);
    if (kind === 'credential_scope') {
        const agent = agentId && SAFE_AGENT_ID.test(agentId)
            ? `agent "${agentId}"`
            : 'this hook\'s agent (no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set)';
        return `This Marrow API key is not authorized to obtain action permits for ${agent}${suffix}. Use the API key issued to that agent, or set MARROW_FLEET_AGENT_ID (or MARROW_AGENT_ID) to the agent this key belongs to, then retry.`;
    }
    if (kind === 'unavailable') {
        return `Marrow is unavailable, so this protected action was denied${suffix}. Retry when Marrow is reachable.`;
    }
    return `Marrow rejected this protected action${suffix}. Restore trusted governance before retrying.`;
}
// Claude Code permission modes in which a PreToolUse "ask" reaches a person.
// bypassPermissions disables prompts, dontAsk auto-denies anything that would
// prompt, and plan mode with bypass available runs edits without prompting.
// https://code.claude.com/docs/en/hooks#pretooluse-decision-control
// https://code.claude.com/docs/en/permission-modes
const OWNER_PROMPT_PERMISSION_MODES = new Set(['default', 'acceptEdits', 'auto']);
const NO_OWNER_PROMPT = { available: false, unavailableReason: 'this agent host cannot prompt the owner' };
/**
 * Whether a PreToolUse "ask" from this hook reaches a person who can approve.
 * Only Claude Code asks; the generic entrypoint counts as Claude Code only when
 * Claude Code itself spawned the hook (CLAUDE_CODE_CHILD_SESSION, v2.1.172+).
 */
function ownerApprovalPrompt(harness, event, env = process.env) {
    const claudeCode = harness === 'claude-code' || (harness === 'mcp-client' && env.CLAUDE_CODE_CHILD_SESSION === '1');
    if (!claudeCode) {
        return harness === 'codex'
            ? { available: false, unavailableReason: 'Codex hooks cannot prompt the owner' }
            : NO_OWNER_PROMPT;
    }
    const mode = typeof event.permission_mode === 'string' && /^[A-Za-z]{1,32}$/.test(event.permission_mode) ? event.permission_mode : '';
    if (!OWNER_PROMPT_PERMISSION_MODES.has(mode)) {
        return { available: false, unavailableReason: `Claude Code permission mode ${mode || 'unknown'} cannot guarantee an owner prompt` };
    }
    // Before Claude Code v2.1.211 the auto-mode classifier could approve a Bash
    // command outside the sandbox without the prompt a hook asked for. The hook
    // input carries scratchpad_dir only from v2.1.257, so it proves a fixed version.
    if (mode === 'auto' && !(typeof event.scratchpad_dir === 'string' && event.scratchpad_dir.trim())) {
        return { available: false, unavailableReason: 'this auto-mode session does not prove a Claude Code version whose classifier honors hook prompts' };
    }
    return { available: true, unavailableReason: '' };
}
function boundedText(value, limit) {
    return String(value ?? '')
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, limit);
}
function asOptionalRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}
// Arbitration review is satisfied only by an authenticated-dashboard receipt,
// never by a host prompt, so any arbitration signal keeps the denial.
function arbitrationReview(runtime) {
    const completion = runtime.completion_contract;
    const approval = asOptionalRecord(completion?.owner_approval);
    return Boolean(runtime.arbitration)
        || completion?.arbitration_receipt_required === true
        || approval?.dashboard_receipt_required === true
        || (approval?.mode !== undefined && approval.mode !== 'ordinary_non_arbitrated');
}
/**
 * True only for the runtime's positive advisory contract. On a plan without
 * production_action_enforcement the backend gate (agent-runtime.service.ts,
 * the hardGateEnforcement branch) carries enforced:false with
 * enforcement_decision:'advisory', and gate_required, owner_approval_required
 * and gate_receipt.required are false; the slim shape the MCP client receives
 * carries risk_gate_enforced:false instead. Missing, malformed or conflicting
 * enforcement fields are never advisory, so a protected action fails closed.
 */
function runtimeGateAdvisory(runtime) {
    const gate = runtime?.risk_gate;
    if (!runtime || !gate)
        return false;
    const slim = runtime.response_mode === 'slim';
    const completion = runtime.completion_contract;
    const plan = runtime.plan_capability;
    return gate.enforced === false
        && gate.enforcement_decision === 'advisory'
        && String(gate.decision) !== 'block'
        // A slim response has no allow field; the client derives it from the decision.
        && (slim ? runtime.risk_gate_enforced === false : gate.allow === true && runtime.risk_gate_enforced == null)
        && (runtime.enforcement_decision == null || runtime.enforcement_decision === 'advisory')
        && (runtime.authorization_state === undefined || runtime.authorization_state === 'advisory_only')
        && runtime.hard_gate_obtained !== true
        && gate.gate_required !== true
        && gate.owner_approval_required !== true
        && runtime.gate_receipt?.required !== true
        && runtime.gate_receipt?.owner_approval_required !== true
        && completion?.gate_receipt_required !== true
        && completion?.owner_approval_required !== true
        && completion?.owner_approval == null
        && !arbitrationReview(runtime)
        && plan?.production_enforcement_entitled !== true
        && plan?.mode !== 'enforced';
}
/** Every gate is enforced unless the runtime positively declares it advisory. */
function runtimeGateEnforced(runtime) {
    return !runtimeGateAdvisory(runtime);
}
function gateReason(runtime) {
    const why = boundedText(runtime.risk_gate.reasons?.[0]?.message, 240);
    const next = boundedText(runtime.exact_next_action, 240);
    return why && next && why !== next ? `${why}${/[.!?]$/.test(why) ? '' : '.'} Next: ${next}` : why || next;
}
/** A warning for a non-allow gate the runtime does not enforce on this plan. */
function advisoryGateNotice(runtime) {
    const gate = runtime?.risk_gate;
    if (!runtime || !gate || !runtimeGateAdvisory(runtime))
        return null;
    const decision = String(gate.decision || '');
    if (gate.allow !== false && !['warn', 'review_required', 'owner_approval_required'].includes(decision))
        return null;
    const reason = gateReason(runtime);
    return boundedText(`Marrow advisory: this plan does not enforce the pre-action gate, so the action is allowed. Gate decision: ${decision}.${reason ? ` Reason: ${reason}` : ''}`, 500);
}
function runtimeGateVerdict(runtime) {
    const gate = runtime?.risk_gate;
    if (!runtime || !gate)
        return null;
    const decision = String(gate.decision || '');
    const review = decision === 'review_required' || decision === 'owner_approval_required';
    if (decision !== 'block' && !review && gate.allow !== false)
        return null;
    // An advisory gate warns; only an enforced gate (or any block) stops the action.
    if (decision !== 'block' && runtimeGateAdvisory(runtime))
        return null;
    const reason = gateReason(runtime);
    if (decision === 'block')
        return { kind: 'block', reason };
    if (review)
        return { kind: arbitrationReview(runtime) ? 'arbitration_review' : 'review', reason };
    return { kind: 'denied', reason };
}
// Fixed wording leads so a long service reason can never truncate what happened.
function gateDecisionMessage(verdict, ask, prompt = NO_OWNER_PROMPT) {
    const headline = verdict.kind === 'block'
        ? 'Marrow blocked this action under the current policy.'
        : verdict.kind === 'arbitration_review'
            ? 'Marrow arbitration requires owner approval in the authenticated Marrow dashboard before this action.'
            : verdict.kind === 'denied'
                ? 'Marrow did not allow this action.'
                : ask
                    ? 'Marrow requires owner review before this action. Approve only if you authorize this exact action.'
                    : `Marrow requires owner review before this action, and no owner approval prompt is available (${prompt.unavailableReason}), so it was denied. Ask the owner to approve or run it.`;
    return boundedText(verdict.reason ? `${headline} Reason: ${verdict.reason}` : headline, 500);
}
const SAFE_DECISION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
function localControlAllowOutput(harness) {
    if (harness === 'windsurf')
        return null;
    if (harness === 'cursor')
        return { permission: 'allow' };
    if (harness === 'cline')
        return { cancel: false };
    if (harness === 'gemini' || harness === 'grok')
        return { decision: 'allow' };
    return {};
}
function localLoopGuardDenyOutput(harness, reason) {
    const bounded = reason.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500);
    if (harness === 'windsurf')
        return null;
    if (harness === 'cursor')
        return { permission: 'deny', user_message: bounded, agent_message: bounded };
    if (harness === 'cline')
        return { cancel: true, errorMessage: bounded };
    if (harness === 'gemini' || harness === 'grok')
        return { decision: 'deny', reason: bounded };
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: bounded } };
}
function emitLoopGuardDenial(harness, reason) {
    if (harness === 'windsurf') {
        process.exitCode = 2;
        process.stderr.write(`${reason.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500)}\n`);
        return;
    }
    process.stdout.write(JSON.stringify(localLoopGuardDenyOutput(harness, reason)));
}
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
        // Keep draining so the host never sees a broken pipe, but stop buffering past the bound.
        if (bytes <= exports.MAX_PRE_ACTION_INPUT_BYTES)
            chunks.push(buffer);
    }
    return { raw: bytes > exports.MAX_PRE_ACTION_INPUT_BYTES ? '' : Buffer.concat(chunks).toString('utf8'), bytes };
}
function localControlDisabled() {
    try {
        return (0, control_state_1.readLocalControlState)().enabled === false;
    }
    catch {
        return false;
    }
}
function classifyTool(event) {
    const tool = String(event.tool_name || 'tool').slice(0, 64);
    const normalizedTool = (0, hook_tool_policy_1.normalizeHookToolName)(tool);
    // Editing and task tools are judged by their target; shell-like words in the
    // content they write or the subject they record are not actions.
    const shellGoverned = (0, hook_tool_policy_1.isShellGovernedTool)(event);
    const command = shellGoverned ? (0, hook_tool_policy_1.hookToolCommand)(event) : '';
    const input = (0, hook_tool_policy_1.toolClassificationText)(event).toLowerCase();
    const readOnly = (0, hook_tool_policy_1.isReadOnlyToolEvent)(event);
    const secretAccess = (0, hook_tool_policy_1.isSecretMaterialAccess)(event);
    const protectedShellCommand = shellGoverned && (0, hook_tool_policy_1.isProtectedShellMutation)(command);
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
    else if (secretAccess || /\b(?:secret|credential|token|key|permission)\b/.test(input))
        type = 'audit';
    else if (/\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input))
        type = 'financial';
    const surfaces = [
        /\b(?:deploy|release|production|prod|wrangler)\b/.test(input) || infrastructureDeployment ? 'production' : '',
        /\b(?:git|github|merge|pull request|push)\b/.test(input) ? 'github' : '',
        /\b(?:npm|package|publish)\b/.test(input) ? 'npm' : '',
        secretAccess || /\b(?:secret|credential|token|key)\b/.test(input) ? 'secrets' : '',
        /\b(?:migration|schema|database|d1)\b/.test(input) ? 'database' : '',
        /\b(?:payment|refund|charge|invoice|stripe|financial)\b/.test(input) ? 'financial' : '',
    ].filter(Boolean);
    const protectedAction = !readOnly && (secretAccess
        || (shellGoverned && /\b(?:deploy|release|publish|git\s+push|git\s+merge|gh\s+pr\s+merge|migration|migrate|secret|credential|rotate|revoke|payment|refund|charge|invoice|production|prod)\b/.test(input))
        || protectedShellCommand
        || ((0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) && !(0, hook_tool_policy_1.isOfficialMarrowMcpTool)(event.tool_name))
        || (['use_mcp_tool', 'use_tool'].includes(normalizedTool) && !(0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(event)));
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
    if (isMarrowOutage(result)) {
        return { permission: 'allow', user_message: hook_contract_1.MARROW_OUTAGE_WARNING, agent_message: hook_contract_1.MARROW_OUTAGE_WARNING };
    }
    const { runtime, permit, protectedRisk } = result;
    const verdict = runtimeGateVerdict(runtime);
    if (verdict) {
        const denial = gateDecisionMessage(verdict, false);
        return { permission: 'deny', user_message: denial, agent_message: denial };
    }
    if (protectedRisk && (!runtime || !permit?.verified)) {
        const denial = boundedText(result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.', 500);
        return {
            permission: 'deny',
            user_message: denial,
            agent_message: denial,
        };
    }
    const advisory = advisoryGateNotice(runtime);
    return advisory ? { permission: 'allow', user_message: advisory, agent_message: advisory } : { permission: 'allow' };
}
function clinePreActionHookOutput(result) {
    if (isMarrowOutage(result))
        return { cancel: false };
    const verdict = runtimeGateVerdict(result.runtime);
    if (verdict) {
        return {
            cancel: true,
            errorMessage: verdict.kind === 'review' || verdict.kind === 'arbitration_review'
                ? 'Marrow requires operator review before this protected action.'
                : 'Marrow blocked this protected action under the current policy.',
        };
    }
    if (result.protectedRisk && (!result.runtime || !result.permit?.verified)) {
        const credentialsUnavailable = /credentials are unavailable/i.test(String(result.enforcementError || ''));
        return {
            cancel: true,
            errorMessage: credentialsUnavailable
                ? 'Marrow credentials are unavailable for this protected action. Restore the configured agent key and retry.'
                : result.failure === 'credential_scope'
                    ? 'This Marrow API key is not authorized to obtain action permits for this agent. Use the API key issued to this agent and retry.'
                    : result.failure === 'unavailable'
                        ? 'Marrow is unavailable, so this protected action was denied. Retry when Marrow is reachable.'
                        : 'Marrow could not verify the required action permit. Restore trusted governance and retry.',
        };
    }
    return { cancel: false };
}
function windsurfPreActionDecision(result) {
    if (isMarrowOutage(result))
        return { exitCode: 0, stderr: `${hook_contract_1.MARROW_OUTAGE_WARNING}\n` };
    const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
    const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
    return denied
        ? {
            exitCode: 2,
            stderr: 'Marrow blocked this action because required governance approval or proof is unavailable.\n',
        }
        : { exitCode: 0, stderr: '' };
}
function geminiPreActionHookOutput(result) {
    if (isMarrowOutage(result))
        return { decision: 'allow' };
    const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
    const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
    return denied
        ? {
            decision: 'deny',
            reason: 'Marrow blocked this action because required governance approval or proof is unavailable.',
        }
        : { decision: 'allow' };
}
function grokPreActionHookOutput(result) {
    if (isMarrowOutage(result))
        return { decision: 'allow' };
    const unavailable = result.protectedRisk && (!result.runtime || !result.permit?.verified);
    const denied = unavailable || runtimeGateVerdict(result.runtime) !== null;
    return denied
        ? { decision: 'deny', reason: 'Marrow blocked this protected action.' }
        : { decision: 'allow' };
}
function preActionHookOutput(result, harness = 'claude-code', prompt = NO_OWNER_PROMPT) {
    if (harness === 'cursor')
        return cursorPreActionHookOutput(result);
    if (harness === 'cline')
        return clinePreActionHookOutput(result);
    if (harness === 'gemini')
        return geminiPreActionHookOutput(result);
    if (harness === 'grok')
        return grokPreActionHookOutput(result);
    if (isMarrowOutage(result)) {
        return {
            hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                additionalContext: hook_contract_1.MARROW_OUTAGE_WARNING,
            },
        };
    }
    const { runtime, permit, protectedRisk } = result;
    const advisory = advisoryGateNotice(runtime);
    const context = runtime?.before_you_act || permit?.permit_id || advisory ? {
        additionalContext: [
            advisory,
            runtime?.before_you_act,
            permit?.permit_id ? `Marrow action permit verified: ${permit.permit_id}. Evidence and outcome closure remain required.` : null,
        ].filter(Boolean).join('\n'),
    } : {};
    const verdict = runtimeGateVerdict(runtime);
    if (verdict) {
        // An ordinary hold the server lets the host approve is answered by
        // heldActionHookOutput. Here every gate denies: block, arbitration, and a
        // review the server offered no chat or terminal approval for.
        const reason = verdict.kind === 'review' && prompt.available
            ? { available: false, unavailableReason: 'this Marrow service did not offer a chat or terminal approval for this hold' }
            : prompt;
        return {
            hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'deny',
                permissionDecisionReason: gateDecisionMessage(verdict, false, reason),
                ...context,
            },
        };
    }
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
    return {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            ...context,
        },
    };
}
function emitDecision(result, harness = 'claude-code', prompt = NO_OWNER_PROMPT) {
    if (harness === 'windsurf') {
        const decision = windsurfPreActionDecision(result);
        process.exitCode = decision.exitCode;
        if (decision.stderr)
            process.stderr.write(decision.stderr);
        return { denied: decision.exitCode === 2, reason: decision.stderr.trim() };
    }
    if (result.outage)
        process.stderr.write(`${hook_contract_1.MARROW_OUTAGE_WARNING}\n`);
    const output = preActionHookOutput(result, harness, prompt);
    process.stdout.write(JSON.stringify(output));
    const specific = asRecord(output.hookSpecificOutput);
    if (specific?.permissionDecision === 'deny')
        return { denied: true, reason: String(specific.permissionDecisionReason || '') };
    if (output.permission === 'deny')
        return { denied: true, reason: String(output.agent_message || '') };
    if (output.cancel === true)
        return { denied: true, reason: String(output.errorMessage || '') };
    if (output.decision === 'deny')
        return { denied: true, reason: String(output.reason || '') };
    return { denied: false, reason: '' };
}
// Closing is best effort: the denial already stands, and the hook must not hang.
exports.DENIED_DECISION_CLOSE_TIMEOUT_MS = 2_500;
/**
 * Records a decision the hook denied as a failed outcome, so it carries real
 * outcome data instead of being swept to a NULL outcome later. Never called for
 * an "ask": an approved prompt runs the action and its outcome is still open.
 */
async function closeDeniedDecision(apiKey, baseUrl, held, reason, sessionId, agentId) {
    if (!held.decisionId)
        return false;
    const outcome = boundedText(`denied by Marrow pre-action gate: ${reason || 'no reason was returned'}`, 500);
    const controller = new AbortController();
    let timer;
    try {
        const committed = await Promise.race([
            (0, index_1.marrowCommit)(apiKey, baseUrl, {
                decision_id: held.decisionId,
                success: false,
                outcome,
                auto_gate: false,
                ...(held.gateReceiptId ? { gate_receipt_id: held.gateReceiptId } : {}),
            }, sessionId, agentId, controller.signal, `mcp-hook-deny:${(0, node_crypto_1.createHash)('sha256').update(`${held.decisionId}\n${outcome}`).digest('hex').slice(0, 40)}`),
            new Promise((resolve) => {
                timer = setTimeout(() => {
                    controller.abort();
                    resolve(null);
                }, exports.DENIED_DECISION_CLOSE_TIMEOUT_MS);
            }),
        ]);
        return committed?.committed === true;
    }
    catch {
        return false;
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
async function withTimeout(operation) {
    const controller = new AbortController();
    let timer;
    try {
        return await Promise.race([
            operation(controller.signal),
            new Promise((_, reject) => {
                timer = setTimeout(() => {
                    controller.abort();
                    reject(new PreActionControlTimeoutError());
                }, exports.PRE_ACTION_CONTROL_TIMEOUT_MS);
            }),
        ]);
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
    let inputFailure = null;
    if (event === undefined) {
        try {
            const stdin = await readStdin();
            if (stdin.bytes > exports.MAX_PRE_ACTION_INPUT_BYTES) {
                inputFailure = `Marrow did not check this action because its hook input is ${stdin.bytes} bytes, over the ${exports.MAX_PRE_ACTION_INPUT_BYTES}-byte pre-action limit, so it was denied. Split it into smaller tool calls and retry.`;
            }
            else {
                const raw = stdin.raw.trim();
                event = raw ? (0, hook_contract_1.normalizeHookEventPayload)(JSON.parse(raw)) : {};
            }
        }
        catch {
            inputFailure = 'Marrow rejected malformed pre-action input.';
        }
    }
    const source = inputFailure ? null : asRecord((0, hook_contract_1.normalizeHookEventPayload)(event));
    if (!inputFailure && !source?.tool_name)
        inputFailure = 'Marrow could not classify this mutation-capable tool request.';
    if (inputFailure || !source) {
        // Owner-disabled local control allows every action, including input Marrow cannot read.
        if (localControlDisabled()) {
            const allow = localControlAllowOutput(identity.harness);
            if (allow === null)
                process.exitCode = 0;
            else
                process.stdout.write(JSON.stringify(allow));
            return;
        }
        emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: inputFailure || 'Marrow could not classify this mutation-capable tool request.' }, identity.harness);
        return;
    }
    if ((0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(source)) {
        if (identity.harness === 'windsurf') {
            process.exitCode = 0;
            return;
        }
        process.stdout.write(JSON.stringify(identity.harness === 'cursor' ? { permission: 'allow' }
            : identity.harness === 'cline' ? { cancel: false }
                : ['gemini', 'grok'].includes(identity.harness) ? { decision: 'allow' }
                    : {}));
        return;
    }
    const classified = classifyTool(source);
    let localControl;
    try {
        localControl = (0, control_state_1.readLocalControlState)();
    }
    catch {
        emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: 'Marrow local control state is unsafe. Protected actions remain blocked until the owner repairs it.' }, identity.harness);
        return;
    }
    if (!localControl.enabled) {
        const resolved = identity.environment;
        const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id;
        const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
        if (resolved.apiKey) {
            try {
                const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
                await (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl, event: {
                        event_id: `owner-bypass-${correlation}`,
                        event_type: 'pre_action_checked',
                        ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                        session_id: sessionId,
                        workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, source.generation_id || source.tool_use_id || source.task_id),
                        correlation_id: correlation,
                        action: control_state_1.CONTROL_BYPASS_ACTION,
                        surfaces: classified.surfaces.slice(0, 6),
                        risk_level: classified.risk,
                        outcome_state: 'pending',
                        intervention_disposition: 'overridden',
                        action_changed: false,
                    } }).catch(() => null);
            }
            catch { /* owner bypass is not trapped by telemetry configuration */ }
        }
        const allow = localControlAllowOutput(identity.harness);
        if (allow === null)
            process.exitCode = 0;
        else
            process.stdout.write(JSON.stringify(allow));
        return;
    }
    let resolved = identity.environment;
    const enforcementRequired = classified.protected || ['windsurf', 'gemini', 'grok'].includes(identity.harness);
    const sessionId = resolved.sessionId || source.session_id || source.conversation_id || source.task_id
        || (0, hook_contract_1.stableSessionWorkflowId)(undefined, [identity.harness, process.cwd()]);
    const agentId = identity.agent_id;
    const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
    const loopOperation = {
        sessionId,
        agentId,
        harness: identity.harness,
        toolName: source.tool_name,
        toolInput: source.tool_input,
        invocationId: source.tool_use_id,
        readOnly: classified.readOnly,
    };
    let loopDecision;
    try {
        loopDecision = (0, session_loop_guard_1.consultSessionLoopGuard)(loopOperation);
    }
    catch {
        emitLoopGuardDenial(identity.harness, 'Marrow local loop guard state is unsafe. Repair the private owner-only state before retrying.');
        return;
    }
    if (!loopDecision.allow) {
        if (resolved.apiKey) {
            try {
                const loopBaseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
                await (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl: loopBaseUrl, event: {
                        event_id: `loop-block-${loopDecision.receipt.slice(4)}`,
                        event_type: 'pre_action_checked',
                        ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                        session_id: sessionId,
                        workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId),
                        correlation_id: loopDecision.receipt,
                        action: 'local session loop guard blocked an unchanged repeated operation',
                        target: 'marrow:loop-guard',
                        surfaces: ['workspace'],
                        risk_level: 'low',
                        outcome_state: 'pending',
                        intervention_disposition: 'followed',
                        action_changed: true,
                    } }).catch(() => null);
            }
            catch { /* local denial remains authoritative when telemetry is unavailable */ }
        }
        emitLoopGuardDenial(identity.harness, loopDecision.reason || `Marrow local loop guard blocked this unchanged repeat. Receipt: ${loopDecision.receipt}.`);
        return;
    }
    if (classified.readOnly) {
        const allow = localControlAllowOutput(identity.harness);
        if (allow === null)
            process.exitCode = 0;
        else
            process.stdout.write(JSON.stringify(allow));
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
            protectedRisk: enforcementRequired,
            enforcementError: 'Marrow enforcement configuration is unavailable. Restore the trusted configuration before retrying this protected action.',
        }, identity.harness);
        return;
    }
    if (!resolved.apiKey) {
        emitDecision({
            runtime: null,
            permit: null,
            protectedRisk: enforcementRequired,
            enforcementError: 'Marrow credentials are unavailable for this protected action. Restore the configured agent key before retrying.',
        }, identity.harness);
        return;
    }
    const holdContext = {
        apiKey: resolved.apiKey,
        baseUrl,
        sessionId,
        agentId,
        harness: identity.harness,
        host: (0, host_approval_1.approvalHostFor)(identity.harness),
        hostSessionId: (0, host_approval_1.hostSessionIdFor)([source.session_id, source.conversation_id, source.task_id], sessionId),
    };
    const toolUseId = typeof source.tool_use_id === 'string' ? source.tool_use_id : null;
    const generationId = typeof source.generation_id === 'string' ? source.generation_id : null;
    // The same action retried after a hold that waited for approval: its status decides.
    const waited = await (0, host_approval_1.resumeWaitingHold)(holdContext, { correlation, toolUseId, generationId }).catch(() => null);
    if (waited?.kind === 'allow') {
        emitHookOutput(identity.harness, approvedHoldHookOutput(identity.harness, waited.contextText));
        return;
    }
    if (waited?.kind === 'deny') {
        const plan = { kind: 'deny', agentText: waited.agentText, userText: waited.userText, code: Boolean(waited.hold.code) };
        emitHookOutput(identity.harness, heldActionHookOutput(identity.harness, plan, waited.hold.code), exports.HOLD_OWNER_DENIAL);
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
            workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId, source.generation_id || source.tool_use_id || source.task_id),
            correlation_id: correlation,
            action: classified.action,
            target: classified.target,
            surfaces: classified.surfaces,
            risk_level: classified.risk,
            outcome_state: 'pending',
        },
    }).catch(() => null);
    // The decision and gate receipt this control path holds, so a denial can close them.
    const held = { decisionId: null, gateReceiptId: null };
    const control = async (signal) => {
        const runtime = await (0, index_1.marrowAgentRuntime)(resolved.apiKey, baseUrl, {
            action: classified.action,
            target: classified.target,
            type: classified.type,
            role: classified.role,
            surfaces: classified.surfaces,
            // Without a risk level the runtime may take its low-risk fast path, whose
            // non-durable fast_gate receipt can never back an action permit.
            ...(enforcementRequired ? { risk_level: classified.risk } : {}),
        }, sessionId, agentId, signal);
        const heldIds = [...new Set([runtime.decision_id, runtime.completion_contract?.decision_id, runtime.runtime_authorization?.decision_id]
                .filter((value) => typeof value === 'string' && SAFE_DECISION_ID.test(value)))];
        held.decisionId = heldIds.length === 1 ? heldIds[0] : null;
        held.gateReceiptId = (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtime) || null;
        const gate = runtime.risk_gate;
        if (gate?.decision === 'block')
            return { runtime, permit: null, protectedRisk: enforcementRequired };
        // Free and starter plans get a positively advisory gate that warns but never
        // hard-stops; every other gate, including an unclear one, keeps enforcement.
        if (runtimeGateAdvisory(runtime))
            return { runtime, permit: null, protectedRisk: false };
        if (runtimeGateVerdict(runtime)) {
            return { runtime, permit: null, protectedRisk: enforcementRequired };
        }
        // Only enforced actions need a decision and permit; creating them for every
        // unprotected tool call would record a decision per edit.
        if (!enforcementRequired)
            return { runtime, permit: null, protectedRisk: false };
        const gateReceiptId = (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtime);
        const runtimeIds = [runtime.decision_id, runtime.completion_contract?.decision_id, runtime.runtime_authorization?.decision_id]
            .filter((value) => typeof value === 'string' && SAFE_DECISION_ID.test(value));
        const distinctRuntimeIds = [...new Set(runtimeIds)];
        const creationRequired = runtime.completion_contract?.decision_creation_required
            ?? runtime.runtime_authorization?.decision_creation_required;
        if (distinctRuntimeIds.length > 1) {
            return { runtime, permit: null, protectedRisk: enforcementRequired, enforcementError: 'Marrow runtime returned conflicting decision identifiers.' };
        }
        let decisionId = distinctRuntimeIds[0] || null;
        if (creationRequired === true) {
            const decision = await (0, index_1.marrowThink)(resolved.apiKey, baseUrl, {
                action: classified.action,
                target: classified.target,
                surfaces: classified.surfaces,
                type: classified.type,
                source_kind: 'integration',
                // Think rejects any source_meta key outside channel, client, agent_id, task_depth and
                // user_intent with HTTP 400. The gate receipt and correlation bind on the permit below.
                ...(identity.harness !== 'mcp-client' ? { source_meta: { client: identity.harness } } : {}),
            }, sessionId, agentId, signal);
            decisionId = SAFE_DECISION_ID.test(decision.decision_id) ? decision.decision_id : null;
            // The runtime receipt is not bound to a decision Think creates; closing with it is a scope mismatch.
            held.decisionId = decisionId;
            held.gateReceiptId = null;
        }
        if (!decisionId) {
            return {
                runtime,
                permit: null,
                protectedRisk: enforcementRequired,
                ...(enforcementRequired ? { enforcementError: 'Marrow runtime did not provide a valid decision and did not authorize decision creation.' } : {}),
            };
        }
        const issued = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'issue',
            action: classified.action,
            action_type: classified.type,
            target: classified.target,
            correlation_id: correlation,
            harness: identity.harness,
            decision_id: decisionId,
            gate_receipt_id: gateReceiptId,
            proof_requirements: runtime.proof_pack?.fields || [],
            surfaces: classified.surfaces,
        }, sessionId, agentId, signal);
        const issuedPermitId = typeof issued.permit_id === 'string' ? issued.permit_id.trim() : '';
        if (!issued.permit || !issuedPermitId) {
            return { runtime, permit: { ...issued, verified: false }, protectedRisk: enforcementRequired, enforcementError: 'Marrow did not issue a complete action permit.' };
        }
        const verified = await (0, index_1.marrowEnforcement)(resolved.apiKey, baseUrl, {
            operation: 'verify',
            // Verify must declare the permit's protocol; issue defaults to version 1.
            protocol_version: issued.protocol_version === 2 ? 2 : 1,
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
            protectedRisk: enforcementRequired,
            ...(verifiedExactly ? {} : { enforcementError: 'Marrow permit verification did not match the issued permit.' }),
        };
    };
    const [result] = await Promise.all([
        withTimeout(control).catch((error) => (isMarrowControlOutage(error)
            ? {
                runtime: null,
                permit: null,
                protectedRisk: enforcementRequired,
                outage: true,
                enforcementError: hook_contract_1.MARROW_OUTAGE_WARNING,
            }
            : {
                runtime: null,
                permit: null,
                protectedRisk: enforcementRequired,
                enforcementError: controlRejectionMessage(error, agentId),
                ...(controlFailureKind(error) ? { failure: controlFailureKind(error) } : {}),
            })),
        lifecycle,
    ]);
    const claudePrompt = ownerApprovalPrompt(identity.harness, source);
    const verdict = result.outage ? null : runtimeGateVerdict(result.runtime);
    const guidance = verdict?.kind === 'review' ? (0, runtime_contract_1.ordinaryApprovalGuidance)(result.runtime) : null;
    if (verdict && guidance) {
        // An ordinary hold: ask in the host's own prompt where it counts and is
        // shown, otherwise deny and wait for the approval. Never close the decision
        // here; that would spend the receipt the operator or owner is about to approve.
        const cursor = holdContext.host === 'cursor' ? (0, host_approval_1.cursorSessionEvidence)(holdContext) : null;
        const plan = (0, host_approval_1.planHeldAction)({
            guidance,
            host: holdContext.host,
            hookEvent: typeof source.hook_event_name === 'string' ? source.hook_event_name : 'PreToolUse',
            reason: verdict.reason,
            claudePrompt,
            cursorInteractive: cursor?.interactive ?? null,
            typedReply: (0, host_approval_1.typedReplyAvailable)(holdContext),
        });
        let code = null;
        let effective = plan;
        try {
            const hold = (0, host_approval_1.rememberHold)(holdContext, {
                guidance,
                correlation,
                toolUseId,
                generationId,
                toolName: String(source.tool_name || 'tool'),
                hookEvent: typeof source.hook_event_name === 'string' ? source.hook_event_name : 'PreToolUse',
                mode: plan.kind === 'ask' ? 'ask' : 'wait',
                withCode: plan.kind === 'deny' && plan.code,
                preActionEventId: `pretool-${correlation}`,
                action: { action: classified.action, target: classified.target, type: classified.type, surfaces: classified.surfaces },
            });
            code = hold.code;
        }
        catch {
            // Without local state the answer could not be linked to this hold, so it is not asked for.
            if (plan.kind === 'ask') {
                const text = `Marrow is holding this action for approval (gate receipt ${guidance.gateReceiptId}), so it did not run. The approval request goes to the account owner. When it is approved, retry this exact action.`;
                effective = { kind: 'deny', agentText: text, userText: text, code: false };
            }
        }
        emitHookOutput(identity.harness, heldActionHookOutput(identity.harness, effective, code), effective.kind === 'deny' ? exports.HOLD_OWNER_DENIAL : undefined);
        return;
    }
    const emitted = emitDecision(result, identity.harness, claudePrompt);
    if (emitted.denied && !result.outage) {
        await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
    }
}
//# sourceMappingURL=hook-pre-action.js.map