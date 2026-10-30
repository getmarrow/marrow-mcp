"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DENIED_DECISION_CLOSE_TIMEOUT_MS = exports.ENV_FILTER_SECRET_NAME = exports.SEATBELT_CURSOR_ASK_AGENT_TEXT = exports.SEATBELT_CURSOR_ASK_USER_TEXT = exports.SEATBELT_HELD_TEXT = exports.GROK_FIXED_DENIAL = exports.HELD_OFFLINE_TEXT = exports.HELD_SLOW_TEXT = exports.HOLD_OWNER_DENIAL = exports.PreActionControlTimeoutError = exports.PRE_ACTION_CONTROL_TIMEOUT_MS = exports.MAX_PRE_ACTION_INPUT_BYTES = exports.MARROW_OUTAGE_WARNING = exports.SETUP_UNCONFIRMED_TEXT = exports.CLAIMED_NO_KEY_TEXT = exports.NO_KEY_TEXT = void 0;
exports.isMarrowControlTimeout = isMarrowControlTimeout;
exports.isMarrowControlOutage = isMarrowControlOutage;
exports.heldActionHookOutput = heldActionHookOutput;
exports.passHookOutput = passHookOutput;
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
exports.seatbeltPassOutput = seatbeltPassOutput;
exports.localLoopGuardDenyOutput = localLoopGuardDenyOutput;
exports.classifyTool = classifyTool;
exports.mayPrintEnvironment = mayPrintEnvironment;
exports.mayReadApprovalState = mayReadApprovalState;
exports.mayReadSecret = mayReadSecret;
exports.controlRouteCall = controlRouteCall;
exports.cursorPreActionHookOutput = cursorPreActionHookOutput;
exports.clinePreActionHookOutput = clinePreActionHookOutput;
exports.windsurfPreActionDecision = windsurfPreActionDecision;
exports.geminiPreActionHookOutput = geminiPreActionHookOutput;
exports.grokPreActionHookOutput = grokPreActionHookOutput;
exports.preActionHookOutput = preActionHookOutput;
exports.closeDeniedDecision = closeDeniedDecision;
exports.localApprovalCategories = localApprovalCategories;
exports.installPreActionHook = installPreActionHook;
exports.runSeatbeltStatusCommand = runSeatbeltStatusCommand;
exports.outageHolds = outageHolds;
exports.runPreActionHookCommand = runPreActionHookCommand;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const index_1 = require("./index");
const request_reliability_1 = require("./request-reliability");
const ipv4_first_1 = require("./ipv4-first");
const lifecycle_spool_1 = require("./lifecycle-spool");
const control_state_1 = require("./control-state");
const control_notice_1 = require("./control-notice");
const runtime_contract_1 = require("./runtime-contract");
const host_approval_1 = require("./host-approval");
const control_routes_1 = require("./control-routes");
const owner_bypass_1 = require("./owner-bypass");
const self_protect_1 = require("./self-protect");
const keyless_notice_1 = require("./keyless-notice");
const session_id_1 = require("./session-id");
const host_approval_state_1 = require("./host-approval-state");
const host_session_1 = require("./host-session");
const own_server_identity_1 = require("./own-server-identity");
const normalized_action_1 = require("./normalized-action");
const secret_paths_1 = require("./secret-paths");
const session_loop_guard_1 = require("./session-loop-guard");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
Object.defineProperty(exports, "MARROW_OUTAGE_WARNING", { enumerable: true, get: function () { return hook_contract_1.MARROW_OUTAGE_WARNING; } });
/** A protected action with no Marrow key anywhere this machine keeps one (MARROW_API_KEY, ~/.marrow/env.local or ~/.marrow/env, owner-only). */
exports.NO_KEY_TEXT = 'Marrow has no API key on this machine, so it held this action. To approve actions like this, create a key at getmarrow.ai/signup and add it: getmarrow.ai/docs#start-here (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins). Agent: do not retry this action.';
/** Seatbelt mode `claimed_no_key` (spec §1.1): account evidence on the machine but no usable key. Same text as src/seatbelt/hook.ts. */
exports.CLAIMED_NO_KEY_TEXT = 'Marrow is linked to an account but has no working key; owner: run `npx -y @getmarrow/install@latest doctor`.';
/**
 * `claimed_no_key` without account evidence (a mode fallback): the same holds, never an account claim.
 * This constant is the generic wording; the hold names its reason (setupUnconfirmedText). Same text as src/seatbelt/hook.ts.
 */
exports.SETUP_UNCONFIRMED_TEXT = 'Marrow stopped this action: there is no Marrow key on this machine, and Marrow uses its stricter no-key mode here because it could not confirm this machine\'s setup. Fix (for the person at this machine, not the agent): run npx -y @getmarrow/install@latest doctor, or add a Marrow key (getmarrow.ai/docs#start-here). Agent: do not retry it another way and do not edit Marrow settings; tell the user why it was stopped. Code: setup_unconfirmed.';
/** The seatbelt path itself could not run (its modules did not load): a stop (spec §2.1.4). */
const SEATBELT_FAILED_TEXT = 'MARROW SEATBELT stopped this action: a safety check that could not finish. If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was stopped. If this keeps happening, run npx -y @getmarrow/install@latest doctor. Code: U5.fail_closed/hook_error.';
/**
 * Seatbelt stop and keyless hold texts end with their code, so they get room for it: the longest real stop
 * (a fallback reason row with the longest label and codes) is about 850 characters. It is our own cap, not a host's:
 * Claude Code, Codex, Cursor and Windsurf document no limit on the text of a denial and their installed hooks pass it on unchanged.
 */
const STOP_TEXT_LIMIT = 880;
/** The installed Gemini CLI guard (@getmarrow/install, src/installer.js) turns a deny reason over 500 characters into its launch failure. */
const GEMINI_REASON_LIMIT = 500;
/** The installed Cline PreToolUse hook (@getmarrow/install, src/installer.js clinePreToolUseHookSource) replaces an errorMessage over 500 characters with its generic "did not return a valid decision" text. */
const CLINE_ERROR_LIMIT = 500;
/** The most characters of a stop or hold text this host takes without losing the code at its end. */
function hostTextLimit(harness) {
    return harness === 'gemini' ? GEMINI_REASON_LIMIT : harness === 'cline' ? CLINE_ERROR_LIMIT : STOP_TEXT_LIMIT;
}
/** The Cursor deny text of every enforcementError that is not one of the fixed keyless texts (as on 3.9.104). */
const CURSOR_ENFORCEMENT_LIMIT = 500;
/** Claude Code plugin only; a host with a tight limit drops it before it would lose the stop's code at the end. */
const PLUGIN_KEY_HINT = ' (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins)';
/** The person's own way out; after the plugin hint it is the next thing a tight limit gives up. The agent's instruction stays. */
const PERSON_ADVICE = ' If you (the person at this machine) meant it, run it yourself in your own terminal.';
/**
 * One line of hook text within a host's limit. A text over it first gives up the plugin hint, then the
 * person's advice; if it is still over, the end of the explanation is cut at a sentence and the stop's
 * code (the last "Code: ..." part) is kept. Texts that fit are untouched.
 */
function fitHookText(value, limit) {
    let text = value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
    for (const part of [PLUGIN_KEY_HINT, PERSON_ADVICE]) {
        if (text.length <= limit)
            break;
        text = text.replace(part, '');
    }
    if (text.length <= limit)
        return text;
    const at = text.lastIndexOf(' Code: ');
    if (at > 0 && limit - (text.length - at) > 40) {
        const tail = text.slice(at);
        const head = text.slice(0, limit - tail.length);
        const cut = head.lastIndexOf('. ');
        return `${cut > 0 ? head.slice(0, cut + 1) : head}${tail}`.slice(0, limit);
    }
    return text.slice(0, limit);
}
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
/**
 * A timeout (the hook's own budget, or a request that did not answer in time):
 * Marrow is slow, not known to be down. It is never treated as an outage.
 */
function isMarrowControlTimeout(error) {
    if (error instanceof PreActionControlTimeoutError)
        return true;
    if (error instanceof request_reliability_1.MarrowRequestError)
        return error.code === 'request_timeout';
    if (!error || typeof error !== 'object')
        return false;
    const named = error;
    return named.name === 'AbortError' || named.name === 'TimeoutError';
}
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
exports.HOLD_OWNER_DENIAL = 'Marrow is holding this action for approval. Retry it after approval.';
/** Marrow did not answer within the hook's time limit: an action that can be held stays held. */
exports.HELD_SLOW_TEXT = 'Marrow did not answer in time, so this action is held. Retry it in a moment.';
/** Marrow cannot be reached (a real outage): a high-risk action fails closed; routine actions keep the outage allow. */
exports.HELD_OFFLINE_TEXT = 'Marrow cannot be reached right now, so this high-risk action is held; routine actions keep running. Retry it when Marrow is back.';
/** The only denial @getmarrow/install's Grok guard passes through (any other output blocks with a launch failure). */
exports.GROK_FIXED_DENIAL = 'Marrow blocked this protected action.';
/**
 * The hook's answer for an ordinary held action, per host. A Claude Code "ask"
 * reason is shown to the user only; a Cursor user_message is shown only in the
 * client; neither ever reaches the agent with an approval code.
 */
function heldActionHookOutput(harness, plan, code = null) {
    if (harness === 'windsurf')
        return null;
    if (plan.kind === 'pass')
        return passHookOutput(harness, plan.contextText);
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
        return { cancel: true, errorMessage: plan.agentText };
    if (harness === 'gemini') {
        // Without a typed reply the Gemini adapter's fixed denial text is kept.
        return code
            ? { decision: 'deny', reason: plan.agentText, systemMessage: (0, host_approval_1.typedReplyUserText)(plan.userText, code) }
            : { decision: 'deny', reason: 'Marrow blocked this action because required governance approval or proof is unavailable.' };
    }
    if (harness === 'grok')
        return { decision: 'deny', reason: exports.GROK_FIXED_DENIAL };
    return {
        hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: plan.agentText },
        ...(harness === 'codex' && code ? { systemMessage: (0, host_approval_1.typedReplyUserText)(plan.userText, code) } : {}),
        // Claude Code, a hold nobody can approve in chat (no dialog here, or nobody in this run): one user-only
        // line says so. Output only: the decision above is the same deny, and the line carries no code or id.
        ...(harness === 'claude-code' && plan.userNotice ? { systemMessage: plan.userNotice } : {}),
    };
}
/**
 * The hook's answer when the host's own approval step decides (owner rule):
 * neutral, never an explicit allow, so the host's normal permission flow runs.
 * Codex: no permissionDecision (only context for the agent); Cline: not
 * cancelled; Windsurf: exit 0 (emitted by the caller). Any other host has no
 * neutral answer here and never gets a pass plan.
 */
function passHookOutput(harness, contextText) {
    if (harness === 'windsurf')
        return null;
    if (harness === 'cline')
        return { cancel: false };
    if (harness === 'codex')
        return { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: contextText } };
    throw new Error(`no neutral pre-tool answer for ${harness}`);
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
const DOCTOR_FIX = 'Run `npx -y @getmarrow/install@latest doctor` in this terminal to check this machine\'s Marrow setup, then retry.';
/**
 * A plain fix for a reached control failure: a known code's own fix, or the
 * service's exact_fix when it is plain (no API calls, dashboard steps or
 * links), else the doctor command. Service text other than exact_fix is never
 * echoed into the agent transcript.
 */
function plainControlFix(error) {
    if (!(error instanceof request_reliability_1.MarrowRequestError))
        return DOCTOR_FIX;
    const code = String(error.backendCode || '');
    if (code === 'AGENT_NOT_REGISTERED' || code === 'MARROW_AGENT_NOT_REGISTERED') {
        if (/agent limit/i.test(error.message)) {
            return 'Marrow could not add this agent: this account has reached its plan\'s agent limit. The account owner can archive an unused agent or change the plan in Marrow, then retry.';
        }
        if (/not active/i.test(error.message)) {
            return 'This agent is turned off in this Marrow account. The account owner can turn it back on in Marrow, then retry.';
        }
        return 'Marrow doesn\'t know this agent yet. Run `npx @getmarrow/install` again in this terminal, then retry.';
    }
    if (error.status === 429 || error.code === 'rate_limited')
        return 'Marrow is busy right now. Retry in a minute.';
    const fix = error.exactFix.replace(/\s+/g, ' ').trim();
    const plain = fix.length > 0 && fix.length <= 240 && /[.!]$/.test(fix)
        && !/\/v1\/|\b(?:POST|GET|PATCH|PUT|DELETE)\b|dashboard|https?:\/\/|X-Marrow|agent_id|api key|curl\b/i.test(fix);
    return plain ? fix : DOCTOR_FIX;
}
// Names a reached control failure by HTTP status and stable failure code, with a plain
// fix (see plainControlFix); private service text is never echoed into the agent transcript.
function controlRejectionMessage(error, agentId, kind = controlFailureKind(error)) {
    const detail = [];
    if (error instanceof request_reliability_1.MarrowRequestError) {
        if (typeof error.status === 'number' && Number.isInteger(error.status))
            detail.push(`HTTP ${error.status}`);
        const code = [error.backendCode, error.code].find((value) => typeof value === 'string' && SAFE_FAILURE_CODE.test(value));
        if (code)
            detail.push(code);
    }
    const suffix = detail.length ? ` (${detail.join(' ')})` : '';
    if (kind === 'credential_scope') {
        const agent = agentId && SAFE_AGENT_ID.test(agentId)
            ? `agent "${agentId}"`
            : 'this hook\'s agent (no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set)';
        return `This Marrow API key is not authorized to obtain action permits for ${agent}${suffix}. Use the API key issued to that agent, or set MARROW_FLEET_AGENT_ID (or MARROW_AGENT_ID) to the agent this key belongs to, then retry.`;
    }
    if (kind === 'unavailable') {
        return `Marrow is unavailable, so this protected action was denied${suffix}. Retry when Marrow is reachable.`;
    }
    return `Marrow did not allow this protected action${suffix}. ${plainControlFix(error)}`;
}
// Claude Code permission modes in which a PreToolUse "ask" reaches a person.
// bypassPermissions disables prompts, dontAsk auto-denies anything that would
// prompt, and plan mode with bypass available runs edits without prompting.
// https://code.claude.com/docs/en/hooks#pretooluse-decision-control
// https://code.claude.com/docs/en/permission-modes
const OWNER_PROMPT_PERMISSION_MODES = new Set(['default', 'acceptEdits', 'auto']);
const FIX_DEFAULT_MODE = 'To approve it, switch Claude Code to its default permission mode and retry this exact action.';
const FIX_HEADLESS = 'To approve it, retry this exact action in an interactive Claude Code session in default permission mode.';
/** Claude Code entrypoints with no one at a dialog (claude -p and the Agent SDKs); hooks inherit it. */
const HEADLESS_CLAUDE_ENTRYPOINTS = host_approval_1.HEADLESS_CLAUDE_ENTRYPOINTS;
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
    const entrypoint = typeof env.CLAUDE_CODE_ENTRYPOINT === 'string' ? env.CLAUDE_CODE_ENTRYPOINT : '';
    if (HEADLESS_CLAUDE_ENTRYPOINTS.has(entrypoint)) {
        return { available: false, unavailableReason: `${entrypoint}, no one sees a dialog`, headless: true, fix: FIX_HEADLESS };
    }
    const mode = typeof event.permission_mode === 'string' && /^[A-Za-z]{1,32}$/.test(event.permission_mode) ? event.permission_mode : '';
    if (!OWNER_PROMPT_PERMISSION_MODES.has(mode)) {
        return { available: false, unavailableReason: `Claude Code permission mode ${mode || 'unknown'} cannot guarantee an owner prompt`, fix: FIX_DEFAULT_MODE };
    }
    // Before Claude Code v2.1.211 the auto-mode classifier could approve a Bash
    // command outside the sandbox without the prompt a hook asked for. The hook
    // input carries scratchpad_dir only from v2.1.257, so it proves a fixed version.
    if (mode === 'auto' && !(typeof event.scratchpad_dir === 'string' && event.scratchpad_dir.trim())) {
        return { available: false, unavailableReason: 'this auto-mode session does not prove a Claude Code version whose classifier honors hook prompts', fix: FIX_DEFAULT_MODE };
    }
    return { available: true, unavailableReason: '' };
}
/** Claude Code modes and entrypoints in which an "ask" reaches nobody (auto, bypassPermissions, dontAsk; claude -p and the Agent SDKs). */
function noPersonAtPrompt(event, env = process.env) {
    const mode = typeof event.permission_mode === 'string' ? event.permission_mode : '';
    const entrypoint = typeof env.CLAUDE_CODE_ENTRYPOINT === 'string' ? env.CLAUDE_CODE_ENTRYPOINT : '';
    return mode === 'auto' || mode === 'bypassPermissions' || mode === 'dontAsk' || HEADLESS_CLAUDE_ENTRYPOINTS.has(entrypoint);
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
// Arbitration review is satisfied only by the account owner's choice of a
// proposal (one-tap link), never by a host prompt, so any arbitration signal keeps the denial.
function arbitrationReview(runtime) {
    const completion = runtime.completion_contract;
    const approval = asOptionalRecord(completion?.owner_approval);
    return Boolean(runtime.arbitration)
        || completion?.arbitration_receipt_required === true
        || (0, runtime_contract_1.ownerReceiptRequired)(approval)
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
// Why the gate held or blocked the action. The runtime's exact_next_action is
// written for API clients (endpoints to call) and is never relayed by a hook.
function gateReason(runtime) {
    return boundedText(runtime.risk_gate.reasons?.[0]?.message, 240);
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
            ? 'Marrow is holding this action for arbitration review: the account owner picks and approves one proposal before it runs. Do not run it yet.'
            : verdict.kind === 'denied'
                ? 'Marrow did not allow this action.'
                : ask
                    ? 'Marrow requires owner review before this action. Approve only if you authorize this exact action.'
                    : `Marrow requires owner review before this action, and no owner approval prompt is available (${prompt.unavailableReason}), so it was denied. Tell the operator it is waiting for the account owner's approval.${prompt.fix ? ` ${prompt.fix}` : ''}`;
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
/** The Cursor events where Cursor enforces "ask" with its own approval prompt (the installer's execution hooks). */
const CURSOR_ASK_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution']);
/** Keyless seatbelt: a host that cannot hand this action to its own approval prompt holds it (no account to approve it). */
exports.SEATBELT_HELD_TEXT = 'MARROW SEATBELT held this action: this host cannot show its own approval prompt here, and no Marrow account is linked to approve it. If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was held. For approval prompts, add a Marrow key: getmarrow.ai/docs#start-here.';
exports.SEATBELT_CURSOR_ASK_USER_TEXT = 'Marrow seatbelt (no account linked): approve this action here only if you expected it.';
exports.SEATBELT_CURSOR_ASK_AGENT_TEXT = 'Cursor is asking the user to approve this action (Marrow seatbelt, no account linked). Wait for the answer; do not retry it another way.';
/**
 * The keyless seatbelt's answer for an action it does not stop (spec §1.3 "pass": Marrow adds no
 * decision and the host's own permission flow runs). `heldBefore`: the 3.9.103 keyless hook held this
 * action (protected, or not read-only on Windsurf, Gemini or Grok). `null` means exit 0, no output.
 * - Not held before: exactly the answer 3.9.103 gave (its read-only and unprotected passes).
 * - Held before: never an explicit allow that could skip the host's own approval step.
 *   Claude Code and Codex `{}` (no permissionDecision), Cline `{cancel:false}`, Windsurf no output:
 *   the hosts' neutral answers (see PASS_THROUGH_HOSTS), so their own approval step runs.
 *   Gemini CLI `{"decision":"allow"}`: the installed guard passes only that or a fixed denial (no
 *   output is a launch failure that blocks), and Gemini applies its own policy and confirmation
 *   after the BeforeTool hook whatever an "allow" says, so it is Gemini's neutral answer.
 *   Cursor beforeShellExecution / beforeMCPExecution: "ask", so Cursor's own approval prompt decides.
 *   Cursor preToolUse (no neutral answer, "ask" not enforced) and Grok (its guard passes only an
 *   explicit allow or the fixed denial, and nothing shows an allow keeps Grok's own approval): held,
 *   as 3.9.103 did. Any other or missing Cursor event name is treated as preToolUse.
 */
function seatbeltPassOutput(harness, hookEventName, heldBefore) {
    if (!heldBefore)
        return localControlAllowOutput(harness);
    if (harness === 'windsurf')
        return null;
    if (harness === 'cline')
        return { cancel: false };
    if (harness === 'gemini')
        return { decision: 'allow' };
    if (harness === 'grok')
        return { decision: 'deny', reason: exports.GROK_FIXED_DENIAL };
    if (harness === 'cursor') {
        return typeof hookEventName === 'string' && CURSOR_ASK_EVENTS.has(hookEventName)
            ? { permission: 'ask', user_message: exports.SEATBELT_CURSOR_ASK_USER_TEXT, agent_message: exports.SEATBELT_CURSOR_ASK_AGENT_TEXT }
            : { permission: 'deny', user_message: exports.SEATBELT_HELD_TEXT, agent_message: exports.SEATBELT_HELD_TEXT };
    }
    return {};
}
function localLoopGuardDenyOutput(harness, reason) {
    const bounded = fitHookText(reason, hostTextLimit(harness));
    if (harness === 'windsurf')
        return null;
    if (harness === 'cursor')
        return { permission: 'deny', user_message: bounded, agent_message: bounded };
    if (harness === 'cline')
        return { cancel: true, errorMessage: bounded };
    // The installed Grok guard passes only an allow or this fixed denial; any other text is its launch failure (audit M1).
    if (harness === 'grok')
        return { decision: 'deny', reason: exports.GROK_FIXED_DENIAL };
    if (harness === 'gemini')
        return { decision: 'deny', reason: bounded };
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: bounded } };
}
function emitLoopGuardDenial(harness, reason) {
    if (harness === 'windsurf') {
        process.exitCode = 2;
        process.stderr.write(`${fitHookText(reason, hostTextLimit(harness))}\n`);
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
// The order classifyTool picks a type and lists surfaces in; earlier types are the more specific (stricter) ones.
const CLASSIFICATION_TYPES = ['security', 'publish', 'deploy', 'review', 'migration', 'audit', 'financial', 'process'];
const CLASSIFICATION_SURFACES = ['production', 'github', 'npm', 'secrets', 'database', 'financial'];
/**
 * The classification of one tool call. A Monitor command (and a native git
 * equivalent such as EnterWorktree) is classified exactly as Bash running it;
 * any other call carrying a command or script string gets the stricter of its
 * own classification and Bash's for that text (its own classification,
 * unchanged, when that is already at least as strict). A PowerShell call is
 * one of those, with Bash's reading in the PowerShell dialect (no read-only
 * allowlist) and never read-only. See toolPolicyReading.
 *
 * `postTool`: the PostToolUse hook (hook.ts) classifies a call that already ran, for the labels of its lifecycle event and the read-only
 * flag of the local loop guard; no approval, redaction or stored output reads the result. That path must add ~no latency, so it asks no
 * environment-print check and never loads the seatbelt mapper: its labels are the ones 3.9.103 gave (the secret-path table it shares with the
 * seatbelt is the one stricter difference). Only the pre-action hook decides (and holds) on what prints the environment.
 */
function classifyTool(event, options = {}) {
    const cwd = absoluteFolder(options.cwd) ?? absoluteFolder(event.cwd);
    if (cwd !== options.cwd)
        options = { ...options, cwd };
    const reading = (0, hook_tool_policy_1.toolPolicyReading)(event);
    if (!reading.shell.length && reading.base === 'named')
        return classificationFrom(classifyAsNamed(event, options));
    const shell = reading.shell.map((twin) => classifyAsNamed(twin, options));
    if (reading.exact) {
        const merged = shell.reduce(stricterParts);
        return classificationFrom(reading.bashLabel ? merged : { ...merged, tool: ownToolLabel(event) });
    }
    const own = reading.base === 'read' ? { ...classifyAsNamed((0, hook_tool_policy_1.readEquivalent)(event), options), tool: ownToolLabel(event) }
        : reading.base === 'non_acting' ? nonActingParts(event)
            : classifyAsNamed(event, options);
    const merged = shell.reduce(stricterParts, own);
    return classificationFrom(reading.dialect === 'powershell' ? { ...merged, readOnly: false } : merged);
}
function ownToolLabel(event) {
    return String(event.tool_name || 'tool').slice(0, 64);
}
// A call whose words are not actions (toolPolicyReading): reported, never read-only, never protected by its text.
function nonActingParts(event) {
    return { tool: ownToolLabel(event), type: 'process', surfaces: [], readOnly: false, protected: false };
}
/** The `type on surfaces` text of a classification, as the runtime action carries it. */
function typeText(parts) {
    return `${parts.type} on ${parts.surfaces.join(', ') || 'workspace'}`;
}
/**
 * `a`, unchanged, when it is at least as strict as `b` on every axis; otherwise the stricter of each. The strictest type wins, every surface
 * of both is kept, and a type that `security` displaces stays in `under` (typeText), so a hold never drops what the other part says.
 */
function stricterParts(a, b) {
    const rank = (type) => {
        const index = CLASSIFICATION_TYPES.indexOf(type);
        return index < 0 ? CLASSIFICATION_TYPES.length : index;
    };
    const type = rank(a.type) <= rank(b.type) ? a.type : b.type;
    const displaced = (parts) => (type === 'security' && parts.type !== type && parts.type !== 'process' ? [typeText(parts)] : []);
    const keptBy = (parts, texts) => texts.every((text) => (parts.under ?? []).includes(text));
    const covers = (!a.readOnly || b.readOnly) && (a.protected || !b.protected) && rank(a.type) <= rank(b.type)
        && b.surfaces.every((surface) => a.surfaces.includes(surface))
        && keptBy(a, [...(b.under ?? []), ...displaced(b)]);
    if (covers)
        return a;
    const surfaces = new Set([...a.surfaces, ...b.surfaces]);
    const under = [...new Set([...(a.under ?? []), ...(b.under ?? []), ...displaced(a), ...displaced(b)])];
    return {
        tool: a.tool,
        type,
        surfaces: [...CLASSIFICATION_SURFACES.filter((surface) => surfaces.has(surface)), ...[...surfaces].filter((surface) => !CLASSIFICATION_SURFACES.includes(surface))],
        readOnly: a.readOnly && b.readOnly,
        protected: a.protected || b.protected,
        ...(under.length ? { under } : {}),
    };
}
let envDumpTools;
let lastEnvDumpAnswer = null;
// Every form that prints the environment holds one of these words (env also covers environ, getenv, printenv, ENV and every wrapper's
// last word). The mapper (about 100 ms to load and run once) is asked only for a command that holds one. Four words are read more closely
// (what the mapper needs, and nothing less), each unless an expansion could spell it:
//   set    only a bare `set` (the mapper's rule is no operand: `set -e` and the word in a message are not);
//   ps     only with an `e` or `E` after it (BSD `ps e`, `-E`); `ps aux` and `docker ps` are not;
//   jq     only with `env` in the text (a filter reads the environment by that word);
//   proc   only as `/proc`, or `process[...]` (a computed name); `process.env` holds `env`.
// A literal read of one non-secret name (`process.env.HOME`, the mapper's own rule) and a word that only joins `env` to a branch name in a
// plain `git` command (`git checkout -b env-fix`) hold nothing. A `$`, a backtick or a brace can spell any of these words, so a command that
// holds one of them and a narrowed word is read exactly as before.
exports.ENV_FILTER_SECRET_NAME = /KEY|TOKEN|SECRET|PASS|CRED/i; // the mapper's SECRET_VAR (src/seatbelt/tables.ts); a test keeps the two equal
const ENV_DUMP_WORDS = /env|export|declare|typeset|readonly|compgen|tmux|systemctl|strace|php|awk|global|\bproc\b|\bprocess\s*(?:\?\.\s*)?\[|\bset\b(?=[^\S\n]*(?:$|[\n\r;&|)}<>#]|\d+[<>]))/i;
const NARROWED_WORDS = /\bjq\b|\bps\b|\bset\b|proc/i;
const EXPANSION = /[$`{]/;
const ONE_NAME_READ = /\bprocess\.env\.(?!(?:items|keys|copy)\b)([A-Za-z_]\w*)/g;
const PLAIN_GIT = /^\s*git\s[^$`;&|<>(){}\\\n]*$/;
/** False for a command that cannot print the environment: the keyed hook then never loads the mapper for it. */
function mayPrintEnvironment(command) {
    // An ANSI-C quote can spell a word in escapes.
    if (command.includes("$'") || command.includes('$"'))
        return true;
    // Quotes and backslashes split a word without changing it (`e'n'v`).
    const text = command.replace(/['"\\]/g, '');
    // The word `env` only hyphen-joined in a plain git command with no secret-looking word (data to git, never a program or a name).
    let words = PLAIN_GIT.test(command) && !exports.ENV_FILTER_SECRET_NAME.test(command) ? text.replace(/-env(?![\w])|env-/gi, '') : text;
    words = words.replace(ONE_NAME_READ, (read, name) => (exports.ENV_FILTER_SECRET_NAME.test(name) ? read : ''));
    if (ENV_DUMP_WORDS.test(words))
        return true;
    if (globInFolderPart(words))
        return true;
    // `ps` with an `e` or `E` anywhere after the first `ps` (an `e` after a later `ps` is after the first one too: one scan, no backtracking).
    const ps = /\bps\b/i.exec(words);
    if (ps && /[eE]/.test(words.slice(ps.index + 2)))
        return true;
    return EXPANSION.test(text) && NARROWED_WORDS.test(text);
}
/**
 * A path whose folder part holds a glob character can spell `/proc/self/task/1/environ` with neither word in it (`/p*\/self/e*`, `/???c/s*\/e*`,
 * `/p[r]oc/self/en[v]iron`). A word that starts like a path (`/`, `~`, `.`, `$`), or any word after a `cd` (or when the hook itself runs in `/` or
 * under `/proc`), is asked of the mapper when a glob sits in a folder of it. One pass over the words, no backtracking.
 */
const WORD_BREAK = /[\s=:<>(;&|]+/;
const GLOB_CHAR = /[*?[]/;
const PATH_START = /^[/~.$]/;
const CHANGES_FOLDER = /\b(?:cd|pushd|popd)\b/;
function runsAtFilesystemRoot() {
    try {
        const cwd = process.cwd();
        return cwd === '/' || cwd === '/proc' || cwd.startsWith('/proc/');
    }
    catch {
        return false;
    }
}
function globInFolderPart(words) {
    const anywhere = CHANGES_FOLDER.test(words) || runsAtFilesystemRoot();
    for (const word of words.split(WORD_BREAK)) {
        const slash = word.lastIndexOf('/');
        if (slash > 0 && (anywhere || PATH_START.test(word)) && GLOB_CHAR.test(word.slice(0, slash)))
            return true;
    }
    return false;
}
const MAPPER_UNSURE = /^(?:mapper_error|budget_)/;
/**
 * False for a command that cannot read the host-approvals state file: the keyed hook then does not load the mapper for it on that account. A command that
 * can spell the folder, or a folder that holds it, holds the word `approvals` or `marrow` (quotes and backslashes split a word without changing it), an
 * ANSI-C quote, a glob in a folder part of a path that starts at the home (`~/.m*\/h*\/state.json`; `cd ~/.marrow; cat h*\/s*` holds `marrow`), or a tree walker (grep, rg, find, tar, cp, ...) given
 * the home or the root, or given `.`/`..`/`*` while the hook runs in the home or the root. A path that only a computed name spells
 * (`cd ~; cd .m*; cd h*; cat s*`) is read by the keyless mapper but not asked of it here.
 */
const TREE_WALKERS = /\b(?:grep|egrep|fgrep|zgrep|rg|ag|ack|find|tar|zip|rsync|cp|scp|xargs|7z|bsdtar|cpio|pax)\b/;
const HOME_OR_ROOT_OPERAND = /(?:^|[\s=:'"])(?:~|\$HOME|\$\{HOME\}|\/home|\/Users|\/)\/?(?=[\s'";&|)]|$)/;
const CWD_RELATIVE_OPERAND = /(?:^|\s)(?:\.\.?|\*|\.\/\*|\.\*)\/?(?=\s|$)/;
function runsInHomeOrAbove() {
    try {
        const home = (process.env.HOME || (0, node_os_1.homedir)()).replace(/\/+$/, '');
        const cwd = process.cwd().replace(/\/+$/, '') || '/';
        return cwd === '/' || cwd === home || home.startsWith(`${cwd}/`);
    }
    catch {
        return false;
    }
}
const HOME_PATH_START = /^(?:~|\$HOME|\$\{HOME\}|\.|\/home\/|\/Users\/|\/root\/)/;
/** A glob in a folder part of a path that starts at the home or in the working folder (the env-dump filter keeps its own glob rule). */
function homeGlobInFolderPart(words) {
    for (const word of words.split(WORD_BREAK)) {
        const slash = word.lastIndexOf('/');
        if (slash > 0 && GLOB_CHAR.test(word.slice(0, slash)) && HOME_PATH_START.test(word))
            return true;
    }
    return false;
}
function mayReadApprovalState(command) {
    if (command.includes("$'") || command.includes('$"'))
        return true;
    const text = command.replace(/['"\\]/g, '').toLowerCase();
    if (text.includes('approvals') || text.includes('marrow') || homeGlobInFolderPart(text))
        return true;
    if (!TREE_WALKERS.test(text))
        return false;
    return HOME_OR_ROOT_OPERAND.test(command) || (CWD_RELATIVE_OPERAND.test(command) && runsInHomeOrAbove());
}
/**
 * False for a command that cannot read a secret FILE inside code the keyed policy does not parse (a quoted `bash -c`, `eval`, `sudo sh -c`, `ssh host` or
 * `xargs` string is one word to it). A command that can spell one holds a word of the secret-path table (src/secret-paths.ts: `.env`, `.npmrc`, `.ssh`, ...)
 * or of the policy's secret file names, a word that starts with a dot and holds a glob or an expansion (`.e*`, `.e$X`), a variable set to a dot
 * word beside any expansion (`A=.e; B=nv; cat $A$B`), or an expansion of a secret-looking variable (`$GITHUB_TOKEN`: ENV_FILTER_SECRET_NAME). Env and
 * process words are not here (mayPrintEnvironment has them), nor are the programs that print a credential, nor an ANSI-C quote: the same text-only
 * answer as before holds for those. A name that variables spell with no dot word in an assignment (`A=x.e`) is read by the keyless mapper but not asked
 * of it here, as for the state file above. A dot word that only a brace spells (`cat .en{v,x}`) is not asked either: test/pre-action-hook.test.js pins it as
 * not protected, and that expectation is left as it is.
 */
const SECRET_FILE_WORDS = /(?<!process)\.env(?![a-z0-9_])|\.(?:ssh|aws|azure|kube|docker|gnupg|config|claude|marrow)|npmrc|netrc|pypirc|pgpass|git-credentials|dev\.vars|id_(?:rsa|dsa|ecdsa|ed25519)|hosts\.yml|settings\.local|htpasswd|my\.cnf|yarnrc|\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk)\b/;
// A word (split at white space and `/`) with a dot that starts it, or follows one of `=:(;&|<>`, and a glob character or an expansion after that dot (`.e*`,
// `a=.e?v`, `.e$X`). One pass over the words and the first such dot only (a later dot's rest is part of its rest): linear, where one regular expression
// for it took seconds on a 100 KB command of `a=.b` repeated.
const DOT_LEAD = '=:(;&|<>';
function dotWordSpelled(text) {
    for (const word of text.split(/[\s/]+/)) {
        let dot = word.indexOf('.');
        while (dot > 0 && !DOT_LEAD.includes(word[dot - 1]))
            dot = word.indexOf('.', dot + 1);
        if (dot !== -1 && /[*?[$`]/.test(word.slice(dot + 1)))
            return true;
    }
    return false;
}
// A variable set to a dot word (`A=.e; B=nv; cat $A$B`) and an expansion anywhere: the name may be spelled by joining them.
const ASSIGNED_DOT_WORD = /(?:^|[\s;&|(])[a-z_]\w*=\.[^\s/;&|)]*/;
const SECRET_VARIABLE_USE = new RegExp(`\\$\\{?!?\\w*(?:${exports.ENV_FILTER_SECRET_NAME.source.toLowerCase()})`);
function mayReadSecret(command) {
    const text = command.replace(/['"\\]/g, '').toLowerCase();
    return SECRET_FILE_WORDS.test(text) || dotWordSpelled(text) || (text.includes('$') && ASSIGNED_DOT_WORD.test(text)) || SECRET_VARIABLE_USE.test(text);
}
/**
 * `link` when a word of the command is a symbolic link, or a path through one (it reads as what it points at, whatever its name; the text alone cannot say);
 * with `onlySecret` (a command the policy reads whole), only a link whose target is a secret path. `unread` when the command has more words than the limit.
 * A word is read as a path from the working folder, the home (`~`, `$HOME`) and any folder the command names that exists (a `cd` target); words that hold an
 * expansion or a glob are not paths yet. The mapper is then given the real `realpath` for this command, and only for it. A command with more words than the
 * limit is asked of the mapper, so an unread word is never a pass.
 */
const LINK_WORD_LIMIT = 2048;
// A subshell `(cat x)`, a substitution `$(cat x)` and a backtick pair `cat x` end a word with `)` or a backtick, so the words are read split there too
// (WORD_BREAK has neither). A name that holds one of those characters is still read whole: a word is a path in either spelling.
const LINK_WORD_BREAK = /[\s=:<>(;&|)`}]+/;
/** `value` when it is an absolute path (the keyless seatbelt's own test for an event's cwd, and no NUL byte), else undefined. */
function absoluteFolder(value) {
    return typeof value === 'string' && value.startsWith('/') && !value.includes('\0') ? value : undefined;
}
function passwdHome() {
    try {
        const home = (0, node_os_1.userInfo)().homedir;
        return typeof home === 'string' && home.startsWith('/') ? home : null;
    }
    catch {
        return null;
    }
}
/**
 * The folders a command's words are read in. The hook process's own (its working folder and $HOME) are always one: that is the reading every earlier build
 * gave, so no answer is looser than it. An event that names an absolute working folder adds the keyless seatbelt's reading of it (that folder and the passwd home),
 * so a host that spawns the hook in another folder is read as the seatbelt reads it, a relative link name included. Any of them can hold the command.
 */
function wordContexts(eventCwd) {
    const contexts = [];
    try {
        contexts.push({ cwd: process.cwd(), home: process.env.HOME || (0, node_os_1.homedir)() });
    }
    catch { /* the hook's own folder is gone: the event's is read alone */ }
    const eventContext = eventCwd === undefined ? null : { cwd: eventCwd, home: passwdHome() || '/nonexistent-home' };
    if (eventContext && !contexts.some((own) => own.cwd === eventContext.cwd && own.home === eventContext.home))
        contexts.push(eventContext);
    return contexts;
}
function namesSymlink(command, onlySecret, contexts) {
    const text = command.replace(/['"\\]/g, '');
    const readable = (word) => word.length > 0 && word.length <= 4096 && !word.startsWith('-') && !/[*?[{$`]/.test(word.replace(/^\$\{?HOME\}?(?=\/|$)/, ''));
    const whole = text.split(WORD_BREAK).filter(readable);
    const known = new Set(whole);
    const words = whole.concat(text.split(LINK_WORD_BREAK).filter((word) => readable(word) && !known.has(word)));
    let unread = false;
    for (const where of contexts) {
        const answer = namesSymlinkIn(command, words, onlySecret, where);
        if (answer === 'link')
            return 'link';
        if (answer === 'unread')
            unread = true;
    }
    return unread ? 'unread' : 'none';
}
function namesSymlinkIn(command, words, onlySecret, where) {
    const cwd = where.cwd;
    const home = where.home.replace(/\/+$/, '');
    const bases = [cwd];
    const moved = (word, base) => {
        const lexical = word === '~' || word.startsWith('~/') ? (0, node_path_1.resolve)(home, word.slice(2)) : word.startsWith('$HOME') || word.startsWith('${HOME}') ? (0, node_path_1.resolve)(home, word.replace(/^\$\{?HOME\}?\/?/, '')) : (0, node_path_1.resolve)(base, word);
        // `/proc/self` and `/proc/thread-self` are links the kernel makes; a word under /proc is read by the env-dump words, not as a link.
        if (lexical === '/proc' || lexical.startsWith('/proc/'))
            return false;
        try {
            const real = (0, node_fs_1.realpathSync)(lexical);
            return real !== lexical && (!onlySecret || (0, hook_tool_policy_1.isSecretPath)(real));
        }
        catch {
            return false;
        }
    };
    let reads = 0;
    if (CHANGES_FOLDER.test(command)) {
        for (const word of words) {
            if (bases.length >= 9)
                break;
            const lexical = word.startsWith('/') ? word : (0, node_path_1.resolve)(cwd, word);
            try {
                if ((0, node_fs_1.statSync)(lexical).isDirectory())
                    bases.push(lexical);
            }
            catch { /* not a folder that exists */ }
        }
    }
    for (const word of words) {
        for (const base of bases) {
            reads += 1;
            if (reads > LINK_WORD_LIMIT)
                return 'unread';
            if (moved(word, base))
                return 'link';
        }
    }
    return 'none';
}
const fsGone = (error) => ['ENOENT', 'ENOTDIR'].includes(error?.code || '');
const fsDenied = (error) => ['EACCES', 'EPERM'].includes(error?.code || '');
const REAL_FS_VIEW = {
    readFile: () => null,
    realpath(path) { try {
        return (0, node_fs_1.realpathSync)(path);
    }
    catch (error) {
        if (fsGone(error))
            return null;
        throw error;
    } },
    readdir(path) { try {
        return (0, node_fs_1.readdirSync)(path);
    }
    catch (error) {
        if (fsGone(error) || fsDenied(error))
            return null;
        throw error;
    } },
};
const TEXT_ONLY_FS_VIEW = { readFile: () => null, realpath: (path) => path };
// What the second run may add to the first: an S4 hit on a PATH (a secret file named, a link to one, a glob or pattern that can spell one, a secret folder
// walked). Never `ps_environment_loose` or a credential-printing command (`gh auth token`, `aws sts get-session-token`: not a read of a file), and never a
// reason the mapper only gives a word that is no path (the pattern of `grep .env README.md`) in a command the policy reads whole (policyReadsAllWords).
const SECOND_RUN_REASONS = /_secret_(?:path|pattern|dir)$|_secret_name$|_unknown_link$|^copy_secret_directory$|^tool_grep_glob_secret$|^tripwire_env_file$/;
// `eventCwd` comes first so classifyAsNamed can bind it and hand the policy a one-argument check.
function shellPrintsEnvironment(eventCwd, command) {
    const contexts = wordContexts(eventCwd);
    const where = contexts.map((context) => `${context.cwd}\0${context.home}`).join('\n');
    if (lastEnvDumpAnswer && lastEnvDumpAnswer.command === command && lastEnvDumpAnswer.where === where)
        return lastEnvDumpAnswer.dumps;
    const secretNamed = mayReadSecret(command);
    const readsWhole = (0, hook_tool_policy_1.policyReadsAllWords)(command);
    const links = namesSymlink(command, readsWhole, contexts);
    // A command the policy reads whole is held when a link in it points at a secret path (the policy judges the target as it judges any path); any other
    // command that names a link, or has too many words to read, is asked of the mapper.
    const linkedSecret = readsWhole && links === 'link';
    const linked = linkedSecret || (readsWhole ? links === 'unread' : links !== 'none');
    if (!mayPrintEnvironment(command) && !mayReadApprovalState(command) && !secretNamed && !linked)
        return false;
    if (linkedSecret) {
        lastEnvDumpAnswer = { command, where, dumps: true };
        return true;
    }
    let dumps;
    try {
        if (envDumpTools === undefined) {
            try {
                // eslint-disable-next-line @typescript-eslint/no-var-requires
                envDumpTools = { mapper: require('./seatbelt/mapper'), reasons: require('./seatbelt/env-dump').ENV_DUMP_REASONS };
            }
            catch {
                envDumpTools = null;
            }
        }
        if (!envDumpTools)
            dumps = ENV_DUMP_WORDS.test(command) || mayReadApprovalState(command) || secretNamed || linked;
        else {
            const { mapper, reasons } = envDumpTools;
            const namesMarrow = /approvals|\.marrow/i.test(command.replace(/['"\\]/g, ''));
            const ask = (fs, at) => mapper.evaluateSeatbeltShell(command, {
                cwd: at.cwd,
                home: at.home,
                tmpdir: '/tmp',
                platform: process.platform,
                fs,
                git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null },
            });
            // The same answer holds both reads: the env-dump reasons, and the host-approvals state file: the reason the mapper adds to a hit on it, or
            // any S4 or S0 stop of a command that names the folder or ~/.marrow (a wrapper, a copy, a walk that reaches it); and a mapper that cannot decide
            // (an error, an exhausted budget) on a command that may read a secret.
            const unsure = ENV_DUMP_WORDS.test(command) || mayReadApprovalState(command) || secretNamed || linked;
            const holds = (decision, paths) => decision.hits.some((hit) => (hit.category === 'S4' && (reasons.has(hit.reason) || hit.reason === secret_paths_1.APPROVAL_STATE_REASON || (paths && SECOND_RUN_REASONS.test(hit.reason)))) || ((hit.category === 'S4' || hit.category === 'S0') && namesMarrow)
                || (MAPPER_UNSURE.test(hit.reason) && unsure));
            // The text alone is read first, exactly as before. A command that can name a secret file inside code the policy does not read (a wrapper, a glob, a
            // variable, a name it cannot parse), or names a link, is then read again with the real `realpath` and `readdir` (no file contents): a word is a secret
            // path only where the file is there (`process.env` in `grep -rn process.env src` names no file; the text alone cannot say), a link reads as its target
            // and a glob as the names it expands to. Either run can hold the command, so no answer is looser than the text's.
            if (!contexts.length)
                throw new Error('no working folder');
            dumps = contexts.some((at) => holds(ask(TEXT_ONLY_FS_VIEW, at), false) || (((secretNamed && !readsWhole) || linked) && holds(ask(REAL_FS_VIEW, at), true)));
        }
    }
    catch {
        dumps = ENV_DUMP_WORDS.test(command) || mayReadApprovalState(command) || secretNamed || linked;
    }
    lastEnvDumpAnswer = { command, where, dumps };
    return dumps;
}
/** Whether a shell call (or the shell text another tool carries) runs the installer as a control-off route (control-routes.ts). */
function controlRouteCall(event) {
    if (!(0, hook_tool_policy_1.isShellTextTool)(event))
        return false;
    const input = asRecord(event.tool_input);
    const texts = typeof event.tool_input === 'string' ? [event.tool_input]
        : ['command', 'cmd', 'script'].map((key) => input?.[key]).filter((value) => typeof value === 'string');
    return texts.some((text) => (0, control_routes_1.controlRoute)(text));
}
/** The classification of a call under its own tool name only (every tool before the built-ins were hooked). */
function classifyAsNamed(event, options) {
    const tool = String(event.tool_name || 'tool').slice(0, 64);
    const normalizedTool = (0, hook_tool_policy_1.normalizeHookToolName)(tool);
    // Editing and task tools are judged by their target; shell-like words in the
    // content they write or the subject they record are not actions.
    const shellGoverned = (0, hook_tool_policy_1.isShellGovernedTool)(event);
    // MCP-10: a way to switch Marrow control off through the installer is a security action on marrow-control, held for the account owner.
    // A hold is merged with the classification of the whole call below, never returned in its place: the rest of a chain keeps every surface
    // and every risk category it has without the hold.
    const controlRoute = controlRouteCall(event);
    const command = shellGoverned ? (0, hook_tool_policy_1.hookToolCommand)(event) : '';
    const input = (0, hook_tool_policy_1.toolClassificationText)(event).toLowerCase();
    // A look-alike of Marrow's own tool is never read-only, whatever its verb.
    // The PostToolUse path passes no check (options.postTool): the mapper is never loaded for it.
    const printsEnvironment = options.postTool === true ? undefined : shellPrintsEnvironment.bind(null, options.cwd);
    const readOnly = options.ownUnproven !== true && (0, hook_tool_policy_1.isReadOnlyToolEventAsNamed)(event, printsEnvironment);
    const secretAccess = (0, hook_tool_policy_1.isSecretMaterialAccessAsNamed)(event, printsEnvironment);
    // T2: a write to Marrow's control files, a host's hooks settings or a file that makes a command run later is a security action, not an audit one.
    const selfProtected = readOnly && !controlRoute ? null : (0, self_protect_1.selfProtectKind)(event, options.cwd);
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
        || ((0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) && (options.ownUnproven === true || !(0, hook_tool_policy_1.isOfficialMarrowMcpTool)(event.tool_name)))
        || (['use_mcp_tool', 'use_tool'].includes(normalizedTool) && !(0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(event)));
    const full = { tool, type, surfaces, readOnly, protected: protectedAction };
    const held = [...new Set([controlRoute ? 'marrow-control' : null, selfProtected])].filter((surface) => surface !== null);
    return held.length ? stricterParts({ tool, type: 'security', surfaces: held, readOnly: false, protected: true }, full) : full;
}
/** The role the runtime call carries: that of the type, or, where `security` displaced a type (ClassificationParts.under), the strictest displaced one, as 3.9.108 sent it. */
function runtimeRole(parts) {
    const rank = (type) => { const index = CLASSIFICATION_TYPES.indexOf(type); return index < 0 ? CLASSIFICATION_TYPES.length : index; };
    const displaced = (parts.under ?? []).map((text) => text.split(' on ')[0]).sort((x, y) => rank(x) - rank(y));
    const type = parts.type === 'security' && displaced.length ? displaced[0] : parts.type;
    return type === 'publish' ? 'deploy' : ['deploy', 'review', 'migration', 'audit'].includes(type) ? type : 'general';
}
function classificationFrom(parts) {
    const { tool, type, surfaces, readOnly } = parts;
    const protectedAction = parts.protected;
    const risk = readOnly ? 'low' : protectedAction ? 'high' : 'medium';
    // The hold surfaces come first: a hold merged with a fuller classification keeps the label it has alone.
    const target = surfaces.includes('marrow-control') ? `marrow:${type}`
        : surfaces.includes('persistence') ? `host:${type}`
            : surfaces.includes('npm') ? `npm:${type}`
                : surfaces.includes('github') ? `github:${type}`
                    : surfaces.includes('production') ? `production:${type}`
                        : surfaces.includes('database') ? `database:${type}`
                            : surfaces.includes('financial') ? `financial:${type}`
                                : surfaces.includes('secrets') ? `secrets:${type}`
                                    : `workspace:${type}`;
    return {
        action: `classified ${tool} action: ${type} on ${surfaces.join(', ') || 'workspace'}${(parts.under ?? []).map((text) => `; classified ${tool} action: ${text}`).join('')}`,
        target,
        type,
        role: runtimeRole(parts),
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
        // Room for the code at the end only for the fixed keyless texts; every other text (it can carry a server error, an agent id) keeps the base bound.
        const denial = boundedText(result.enforcementError || 'Marrow could not verify the required action permit. Retry after governance is available.', isKeylessHoldText(result.enforcementError) ? STOP_TEXT_LIMIT : CURSOR_ENFORCEMENT_LIMIT);
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
        return {
            cancel: true,
            errorMessage: result.credentialsUnavailable === true
                ? fitHookText(result.enforcementError, CLINE_ERROR_LIMIT)
                : result.failure === 'credential_scope'
                    ? 'This Marrow API key is not authorized to obtain action permits for this agent. Use the API key issued to this agent and retry.'
                    : result.failure === 'unavailable'
                        ? 'Marrow is unavailable, so this protected action was denied. Retry when Marrow is reachable.'
                        : `Marrow could not confirm a permit for this protected action. ${DOCTOR_FIX}`,
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
function preActionHookOutput(result, harness = 'claude-code', prompt = NO_OWNER_PROMPT, 
/** An older service without host approvals: Claude Code asks in its dialog exactly as 3.9.98 did. */
legacyServiceAsk = false) {
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
    if (verdict && legacyServiceAsk && verdict.kind === 'review' && prompt.available && harness !== 'codex') {
        return {
            hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'ask',
                permissionDecisionReason: gateDecisionMessage(verdict, true, prompt),
                ...context,
            },
        };
    }
    if (verdict) {
        // An ordinary hold the server lets the host approve is answered by
        // heldActionHookOutput. Here every gate denies: block, arbitration, and a
        // review the server offered no chat or terminal approval for.
        const reason = verdict.kind === 'review' && prompt.available && !legacyServiceAsk
            ? { available: false, unavailableReason: 'this Marrow service did not offer a chat or terminal approval for this hold' }
            // The fix names default mode, which asks only on a legacy service; any other service denies there too.
            : legacyServiceAsk ? prompt : { ...prompt, fix: undefined };
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
function emitDecision(result, harness = 'claude-code', prompt = NO_OWNER_PROMPT, legacyServiceAsk = false) {
    if (harness === 'windsurf') {
        const decision = windsurfPreActionDecision(result);
        process.exitCode = decision.exitCode;
        if (decision.stderr)
            process.stderr.write(decision.stderr);
        return { denied: decision.exitCode === 2, reason: decision.stderr.trim() };
    }
    if (result.outage)
        process.stderr.write(`${hook_contract_1.MARROW_OUTAGE_WARNING}\n`);
    const output = preActionHookOutput(result, harness, prompt, legacyServiceAsk);
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
async function withTimeout(operation, timeoutMs = exports.PRE_ACTION_CONTROL_TIMEOUT_MS) {
    const controller = new AbortController();
    let timer;
    try {
        return await Promise.race([
            operation(controller.signal),
            new Promise((_, reject) => {
                timer = setTimeout(() => {
                    controller.abort();
                    reject(new PreActionControlTimeoutError());
                }, timeoutMs);
            }),
        ]);
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
/**
 * The gate's risk categories for this classified action, as the server
 * derives them from the same action, type and surfaces (risk-categories.ts).
 * Used only while Marrow cannot be reached, to keep owner-protected actions held.
 */
const LOCAL_CATEGORY_PATTERNS = [
    ['production_deploy', /\b(deploy|release|rollback|rollout|production|prod)\b/i],
    ['source_control', /\b(merge|pull request|pr|github|main|master)\b/i],
    ['data_migration', /\b(migration|migrate|schema|database|sql|table|column)\b/i],
    ['secrets_security', /\b(secret|token|key|credential|rotate|revoke|security|waf|auth)\b/i],
    ['billing_access', /\b(billing|payment|invoice|subscription|plan|tier|permission|access)\b/i],
    ['destructive_action', /\b(?:delete|drop|truncate|purge|destroy|remove all|wipe)\b/i],
];
function localApprovalCategories(action) {
    const text = `${action.action} ${action.type} ${action.surfaces.join(' ')}`;
    const categories = LOCAL_CATEGORY_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([category]) => category);
    // Broader than the server's package-publish check on purpose: it only keeps an action held.
    if (action.type.toLowerCase() === 'publish' || /\bpublish\b/i.test(text))
        categories.unshift('package_publish');
    return categories;
}
/**
 * Positive evidence that a person is at this host for a call Marrow cannot ask
 * about: a local interactive Codex, Gemini CLI or Cline CLI process, Cline or
 * Windsurf inside the editor app, or a local Cursor session (sessionStart).
 * Missing evidence is not attended.
 */
function attendedConfirmed(ctx, cursorInteractive) {
    if (ctx.host === 'codex' || ctx.host === 'gemini' || ctx.host === 'cline' || ctx.host === 'windsurf')
        return (0, host_session_1.localInteractiveSession)(ctx.host) === true;
    if (ctx.host === 'cursor')
        return cursorInteractive === true;
    return false;
}
/**
 * Nobody is in this run: headless Claude Code (sdk-*, its GitHub Action), a
 * scripted Codex or Gemini CLI run (`codex exec`, `gemini -p`), or a Cursor
 * background agent. Missing evidence is not unattended.
 */
function unattendedRun(ctx, claudePrompt, cursorInteractive) {
    if (ctx.host === 'claude-code')
        return claudePrompt.headless === true;
    if (ctx.host === 'codex' || ctx.host === 'gemini')
        return (0, host_session_1.localInteractiveSession)(ctx.host) === false;
    // Cursor: sessionStart reports local sessions; without it (cloud agents) or as a background agent, nobody is there.
    if (ctx.host === 'cursor')
        return cursorInteractive !== true;
    // Grok, Cline, Windsurf: attended only with positive evidence of a person's session.
    if (ctx.host === 'grok' || ctx.host === 'cline' || ctx.host === 'windsurf')
        return (0, host_session_1.localInteractiveSession)(ctx.host) !== true;
    return false;
}
/** The hook's answer for a held action on any host (Windsurf answers through its exit code). */
function emitHeldPlan(harness, plan, code = null) {
    emitHookOutput(harness, heldActionHookOutput(harness, plan, code), plan.kind === 'deny' ? plan.agentText : undefined);
}
/** Work that does not decide the answer, done after it is written and inside the hook's budget. */
async function afterAnswer(ctx, work) {
    try {
        if (work.link)
            await (0, host_approval_1.requestOwnerLink)(ctx, work.link, 0);
        if ((0, host_approval_1.remainingMs)(ctx) > 800)
            await (0, host_approval_1.flushHoldOutbox)(ctx, 2, Math.min(4_000, (0, host_approval_1.remainingMs)(ctx) - 200));
    }
    catch { /* best effort: a later hook resends queued work */ }
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
/**
 * `marrow-mcp seatbelt-status`: exactly one line of JSON, exit 0. Read-only. On any error the unknown line.
 * The installer's doctor reads it; it is not a user feature.
 */
function runSeatbeltStatusCommand() {
    let status = { mode: 'unknown', reasons: [] };
    try {
        status = require('./seatbelt/hook').seatbeltStatus();
    }
    catch { /* the unknown line */ }
    process.stdout.write(`${JSON.stringify({ mode: status.mode, reasons: status.reasons })}\n`);
}
/**
 * I3: whether a real outage (the gate never answered) holds this action. Never looser than master,
 * which allowed every action in an outage. A shell command is read by the seatbelt mapper: held for an
 * S0-S5/S-x hit or a program on the outage list (git push, publish, deploy, remote delete), allowed
 * when the mapper read all of it and found neither (words in a message, a path or a comment never hold
 * it). Anything else, or a mapper that could not finish, keeps `classifiedHighRisk` (F2).
 */
function outageHolds(classifiedHighRisk, read) {
    let reading = { shell: false, risk: 'unknown' };
    try {
        reading = read();
    }
    catch { /* unknown: the classifier's answer */ }
    if (reading.risk === 'high')
        return true;
    if (reading.shell && reading.risk === 'not_high')
        return false;
    return classifiedHighRisk;
}
/**
 * The hold text of the keyless fallback, naming its reason. The words live in the seatbelt module (a lazy
 * require, like the rest of the keyless path); if it cannot load the generic wording stands.
 */
function setupUnconfirmedHold(modeReason) {
    try {
        return require('./seatbelt/fallback-copy').setupUnconfirmedText(modeReason);
    }
    catch {
        return exports.SETUP_UNCONFIRMED_TEXT;
    }
}
let keylessHoldTexts = null;
/**
 * True only for the fixed texts the keyless path sets as enforcementError (NO_KEY_TEXT, CLAIMED_NO_KEY_TEXT, or one
 * setupUnconfirmedHold text per row of the fallback table). An exact match against that generated set: never a prefix,
 * a pattern or a flag, so no other text, whatever it starts with, is taken for one of them.
 */
function isKeylessHoldText(text) {
    if (typeof text !== 'string')
        return false;
    if (text === exports.NO_KEY_TEXT || text === exports.CLAIMED_NO_KEY_TEXT || text === exports.SETUP_UNCONFIRMED_TEXT)
        return true;
    try {
        keylessHoldTexts ??= new Set(require('./seatbelt/fallback-copy').setupUnconfirmedTexts());
        return keylessHoldTexts.has(text);
    }
    catch {
        return false;
    }
}
function seatbeltEvent(source, rawEvent) {
    const raw = asRecord(rawEvent) || {};
    const event = source;
    return {
        tool_name: source.tool_name, tool_input: source.tool_input, cwd: event.cwd ?? raw.cwd, truncated: event.input_truncated === true,
        session: source.session_id || source.conversation_id || source.task_id || undefined,
    };
}
async function runPreActionHookCommand(input) {
    // N1: IPv4 first with happy eyeballs, set once before any request this hook makes.
    (0, ipv4_first_1.preferIpv4FirstWithHappyEyeballs)();
    // Account mode: the S0-S5 floor in watch runs after the answer is written, for the record only.
    const watch = {};
    try {
        await runPreActionHook(input, watch);
    }
    finally {
        if (watch.harness && watch.event) {
            try {
                require('./seatbelt/hook').accountFloor(watch.harness, watch.event, (0, host_approval_1.preToolDeadline)((0, host_approval_1.approvalHostFor)(watch.harness)));
            }
            catch { /* watch never changes the answer */ }
        }
    }
}
async function runPreActionHook(input, watch) {
    const identity = (0, hook_contract_1.resolveNativeHookIdentity)(process.argv[2]);
    if (process.env.MARROW_AUTO_HOOK === 'false') {
        await (0, owner_bypass_1.recordSessionBypass)('hooks_switched_off', identity, input);
        return;
    }
    let event = input;
    let rawEvent = input;
    let inputFailure = null;
    if (event === undefined) {
        try {
            const stdin = await readStdin();
            if (stdin.bytes > exports.MAX_PRE_ACTION_INPUT_BYTES) {
                inputFailure = `Marrow did not check this action because its hook input is ${stdin.bytes} bytes, over the ${exports.MAX_PRE_ACTION_INPUT_BYTES}-byte pre-action limit, so it was denied. Split it into smaller tool calls and retry.`;
            }
            else {
                const raw = stdin.raw.trim();
                rawEvent = raw ? JSON.parse(raw) : {};
                event = (0, hook_contract_1.normalizeHookEventPayload)(rawEvent);
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
    if ((0, own_server_identity_1.isOfficialMarrowMcpEventOnHost)(identity.harness, source, rawEvent)) {
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
    const classified = classifyTool(source, { ownUnproven: (0, hook_tool_policy_1.isOfficialMarrowMcpEvent)(source) });
    let localControl;
    try {
        localControl = (0, control_state_1.readLocalControlState)();
    }
    catch {
        emitDecision({ runtime: null, permit: null, protectedRisk: true, enforcementError: `Marrow local control state is unsafe. Protected actions remain blocked until the owner repairs it.${(0, control_notice_1.unreadableControlSuffix)()}` }, identity.harness);
        return;
    }
    if (!localControl.enabled) {
        const resolved = identity.environment;
        const sessionId = (0, session_id_1.marrowSessionId)(resolved.sessionId || source.session_id || source.conversation_id || source.task_id || '', identity.agent_id) || undefined;
        const correlation = (0, hook_contract_1.stableToolCorrelation)({ ...source, session_id: sessionId });
        if (resolved.apiKey) {
            try {
                const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
                await (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl, event: (0, lifecycle_spool_1.payloadBoundEvent)(`owner-bypass-${correlation}`, {
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
                    }) }).catch(() => null);
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
    // MCP-5: control is on and no key resolves, so nothing this hook does is recorded: say so once per session.
    if (!identity.environment.apiKey)
        (0, keyless_notice_1.armKeylessNotice)(identity.harness, identity.environment.sessionId || source.session_id || source.conversation_id || source.task_id);
    // MCP-10: where no person can answer a prompt (auto, bypass and dontAsk modes, headless runs), turning control off is denied outright.
    if (classified.type === 'security' && classified.surfaces.includes('marrow-control') && controlRouteCall(source) && noPersonAtPrompt(source)) {
        emitLoopGuardDenial(identity.harness, control_routes_1.CONTROL_ROUTE_DENY_TEXT);
        return;
    }
    let resolved = identity.environment;
    const enforcementRequired = classified.protected || ['windsurf', 'gemini', 'grok'].includes(identity.harness);
    const sessionId = (0, session_id_1.marrowSessionId)(resolved.sessionId || source.session_id || source.conversation_id || source.task_id
        || (0, hook_contract_1.stableSessionWorkflowId)(undefined, [identity.harness, process.cwd()]), identity.agent_id);
    const agentId = identity.agent_id;
    // With a resolved key, the no-device-key fallback may make its approval state (nokeyFallbackKey); with none it never does.
    if (resolved.apiKey)
        (0, host_approval_state_1.allowNokeyFallbackCreate)();
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
                await (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl: loopBaseUrl, event: (0, lifecycle_spool_1.payloadBoundEvent)(`loop-block-${loopDecision.receipt.slice(4)}`, {
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
                    }) }).catch(() => null);
            }
            catch { /* local denial remains authoritative when telemetry is unavailable */ }
        }
        emitLoopGuardDenial(identity.harness, loopDecision.reason || `Marrow local loop guard blocked this unchanged repeat. Receipt: ${loopDecision.receipt}.`);
        return;
    }
    // No usable key: the seatbelt decides first (spec §1.1), before the read-only pass so S4 reads stop.
    // `seatbelt` answers here with no network call; `claimed_no_key` stops S0-S5 here and keeps the holds below.
    // Whether a keyless hold may say "linked to an account" (only with account evidence, never for a mode fallback).
    let keylessAccountLinked = false;
    // The keyless hold text when the seatbelt does not answer: master's no-key text in seatbelt mode (a
    // tool the mapper does not recognise, audit H1), the claimed_no_key texts otherwise.
    let keylessSeatbeltMode = false;
    // Why the stricter fallback is on (words only, read from the mode resolution; the mode is decided elsewhere).
    let keylessModeReason = null;
    if (!resolved.apiKey) {
        let keyless;
        try {
            keyless = require('./seatbelt/hook').keylessSeatbelt(identity.harness, seatbeltEvent(source, rawEvent));
        }
        catch {
            keyless = { mode: 'claimed_no_key', stopText: SEATBELT_FAILED_TEXT };
        }
        keylessAccountLinked = keyless.accountLinked === true;
        keylessSeatbeltMode = keyless.mode === 'seatbelt';
        keylessModeReason = typeof keyless.modeReason === 'string' ? keyless.modeReason : null;
        if (keyless.stopText) {
            emitLoopGuardDenial(identity.harness, keyless.stopText);
            return;
        }
        // A tool the mapper does not recognise never gets the seatbelt pass: master's answer below.
        if (keyless.mode === 'seatbelt' && keyless.recognized === true) {
            // Never an explicit allow for an action 3.9.103 held: the host's own approval step decides.
            const answer = seatbeltPassOutput(identity.harness, source.hook_event_name, !classified.readOnly && enforcementRequired);
            if (answer === null)
                process.exitCode = 0;
            else
                process.stdout.write(JSON.stringify(answer));
            return;
        }
    }
    else {
        watch.harness = identity.harness;
        watch.event = seatbeltEvent(source, rawEvent);
        let floor = null;
        try {
            floor = require('./seatbelt/hook');
        }
        catch { /* watch only: a missing module never changes the account flow */ }
        if (floor && floor.SEATBELT_ROLLOUT.account_floor === 'on') {
            watch.harness = undefined;
            const stopText = floor.accountFloor(identity.harness, watch.event, (0, host_approval_1.preToolDeadline)((0, host_approval_1.approvalHostFor)(identity.harness)));
            if (stopText) {
                emitLoopGuardDenial(identity.harness, stopText);
                return;
            }
        }
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
            enforcementError: 'The Marrow address in this machine\'s settings is not valid, so this protected action was held. Run `npx @getmarrow/install` again in this terminal, then retry.',
        }, identity.harness);
        return;
    }
    if (!resolved.apiKey) {
        emitDecision({
            runtime: null,
            permit: null,
            protectedRisk: enforcementRequired,
            enforcementError: keylessSeatbeltMode ? exports.NO_KEY_TEXT : keylessAccountLinked ? exports.CLAIMED_NO_KEY_TEXT : setupUnconfirmedHold(keylessModeReason),
            credentialsUnavailable: true,
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
        // One total budget for this hook's answer and its follow-up work.
        deadlineAt: (0, host_approval_1.preToolDeadline)((0, host_approval_1.approvalHostFor)(identity.harness)),
    };
    const toolUseId = typeof source.tool_use_id === 'string' ? source.tool_use_id : null;
    const generationId = typeof source.generation_id === 'string' ? source.generation_id : null;
    // Cursor runs an MCP call through preToolUse and then beforeMCPExecution, the
    // only event where Cursor shows its own approval prompt. In a local
    // interactive session preToolUse defers to it; cloud agents never run
    // beforeMCPExecution, so there preToolUse is the gate and holds quietly.
    const cursorMcpPreToolUse = holdContext.host === 'cursor' && String(source.hook_event_name || '').toLowerCase() === 'pretooluse'
        && /^MCP:/i.test(String(source.tool_name || ''));
    if (cursorMcpPreToolUse && (0, host_approval_1.cursorSessionEvidence)(holdContext).interactive === true) {
        process.stdout.write(JSON.stringify({ permission: 'allow' }));
        return;
    }
    // The same action retried after a hold that waited for approval: its status decides.
    const dialogAvailable = holdContext.host === 'claude-code' && ownerApprovalPrompt(identity.harness, source).available;
    // The exact target (not only the correlation) binds a hold's approval to this call.
    const target = (0, hook_contract_1.exactHookTarget)(source);
    const waited = await (0, host_approval_1.resumeWaitingHold)(holdContext, { correlation, target, toolUseId, generationId, dialogAvailable }).catch(() => null);
    if (waited?.kind === 'allow') {
        emitHookOutput(identity.harness, approvedHoldHookOutput(identity.harness, waited.contextText));
        await afterAnswer(holdContext, {});
        return;
    }
    if (waited?.kind === 'ask') {
        emitHookOutput(identity.harness, heldActionHookOutput(identity.harness, { kind: 'ask', promptText: waited.promptText }, null));
        await afterAnswer(holdContext, {});
        return;
    }
    if (waited?.kind === 'deny') {
        // The retry of a hold that waits for an approval nobody can give in chat: the same user-only line again (not for a denial that has another cause: see holdNotice).
        const userNotice = identity.harness === 'claude-code' ? (0, host_approval_1.holdNotice)(waited.hold, (0, host_approval_1.heldKindLabel)(localApprovalCategories(classified)), waited.waiting === true) : null;
        emitHeldPlan(identity.harness, { kind: 'deny', agentText: waited.agentText, userText: waited.userText, code: Boolean(waited.hold.code), ...(userNotice ? { userNotice } : {}) }, waited.hold.code);
        await afterAnswer(holdContext, { link: waited.deferredLink ? waited.hold : null });
        return;
    }
    // One lifecycle record per attempt: its id names its payload (a retried action
    // is a new attempt), and a hold names the record of the attempt that created it.
    const preActionEvent = (0, lifecycle_spool_1.payloadBoundEvent)(`pretool-${correlation}`, {
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
    });
    const preActionEventId = preActionEvent.event_id;
    const lifecycle = (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl, event: preActionEvent }).catch(() => null);
    // Normalizing has its own share of the host's budget: past it the action is
    // a truncated placeholder, so the hook still answers (deny first) in time.
    const normalizedAction = (0, normalized_action_1.normalizedHookAction)(source, {
        deadlineAt: Math.min(Date.now() + 750, (holdContext.deadlineAt ?? Number.POSITIVE_INFINITY) - 1_000),
    });
    // The decision and gate receipt this control path holds, so a denial can close them.
    const held = { decisionId: null, gateReceiptId: null };
    // Set once the runtime gate has answered. A later network or 5xx failure (decision, permit issue
    // or verify) on a high-risk action is a reached answer that no permit can be had: a denial, never
    // "offline, allowed". Routine actions keep the outage policy (failure_mode low_risk_behavior).
    const reach = { gateAnswered: false };
    const highRisk = classified.protected || classified.risk === 'high';
    const control = async (signal) => {
        const runtime = await (0, index_1.marrowAgentRuntime)(resolved.apiKey, baseUrl, {
            action: classified.action,
            target: classified.target,
            type: classified.type,
            role: classified.role,
            surfaces: classified.surfaces,
            // The exact command or tool call (secrets removed), so Marrow binds the
            // gate and any approval to this action, not to its coarse class.
            normalized_action: normalizedAction,
            // Without a risk level the runtime may take its low-risk fast path, whose
            // non-durable fast_gate receipt can never back an action permit.
            ...(enforcementRequired ? { risk_level: classified.risk } : {}),
        }, sessionId, agentId, signal);
        reach.gateAnswered = true;
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
    // Codex and Cursor stop the hook at 5 s (and Codex then lets the call run):
    // the control path ends inside the hook's budget, leaving time to answer.
    const controlTimeoutMs = Math.max(1_000, Math.min(exports.PRE_ACTION_CONTROL_TIMEOUT_MS, (0, host_approval_1.remainingMs)(holdContext) - 400));
    const [result] = await Promise.all([
        withTimeout(control, controlTimeoutMs).catch((error) => (isMarrowControlTimeout(error)
            ? {
                runtime: null,
                permit: null,
                protectedRisk: enforcementRequired,
                timedOut: true,
                enforcementError: hook_contract_1.MARROW_OUTAGE_WARNING,
            }
            : isMarrowControlOutage(error) && !(reach.gateAnswered && highRisk)
                ? {
                    runtime: null,
                    permit: null,
                    protectedRisk: enforcementRequired,
                    outage: true,
                    enforcementError: hook_contract_1.MARROW_OUTAGE_WARNING,
                }
                : isMarrowControlOutage(error)
                    ? {
                        runtime: null,
                        permit: null,
                        protectedRisk: enforcementRequired,
                        enforcementError: controlRejectionMessage(error, agentId, 'unavailable'),
                        failure: 'unavailable',
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
    if (result.timedOut) {
        // Marrow is slow, not down: a self-imposed budget is never an outage. An
        // action that can be held stays held; routine actions keep flowing.
        const holdable = classified.protected || classified.risk === 'high'
            || (0, host_approval_1.protectedAmong)(holdContext, localApprovalCategories(classified)).length > 0;
        if (holdable) {
            emitHeldPlan(identity.harness, { kind: 'deny', agentText: exports.HELD_SLOW_TEXT, userText: exports.HELD_SLOW_TEXT, code: false });
            return;
        }
        emitDecision({ ...result, outage: true, timedOut: false }, identity.harness, claudePrompt);
        return;
    }
    if (result.outage) {
        // Marrow cannot be reached. An action in a category the account owner
        // protects stays held on every host; a high-risk action fails closed (high-risk
        // work needs a fresh gate); routine actions keep the outage policy.
        const protectedNow = (0, host_approval_1.protectedAmong)(holdContext, localApprovalCategories(classified));
        if (protectedNow.length) {
            emitHeldPlan(identity.harness, { kind: 'deny', agentText: host_approval_1.HELD_UNREACHABLE_TEXT, userText: host_approval_1.HELD_UNREACHABLE_TEXT, code: false });
            return;
        }
        if (outageHolds(highRisk, () => require('./seatbelt/hook').outageRisk(seatbeltEvent(source, rawEvent), holdContext.deadlineAt ?? Number.POSITIVE_INFINITY))) {
            emitHeldPlan(identity.harness, { kind: 'deny', agentText: exports.HELD_OFFLINE_TEXT, userText: exports.HELD_OFFLINE_TEXT, code: false });
            return;
        }
    }
    const verdict = result.outage ? null : runtimeGateVerdict(result.runtime);
    const guidance = verdict?.kind === 'review' ? (0, runtime_contract_1.ordinaryApprovalGuidance)(result.runtime) : null;
    const arbitration = verdict?.kind === 'arbitration_review' ? (0, runtime_contract_1.arbitrationApprovalGuidance)(result.runtime) : null;
    if (verdict && guidance && !guidance.hostApprovalSupported && holdContext.host === 'claude-code') {
        // An older service without host approvals: exactly as released 3.9.98 —
        // ask in Claude Code's dialog (the close stays unverified), never wait.
        const emitted = emitDecision(result, identity.harness, claudePrompt, true);
        if (emitted.denied)
            await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
        return;
    }
    if (verdict && (guidance || arbitration)) {
        // A hold: ask in the host's own prompt where it counts and is shown,
        // otherwise deny and wait for the approval. Never close the decision here;
        // that would spend the receipt the operator or owner is about to approve.
        const hookEvent = typeof source.hook_event_name === 'string' ? source.hook_event_name : 'PreToolUse';
        let plan;
        const cursor = holdContext.host === 'cursor' ? (0, host_approval_1.cursorSessionEvidence)(holdContext) : null;
        const nobodyHere = cursorMcpPreToolUse || unattendedRun(holdContext, claudePrompt, cursor?.interactive ?? null);
        if (guidance) {
            (0, host_approval_1.rememberProtection)(holdContext, guidance);
            plan = (0, host_approval_1.planHeldAction)({
                unattended: nobodyHere,
                attendedConfirmed: !cursorMcpPreToolUse && attendedConfirmed(holdContext, cursor?.interactive ?? null),
                hostPromptOff: (0, host_session_1.hostApprovalPromptOff)(holdContext.host),
                guidance,
                host: holdContext.host,
                hookEvent,
                // Only why it is held: the server's next-action text is written for API
                // clients and names endpoints, so it is never relayed.
                reason: boundedText(result.runtime?.risk_gate?.reasons?.[0]?.message, 240),
                claudePrompt,
                cursorInteractive: cursor?.interactive ?? null,
                typedReply: (0, host_approval_1.typedReplyAvailable)(holdContext),
            });
        }
        else {
            plan = (0, host_approval_1.planArbitrationHold)(arbitration, { unattended: nobodyHere });
        }
        let code = null;
        let effective = plan;
        let linkOutcome = { kind: 'none' };
        let laterLink = null;
        try {
            // An unreadable approval state leaves nothing to wait on: the next attempt starts over.
            const hold = plan.kind === 'deny' && plan.retryFresh ? null : (0, host_approval_1.rememberHold)(holdContext, {
                guidance: guidance || (0, host_approval_1.arbitrationHoldGuidance)(arbitration),
                correlation,
                target,
                toolUseId,
                generationId,
                toolName: String(source.tool_name || 'tool'),
                hookEvent,
                // ask and pass: the host decides now; deny: the hold waits for an approval.
                mode: plan.kind === 'deny' ? 'wait' : 'ask',
                withCode: plan.kind === 'deny' && plan.code,
                preActionEventId,
                action: { action: classified.action, target: classified.target, type: classified.type, surfaces: classified.surfaces },
                ...(plan.kind === 'deny' && plan.ownerLink ? { ownerLink: plan.ownerLink } : {}),
                ...(plan.kind === 'deny' && plan.dialogLater ? { dialogLater: true, laterPrompt: plan.laterPrompt } : {}),
                ...(plan.kind === 'deny' && plan.quiet ? { quiet: plan.quiet } : {}),
                ...(plan.kind === 'pass' ? { notObserved: true } : {}),
                normalizedAction,
                ...(guidance ? {} : { personPresent: !nobodyHere }),
            });
            code = hold?.code ?? null;
            if (hold && plan.kind === 'deny' && plan.ownerLink === 'now') {
                linkOutcome = await (0, host_approval_1.requestOwnerLink)(holdContext, hold);
                if (linkOutcome.kind === 'deferred')
                    laterLink = hold;
            }
        }
        catch {
            // Without local state the answer could not be linked to this hold, so it is not asked for.
            if (plan.kind === 'ask' || plan.kind === 'pass') {
                const text = `Marrow is holding this action for approval (gate receipt ${guidance?.gateReceiptId || arbitration?.gateReceiptId}), so it did not run. Tell the operator it is waiting for approval; local approval state is unavailable on this machine.`;
                effective = { kind: 'deny', agentText: text, userText: (0, host_approval_1.forPerson)(text), code: false };
            }
        }
        effective = (0, host_approval_1.finalizeOwnerRequest)(effective, linkOutcome);
        if (effective.kind === 'pass') {
            // The hook does not block and does not allow: the host's own approval step decides.
            emitHookOutput(identity.harness, passHookOutput(identity.harness, effective.contextText));
            await afterAnswer(holdContext, {});
            return;
        }
        emitHeldPlan(identity.harness, effective, code);
        await afterAnswer(holdContext, { link: laterLink });
        return;
    }
    const emitted = emitDecision(result, identity.harness, claudePrompt);
    if (emitted.denied && !result.outage) {
        await closeDeniedDecision(resolved.apiKey, baseUrl, held, emitted.reason, sessionId, agentId);
    }
}
//# sourceMappingURL=hook-pre-action.js.map