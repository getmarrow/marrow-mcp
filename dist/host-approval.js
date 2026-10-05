"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLAUDE_CODE_NOT_A_DECISION_PREFIXES = exports.CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK = exports.CLAUDE_CODE_USER_REJECTED = exports.TYPED_REPLY_MARKER = exports.OWNER_APPROVAL_REQUEST_TEXT = exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS = exports.CURSOR_ASK_EVENTS = exports.HOST_LABEL = void 0;
exports.approvalHostFor = approvalHostFor;
exports.settleBudgetMs = settleBudgetMs;
exports.hostSessionIdFor = hostSessionIdFor;
exports.ownerLinkSentText = ownerLinkSentText;
exports.withOwnerLink = withOwnerLink;
exports.planHeldAction = planHeldAction;
exports.typedReplyUserText = typedReplyUserText;
exports.rememberHold = rememberHold;
exports.requestOwnerLink = requestOwnerLink;
exports.noteDialogShown = noteDialogShown;
exports.resumeWaitingHold = resumeWaitingHold;
exports.deliverHold = deliverHold;
exports.flushHoldOutbox = flushHoldOutbox;
exports.holdSessionForReceipt = holdSessionForReceipt;
exports.deliverQueuedForReceipt = deliverQueuedForReceipt;
exports.settleAfterTool = settleAfterTool;
exports.toolResultText = toolResultText;
exports.classifyClaudeToolResult = classifyClaudeToolResult;
exports.transcriptToolResults = transcriptToolResults;
exports.settleToolBatch = settleToolBatch;
exports.settleAtPrompt = settleAtPrompt;
exports.parseTypedReply = parseTypedReply;
exports.noteCursorSession = noteCursorSession;
exports.cursorSessionEvidence = cursorSessionEvidence;
exports.typedReplyAvailable = typedReplyAvailable;
exports.settleTypedReply = settleTypedReply;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const index_1 = require("./index");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
const host_approval_state_1 = require("./host-approval-state");
const host_session_1 = require("./host-session");
exports.HOST_LABEL = {
    'claude-code': 'Claude Code',
    codex: 'Codex',
    cursor: 'Cursor',
    cline: 'Cline',
    windsurf: 'Windsurf',
    gemini: 'Gemini CLI',
    grok: 'Grok',
    other: 'the host',
};
function approvalHostFor(harness, env = process.env) {
    if (harness === 'claude-code' || (harness === 'mcp-client' && env.CLAUDE_CODE_CHILD_SESSION === '1'))
        return 'claude-code';
    if (harness === 'mcp-client')
        return 'other';
    return harness;
}
/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
exports.CURSOR_ASK_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution']);
const HOST_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4_000;
/** The status read is one key lookup; a slow read falls back to the normal flow. */
const STATUS_READ_TIMEOUT_MS = 2_500;
/**
 * Work a post-tool hook does for a held call. Codex and Cursor run these hooks
 * with a 5-second timeout (as @getmarrow/install configures them); a hook cut
 * short keeps its queued report, which a later hook resends.
 */
function settleBudgetMs(host) {
    return host === 'codex' || host === 'cursor' ? 4_000 : 9_000;
}
function hostSessionIdFor(candidates, fallback) {
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && HOST_SESSION_ID.test(candidate.trim()))
            return candidate.trim();
    }
    return HOST_SESSION_ID.test(fallback) ? fallback : `session-${(0, node_crypto_1.createHash)('sha256').update(fallback).digest('hex').slice(0, 32)}`;
}
function scopeOf(ctx) {
    return { apiKey: ctx.apiKey, baseUrl: ctx.baseUrl, agentId: ctx.agentId || null };
}
function bounded(value, limit) {
    return value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, limit);
}
/** Why the operator's own approval does not count for this hold (the server's refusal). */
function ownerOnlyReason(guidance) {
    if (guidance.hostApprovalRefusal === 'owner_decline_stands') {
        return `The account owner declined this action${guidance.ownerDeclinedAt ? ` at ${guidance.ownerDeclinedAt}` : ' earlier'}.`;
    }
    if (guidance.hostApprovalRefusal === 'approval_state_unavailable') {
        return 'Marrow could not check how this hold can be approved right now.';
    }
    if (guidance.verifiedApprovalRequired === true) {
        return `The account owner approves ${guidance.verifiedApprovalCategories.join(', ') || 'these'} actions personally.`;
    }
    if (guidance.verifiedApprovalRequired === null) {
        return 'Marrow could not read the account approval settings.';
    }
    return 'An operator approval is not available for this hold.';
}
/** Where the approval request goes when no operator can answer here. Never a login step. */
exports.OWNER_APPROVAL_REQUEST_TEXT = 'The approval request goes to the account owner.';
/** The sentence that replaces OWNER_APPROVAL_REQUEST_TEXT once Marrow sent the owner a one-tap link. */
function ownerLinkSentText(channel) {
    return `An approval link was sent to the account owner (${channel}).`;
}
/** Puts the link outcome into a plan that asked the owner. */
function withOwnerLink(plan, channel) {
    if (plan.kind !== 'deny' || !plan.ownerRequest || !channel)
        return plan;
    const sent = ownerLinkSentText(channel);
    return { ...plan, agentText: plan.agentText.replace(exports.OWNER_APPROVAL_REQUEST_TEXT, sent), userText: plan.userText.replace(exports.OWNER_APPROVAL_REQUEST_TEXT, sent) };
}
/** Hosts whose typed reply is a person-only marker, and that marker (backend OPERATOR_MARKER_BY_HOST). */
exports.TYPED_REPLY_MARKER = {
    codex: 'UserPromptSubmit',
    gemini: 'BeforeAgent',
    cursor: 'beforeSubmitPrompt',
};
/**
 * Decides how a hook answers an ordinary held action. The operator approves
 * where they work: the host's own dialog (Claude Code, Cursor shell and MCP
 * calls), or a typed reply in a local interactive session of a host without a
 * dialog (Codex, Gemini CLI, Cursor otherwise). The approval code and its
 * prompt go only to a user-only channel; model-facing text never contains it.
 * When no operator can answer here, the request goes to the account owner.
 * No text makes a dashboard login the step to take.
 */
function planHeldAction(input) {
    const { guidance, host } = input;
    const reason = input.reason ? ` Reason: ${bounded(input.reason, 200)}` : '';
    const id = guidance.gateReceiptId;
    // Shown in the host's own prompt (to the operator, never to the agent).
    const notice = guidance.operatorNotice ? ` Note: ${guidance.operatorNotice}` : '';
    const held = `Marrow is holding this action for approval (gate receipt ${id}), so it did not run.${reason}`;
    const tail = ' When it is approved, retry this exact action; Marrow checks the approval then. Do not report or claim an approval yourself.';
    if (guidance.hostApprovalAccepted) {
        if (host === 'claude-code' && input.claudePrompt?.available) {
            return {
                kind: 'ask',
                promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer (gate receipt ${id}).${notice}${reason}`, 500),
            };
        }
        // After an operator decline only a marked answer counts; Cursor's dialog carries no marker.
        if (host === 'cursor' && exports.CURSOR_ASK_EVENTS.has(input.hookEvent) && input.cursorInteractive === true && !guidance.operatorOnly) {
            return {
                kind: 'ask',
                promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action (gate receipt ${id}).${notice}${reason}`, 500),
            };
        }
        if (input.typedReply && exports.TYPED_REPLY_MARKER[host]) {
            return {
                kind: 'deny',
                agentText: bounded(`${held} The operator was asked to approve it here.${tail}`, 500),
                userText: bounded(`Marrow holds this action for your approval (gate receipt ${id}).${notice}${reason}`, 400),
                code: true,
            };
        }
    }
    const operatorPresent = guidance.hostApprovalAccepted && host === 'claude-code';
    const why = !guidance.hostApprovalAccepted
        ? `${ownerOnlyReason(guidance)} ${exports.OWNER_APPROVAL_REQUEST_TEXT}`
        : operatorPresent
            ? `Claude Code shows no approval dialog in this session (${input.claudePrompt?.unavailableReason || 'it cannot prompt'}). To approve it here, switch Claude Code to its default permission mode and retry this exact action; Claude Code then asks you.`
            : host === 'cursor'
                ? `Cursor asks for approval only for shell and MCP calls in a local interactive session. ${exports.OWNER_APPROVAL_REQUEST_TEXT}`
                : `${exports.HOST_LABEL[host]} cannot ask the operator in this session. ${exports.OWNER_APPROVAL_REQUEST_TEXT}`;
    const agentText = bounded(`${held} ${why}${tail}`, 500);
    return { kind: 'deny', agentText, userText: agentText, code: false, ownerRequest: !operatorPresent };
}
/** User-only text with the typed-reply code (Cursor user_message, Codex and Gemini systemMessage). */
function typedReplyUserText(userText, code) {
    return bounded(`${userText} To approve it, type: marrow approve ${code} (or: marrow decline ${code}). Then let the agent retry it.`, 600);
}
const HOOK_EVENT_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
const BOUNDED_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
function rememberHold(ctx, input) {
    return (0, host_approval_state_1.recordHold)(scopeOf(ctx), {
        host: ctx.host,
        harness: ctx.harness,
        // The same bound buildHeaders applies to X-Marrow-Session-Id.
        session_id: (0, host_approval_state_1.boundSessionId)(ctx.sessionId),
        host_session_id: ctx.hostSessionId,
        agent_id: ctx.agentId && ctx.agentId.length <= 128 ? ctx.agentId : null,
        correlation: input.correlation,
        tool_use_id: input.toolUseId && BOUNDED_ID.test(input.toolUseId) ? input.toolUseId : null,
        generation_id: input.generationId && BOUNDED_ID.test(input.generationId) ? input.generationId : null,
        tool_name: input.toolName.slice(0, 256),
        hook_event: HOOK_EVENT_NAME.test(input.hookEvent) ? input.hookEvent : 'PreToolUse',
        mode: input.mode,
        gate_receipt_id: input.guidance.gateReceiptId,
        decision_id: input.guidance.decisionId,
        asked_at: new Date().toISOString(),
        pre_action_event_id: input.preActionEventId,
        proof_required: input.guidance.proofRequired,
        proof_fields: input.guidance.proofFields,
        expires_at: input.guidance.expiresAt,
        action: {
            action: input.action.action.slice(0, 512),
            target: input.action.target.slice(0, 256),
            type: input.action.type.slice(0, 64),
            surfaces: input.action.surfaces.slice(0, 16),
        },
        withCode: input.withCode,
    }, ctx.home);
}
const OWNER_LINK_TIMEOUT_MS = 2_000;
/**
 * Asks Marrow to send the account owner a one-tap approval link for this hold
 * (once; the server limits repeats). Returns the channel when it was sent.
 * The link itself never reaches this client or the agent.
 */
async function requestOwnerLink(ctx, hold, guidance) {
    if (hold.owner_link === 'sent')
        return null;
    if (!guidance?.approvalLinkPath && hold.owner_link !== 'unsent')
        return null;
    const timeout = statusTimeout(OWNER_LINK_TIMEOUT_MS);
    let channel = null;
    try {
        const result = await (0, index_1.marrowRequestApprovalLink)(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.decision_id, hold.session_id, hold.agent_id || undefined, timeout.signal);
        channel = result.ok ? result.link.channel : null;
    }
    catch {
        channel = null;
    }
    finally {
        timeout.cancel();
    }
    try {
        (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, (current) => ({ ...current, owner_link: channel ? 'sent' : 'unsent' }), ctx.home);
    }
    catch { /* the link state is a convenience; the hold stands */ }
    return channel;
}
/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
function noteDialogShown(ctx, correlation) {
    return (0, host_approval_state_1.markDialogShown)(scopeOf(ctx), { correlation, sessionId: ctx.sessionId }, new Date().toISOString(), ctx.home);
}
function statusTimeout(ms = exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    timer.unref?.();
    return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}
async function readStatus(ctx, hold) {
    const timeout = statusTimeout(STATUS_READ_TIMEOUT_MS);
    try {
        const result = await (0, index_1.marrowOwnerApprovalStatus)(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.session_id, hold.agent_id || undefined, timeout.signal);
        return result.kind === 'not_found' ? { status: null, notFound: true, failed: false } : { status: result.status, notFound: false, failed: false };
    }
    catch {
        return { status: null, notFound: false, failed: true };
    }
    finally {
        timeout.cancel();
    }
}
function approvedByText(status) {
    if (status.approval_source === 'host_prompt') {
        return status.approval_answered_by === 'host_operator' ? 'the operator (client-attested)'
            : status.approval_answered_by === 'owner_chat_preapproval' ? 'the account owner\'s chat pre-approval (client-attested)'
                : 'an allow rule in the host (client-attested)';
    }
    return 'the account owner';
}
/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt; pending denies again without a new hold; declined,
 * expired or used fall back to the normal flow (null).
 */
async function resumeWaitingHold(ctx, input) {
    let holds;
    try {
        holds = (0, host_approval_state_1.findHolds)(scopeOf(ctx), { correlation: input.correlation, sessionId: ctx.sessionId, mode: 'wait', states: ['open'] }, ctx.home);
    }
    catch {
        return null;
    }
    const hold = holds[holds.length - 1];
    if (!hold)
        return null;
    const read = await readStatus(ctx, hold);
    // Marrow unreachable: the normal flow decides (its outage policy applies).
    if (read.failed)
        return null;
    const status = read.status;
    if (!status || read.notFound) {
        (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, () => null, ctx.home);
        return null;
    }
    if (status.state === 'approved') {
        const allowed = (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, (current) => ({
            ...current,
            state: 'allowed',
            tool_use_id: input.toolUseId,
            generation_id: input.generationId,
            decision_id: current.decision_id || status.decision_id,
        }), ctx.home);
        if (!allowed)
            return null;
        return {
            kind: 'allow',
            hold: allowed,
            contextText: bounded(`Marrow: ${approvedByText(status)} approved this held action (gate receipt ${hold.gate_receipt_id}). Run only this exact action; Marrow records its outcome on that receipt.`, 400),
        };
    }
    if (status.state === 'pending' || status.state === 'unavailable') {
        const linkChannel = !hold.code && hold.owner_link === 'unsent' ? await requestOwnerLink(ctx, hold, null) : null;
        const waiting = hold.code ? 'The operator was asked to approve it here.'
            : linkChannel ? ownerLinkSentText(linkChannel)
                : hold.owner_link === 'sent' ? 'An approval link was sent to the account owner.'
                    : exports.OWNER_APPROVAL_REQUEST_TEXT;
        const expires = status.expires_at || hold.expires_at;
        const text = bounded(`Marrow is still holding this action for approval (gate receipt ${hold.gate_receipt_id}), so it did not run. ${waiting} When it is approved${expires ? ` (before ${expires})` : ''}, retry this exact action. Do not report or claim an approval yourself.`, 500);
        return {
            kind: 'deny',
            hold,
            agentText: text,
            userText: hold.code ? `Marrow still holds this action for your approval (gate receipt ${hold.gate_receipt_id}).` : text,
        };
    }
    if (status.state === 'declined') {
        const who = status.approval_source === 'host_prompt' ? `the operator declined it in ${exports.HOST_LABEL[ctx.host]}` : 'the account owner declined it';
        await closeAsDenial(ctx, hold, `Denied by Marrow pre-action gate: ${who} (gate receipt ${hold.gate_receipt_id}); the action did not run.`);
    }
    (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, () => null, ctx.home);
    return null;
}
function idempotencyFor(hold, kind) {
    return `mcp-host-approval:${(0, node_crypto_1.createHash)('sha256').update(`${kind}\n${hold.gate_receipt_id}`).digest('hex').slice(0, 40)}`;
}
async function ensureDecision(ctx, hold, signal) {
    if (hold.decision_id)
        return hold.decision_id;
    try {
        const decision = await (0, index_1.marrowThink)(ctx.apiKey, ctx.baseUrl, {
            action: hold.action.action,
            target: hold.action.target,
            surfaces: hold.action.surfaces,
            type: hold.action.type,
            source_kind: 'integration',
            ...(hold.harness !== 'mcp-client' ? { source_meta: { client: hold.harness } } : {}),
        }, hold.session_id, hold.agent_id || undefined, signal);
        const decisionId = typeof decision.decision_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/.test(decision.decision_id) ? decision.decision_id : null;
        if (decisionId)
            (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, (current) => ({ ...current, decision_id: decisionId }), ctx.home);
        return decisionId;
    }
    catch {
        return null;
    }
}
async function commitHold(ctx, hold, commit, signal) {
    const decisionId = hold.decision_id || await ensureDecision(ctx, hold, signal);
    if (!decisionId)
        return 'failed';
    try {
        const result = await (0, index_1.marrowCommit)(ctx.apiKey, ctx.baseUrl, {
            decision_id: decisionId,
            success: commit.success,
            outcome: commit.outcome,
            gate_receipt_id: hold.gate_receipt_id,
            auto_gate: false,
        }, hold.session_id, hold.agent_id || undefined, signal, idempotencyFor(hold, commit.success ? 'commit' : 'denial'));
        return result.committed === true ? 'committed' : 'unverified';
    }
    catch {
        return 'failed';
    }
}
async function closeAsDenial(ctx, hold, outcome) {
    const timeout = statusTimeout(3_000);
    try {
        await commitHold(ctx, hold, { success: false, outcome: bounded(outcome, 480) }, timeout.signal);
    }
    finally {
        timeout.cancel();
    }
}
const REFUSED_AFTER_RUN = new Set([
    'MARROW_OWNER_APPROVAL_DECLINED',
    'MARROW_OWNER_DECLINE_STANDS',
    'MARROW_VERIFIED_OWNER_APPROVAL_REQUIRED',
    'MARROW_PRE_ACTION_GATE_EXPIRED',
    'MARROW_PRE_ACTION_GATE_USED',
    'MARROW_ARBITRATION_OWNER_APPROVAL_REQUIRED',
]);
function backoffMs(attempts, retryAfterMs) {
    const exponential = Math.min(60_000, 1_000 * 2 ** Math.min(attempts, 6));
    return Math.max(exponential, retryAfterMs ?? 0);
}
/**
 * Sends a hold's queued report (and the commit that follows it) once. A
 * retryable failure (network, 409 STATE_UNAVAILABLE, 429, 5xx) keeps the
 * identical body queued with backoff: the operator's answer is never dropped
 * while its gate receipt can still accept it.
 */
async function deliverHold(ctx, holdId, deadline = Date.now() + settleBudgetMs(ctx.host)) {
    const scope = scopeOf(ctx);
    let hold = (0, host_approval_state_1.findHolds)(scope, { id: holdId }, ctx.home)[0];
    if (!hold?.outbox)
        return null;
    const outbox = hold.outbox;
    const remaining = () => Math.max(250, deadline - Date.now());
    const commitAfter = async (current) => {
        if (!outbox.commit)
            return 'skipped';
        const timeout = statusTimeout(remaining());
        try {
            return await commitHold(ctx, current, outbox.commit, timeout.signal);
        }
        finally {
            timeout.cancel();
        }
    };
    // A typed approval of a waiting hold keeps it waiting: the retried action reads the status and runs once.
    const settledState = hold.mode === 'wait' && outbox.report?.verdict === 'approved' && !outbox.commit ? 'open' : 'resolved';
    const finish = (state = settledState) => (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, outbox: null, state }), ctx.home);
    if (!outbox.report) {
        const committed = await commitAfter(hold);
        if (committed === 'failed') {
            (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
            return { kind: 'queued' };
        }
        finish();
        return { kind: 'already_approved', committed };
    }
    let report = outbox.report;
    if (report.verdict === 'approved' && !report.decision_id) {
        const timeout = statusTimeout(remaining());
        const decisionId = await ensureDecision(ctx, hold, timeout.signal).finally(timeout.cancel);
        if (!decisionId) {
            (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
            return { kind: 'queued' };
        }
        report = { ...report, decision_id: decisionId };
        hold = (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, decision_id: decisionId, outbox: current.outbox && { ...current.outbox, report } }), ctx.home) || hold;
    }
    const timeout = statusTimeout(Math.min(exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS, remaining()));
    let result;
    try {
        result = await (0, index_1.marrowHostApproval)(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, report, hold.session_id, hold.agent_id || undefined, timeout.signal);
    }
    catch {
        result = null;
    }
    finally {
        timeout.cancel();
    }
    if (!result || (!result.ok && (result.retryable || result.code === 'MARROW_OWNER_APPROVAL_STATE_UNAVAILABLE'))) {
        const retryAfter = result && !result.ok ? result.retryAfterMs : null;
        (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({
            ...current,
            outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, retryAfter) },
        }), ctx.home);
        return { kind: 'queued' };
    }
    if (result.ok) {
        const recorded = (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, decision_id: current.decision_id || result.receipt.decision_id, outbox: current.outbox && { ...current.outbox, report: null } }), ctx.home) || hold;
        const committed = await commitAfter(recorded);
        if (committed === 'failed') {
            (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
        }
        else {
            finish();
        }
        return { kind: 'recorded', answeredBy: result.receipt.answered_by, verdict: result.receipt.verdict, committed };
    }
    if (result.code === 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED' && result.existingVerdict === report.verdict) {
        const committed = await commitAfter(hold);
        finish();
        return { kind: 'already_approved', committed };
    }
    if (result.code && REFUSED_AFTER_RUN.has(result.code) || result.code === 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED') {
        // Nothing was recorded. When the action already ran, its real outcome is
        // still committed; it stays unverified, which is correct.
        const committed = report.verdict === 'approved' && outbox.commit ? await commitAfter(hold) : 'skipped';
        finish();
        return { kind: 'refused', code: result.code, committed };
    }
    // 400 invalid, 403/409 scope mismatch, not held, decision closed: a hook bug or a
    // receipt that is not waiting. Never retried.
    finish();
    return { kind: 'dropped', code: result.code };
}
/** Delivers due queued reports for this key (bounded); called at the start of later hooks. */
async function flushHoldOutbox(ctx, limit = 2, budgetMs = 4_000) {
    let due;
    try {
        due = (0, host_approval_state_1.findHolds)(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.outbox && hold.outbox.next_at <= Date.now()).slice(0, limit);
    }
    catch {
        return;
    }
    const deadline = Date.now() + budgetMs;
    for (const hold of due) {
        if (Date.now() >= deadline)
            break;
        await deliverHold(ctx, hold.id, deadline).catch(() => null);
    }
}
/**
 * marrow_commit from the MCP server: the hooks bound this gate receipt to the
 * host session (for example Claude Code's session_id), which the MCP server
 * process does not know. The receipt stays the authority; the session only has
 * to match it.
 */
function holdSessionForReceipt(ctx, gateReceiptId) {
    try {
        const holds = (0, host_approval_state_1.findHolds)(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.gate_receipt_id === gateReceiptId);
        return holds.length ? holds[holds.length - 1].session_id : null;
    }
    catch {
        return null;
    }
}
/** marrow_commit: send a queued host approval for this receipt before the agent's own commit. */
async function deliverQueuedForReceipt(ctx, gateReceiptId) {
    let holds;
    try {
        holds = (0, host_approval_state_1.findHolds)(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.gate_receipt_id === gateReceiptId && hold.outbox?.report);
    }
    catch {
        return;
    }
    for (const hold of holds)
        await deliverHold(ctx, hold.id, Date.now() + 5_000).catch(() => null);
}
function outcomeText(hold, success, host) {
    return bounded(`${hold.action.action} ${success ? 'completed' : 'failed'} in ${exports.HOST_LABEL[host]} after it was approved (gate receipt ${hold.gate_receipt_id}).`, 480);
}
function handoffText(hold, delivery) {
    const decision = hold.decision_id ? `decision_id ${hold.decision_id}, ` : '';
    const proof = hold.proof_fields.length ? hold.proof_fields.join(', ') : 'the required fields';
    if (!delivery)
        return null;
    if (delivery.kind === 'queued') {
        return bounded(`Marrow is recording the approval of this held action (gate receipt ${hold.gate_receipt_id}); the report is queued and retried automatically. Close it with marrow_commit as usual: ${decision}gate_receipt_id ${hold.gate_receipt_id}, the real success and outcome${hold.proof_required ? `, and proof with ${proof}` : ''}. Marrow sends the queued approval first.`, 600);
    }
    if (delivery.kind === 'refused') {
        return bounded(`Marrow could not record an approval for this held action (${delivery.code || 'refused'}), so its outcome stays unverified. Do not retry it to get approval; the account owner sees it with its receipts in Marrow.`, 400);
    }
    if (delivery.kind === 'dropped')
        return null;
    const approved = delivery.kind === 'already_approved' || (delivery.kind === 'recorded' && delivery.verdict === 'approved');
    if (!approved)
        return null;
    if (delivery.committed === 'committed') {
        return bounded(`Marrow recorded the approval (client-attested) and closed this held action on gate receipt ${hold.gate_receipt_id}.`, 300);
    }
    if (hold.proof_required) {
        return bounded(`Marrow recorded the approval of this held action (client-attested). Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, the real success and outcome, and proof with ${proof}. Do not call marrow_agent_runtime or marrow_think again for it.`, 600);
    }
    return bounded(`Marrow recorded the approval of this held action (client-attested). Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, and the real success and outcome.`, 500);
}
/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required; otherwise tells the agent how to close it with proof.
 */
async function settleAfterTool(ctx, input) {
    const scope = scopeOf(ctx);
    let holds;
    try {
        holds = (0, host_approval_state_1.findHolds)(scope, {
            correlation: input.correlation,
            sessionId: ctx.sessionId,
            states: ['open', 'allowed'],
            ...(input.toolUseId ? { toolUseId: input.toolUseId } : {}),
            ...(input.generationId ? { generationId: input.generationId } : {}),
        }, ctx.home).filter((hold) => hold.mode === 'ask' ? hold.state === 'open' : hold.state === 'allowed');
    }
    catch {
        return null;
    }
    const hold = holds[0];
    if (!hold || hold.outbox)
        return null;
    const answeredAt = new Date().toISOString();
    const commit = hold.proof_required ? null : { success: input.success, outcome: outcomeText(hold, input.success, ctx.host) };
    const report = hold.mode === 'ask'
        ? {
            verdict: 'approved',
            host: hold.host,
            host_session_id: hold.host_session_id,
            // Claude Code's operator marker is the pass-through PermissionRequest
            // hook only. Without it the answer is reported as the event that asked
            // and the server labels it an allow rule.
            hook_event: hold.host === 'claude-code' ? (hold.dialog_at ? 'PermissionRequest' : 'PreToolUse') : hold.hook_event,
            pre_action_event_id: hold.pre_action_event_id,
            asked_at: hold.dialog_at || hold.asked_at,
            answered_at: answeredAt,
            ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
        }
        : null;
    if (!report && !commit) {
        (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, state: 'resolved' }), ctx.home);
        return handoffText(hold, { kind: 'already_approved', committed: 'skipped' });
    }
    (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
    const delivery = await deliverHold(ctx, hold.id);
    const latest = (0, host_approval_state_1.findHolds)(scope, { id: hold.id }, ctx.home)[0] || hold;
    return handoffText({ ...latest, decision_id: latest.decision_id || hold.decision_id }, delivery);
}
// ---------------------------------------------------------------------------
// Claude Code declines: a permission rejection, never an interruption.
// Texts pinned from the Claude Code 2.1.289 bundle (see test/host-approvals-claude-texts).
// ---------------------------------------------------------------------------
exports.CLAUDE_CODE_USER_REJECTED = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed.";
exports.CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n";
/** Interruptions, cancellations and unanswered prompts: never a decline. */
exports.CLAUDE_CODE_NOT_A_DECISION_PREFIXES = [
    '[Request interrupted by user',
    '[Tool call did not complete:',
    '[Tool call interrupted:',
    '[Tool call skipped:',
    '[Tool call not completed:',
    '[Tool call result not in this copy:',
    "The user doesn't want to take this action right now.",
];
/** Transcript toolDenialKind values that mean the call never got an operator answer. */
const NOT_A_DECISION_KINDS = new Set(['cancelled', 'interrupted']);
function toolResultText(value) {
    if (typeof value === 'string')
        return value;
    if (Array.isArray(value)) {
        const text = value.find((block) => block && typeof block === 'object' && block.type === 'text'
            && typeof block.text === 'string');
        return text ? String(text.text) : null;
    }
    return null;
}
/**
 * A structured transcript denial kind wins. Free text is used only for
 * built-in tools: an MCP tool authors its own result text and could imitate a
 * rejection, so for MCP tools only the structured kind counts.
 */
function classifyClaudeToolResult(input) {
    if (input.denialKind === 'user-rejected')
        return 'declined';
    if ((input.denialKind && NOT_A_DECISION_KINDS.has(input.denialKind)) || input.unanswered)
        return 'interrupted';
    if (input.denialKind)
        return 'unknown';
    if ((0, hook_tool_policy_1.isMcpHookTool)(input.toolName) || input.text === null)
        return 'unknown';
    const text = input.text.replace(/\s+$/, '');
    if (text === exports.CLAUDE_CODE_USER_REJECTED || input.text.startsWith(exports.CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK))
        return 'declined';
    if (exports.CLAUDE_CODE_NOT_A_DECISION_PREFIXES.some((prefix) => text.startsWith(prefix)))
        return 'interrupted';
    return 'unknown';
}
const TRANSCRIPT_TAIL_BYTES = 512 * 1024;
/** Reads only a bounded tail of the host's own transcript, and only the tool results asked for. */
function transcriptToolResults(path, toolUseIds) {
    const found = new Map();
    if (typeof path !== 'string' || path.length > 4096 || !(0, node_path_1.isAbsolute)(path) || !path.endsWith('.jsonl') || toolUseIds.size === 0)
        return found;
    let fd = -1;
    try {
        const stat = (0, node_fs_1.lstatSync)(path);
        const uid = typeof process.getuid === 'function' ? process.getuid() : null;
        if (!stat.isFile() || stat.isSymbolicLink() || (uid !== null && stat.uid !== uid))
            return found;
        fd = (0, node_fs_1.openSync)(path, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NOFOLLOW || 0));
        const opened = (0, node_fs_1.fstatSync)(fd);
        if (opened.ino !== stat.ino)
            return found;
        const length = Math.min(opened.size, TRANSCRIPT_TAIL_BYTES);
        const buffer = Buffer.alloc(length);
        (0, node_fs_1.readSync)(fd, buffer, 0, length, opened.size - length);
        const lines = buffer.toString('utf8').split('\n');
        if (opened.size > length)
            lines.shift();
        for (const line of lines) {
            if (!line.includes('tool_result'))
                continue;
            let entry;
            try {
                entry = JSON.parse(line);
            }
            catch {
                continue;
            }
            const message = entry.message && typeof entry.message === 'object' ? entry.message : null;
            if (entry.type !== 'user' || !Array.isArray(message?.content))
                continue;
            for (const block of message.content) {
                if (!block || block.type !== 'tool_result' || typeof block.tool_use_id !== 'string' || !toolUseIds.has(block.tool_use_id))
                    continue;
                found.set(block.tool_use_id, {
                    text: toolResultText(block.content),
                    denialKind: typeof entry.toolDenialKind === 'string' ? entry.toolDenialKind.slice(0, 64) : null,
                    unanswered: typeof entry.toolDenialUnanswered === 'string' ? entry.toolDenialUnanswered.slice(0, 64) : null,
                });
            }
        }
    }
    catch {
        return found;
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
    }
    return found;
}
async function settleClaudeResolution(ctx, hold, resolution, hookEvent) {
    const scope = scopeOf(ctx);
    if (resolution === 'unknown')
        return;
    if (resolution === 'declined') {
        const report = {
            verdict: 'declined',
            host: hold.host,
            host_session_id: hold.host_session_id,
            hook_event: hookEvent,
            pre_action_event_id: hold.pre_action_event_id,
            asked_at: hold.dialog_at || hold.asked_at,
            answered_at: new Date().toISOString(),
            ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
        };
        const commit = {
            success: false,
            outcome: `Denied by Marrow pre-action gate: the operator declined in ${exports.HOST_LABEL[ctx.host]} (gate receipt ${hold.gate_receipt_id}).`,
        };
        (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
        await deliverHold(ctx, hold.id);
        return;
    }
    // Interrupted, cancelled or left unanswered: not a decline and not an approval.
    // The observed outcome is committed without an approval and stays unverified.
    const commit = {
        success: false,
        outcome: `Not completed: the call was interrupted, cancelled or left unanswered in ${exports.HOST_LABEL[ctx.host]} before Marrow recorded an answer (gate receipt ${hold.gate_receipt_id}); no approval or decline was given.`,
    };
    (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report: null, commit, attempts: 0, next_at: 0 } }), ctx.home);
    await deliverHold(ctx, hold.id);
}
/** Claude Code PostToolBatch: decide each still-open asked call of the batch per tool_use_id. */
async function settleToolBatch(ctx, input) {
    if (!Array.isArray(input.toolCalls))
        return 0;
    const scope = scopeOf(ctx);
    let open;
    try {
        open = (0, host_approval_state_1.findHolds)(scope, { sessionId: ctx.sessionId, mode: 'ask', states: ['open'] }, ctx.home).filter((hold) => !hold.outbox);
    }
    catch {
        return 0;
    }
    if (open.length === 0)
        return 0;
    const calls = input.toolCalls.slice(0, 64).filter((call) => Boolean(call) && typeof call === 'object');
    const ids = new Set(open.map((hold) => hold.tool_use_id).filter((id) => Boolean(id)));
    const transcript = transcriptToolResults(input.transcriptPath, ids);
    let settled = 0;
    for (const call of calls) {
        const toolUseId = typeof call.tool_use_id === 'string' ? call.tool_use_id : null;
        const toolName = typeof call.tool_name === 'string' ? call.tool_name : '';
        const correlation = (0, hook_contract_1.stableToolCorrelation)({ session_id: ctx.sessionId, tool_name: toolName, tool_input: call.tool_input });
        const hold = open.find((candidate) => candidate.correlation === correlation && (!toolUseId || !candidate.tool_use_id || candidate.tool_use_id === toolUseId));
        if (!hold)
            continue;
        const fromTranscript = toolUseId ? transcript.get(toolUseId) : undefined;
        const resolution = classifyClaudeToolResult({
            toolName,
            text: toolResultText(call.tool_response),
            denialKind: fromTranscript?.denialKind,
            unanswered: fromTranscript?.unanswered,
        });
        if (resolution === 'unknown')
            continue;
        await settleClaudeResolution(ctx, hold, resolution, 'PostToolBatch');
        settled += 1;
    }
    return settled;
}
/** Claude Code UserPromptSubmit fallback: a rejected dialog can end the turn before PostToolBatch. */
async function settleAtPrompt(ctx, transcriptPath) {
    const scope = scopeOf(ctx);
    let open;
    try {
        open = (0, host_approval_state_1.findHolds)(scope, { sessionId: ctx.sessionId, mode: 'ask', states: ['open'] }, ctx.home)
            .filter((hold) => !hold.outbox && hold.tool_use_id);
    }
    catch {
        return 0;
    }
    if (open.length === 0)
        return 0;
    const results = transcriptToolResults(transcriptPath, new Set(open.map((hold) => hold.tool_use_id)));
    let settled = 0;
    for (const hold of open) {
        const found = results.get(hold.tool_use_id);
        if (!found)
            continue;
        const resolution = classifyClaudeToolResult({ toolName: hold.tool_name, text: found.text, denialKind: found.denialKind, unanswered: found.unanswered });
        if (resolution === 'unknown')
            continue;
        await settleClaudeResolution(ctx, hold, resolution, 'UserPromptSubmit');
        settled += 1;
    }
    return settled;
}
// ---------------------------------------------------------------------------
// Typed replies: local interactive Codex, Gemini CLI and Cursor sessions only
// (never Claude Code, Cursor cloud or background agents, codex exec or gemini -p).
// ---------------------------------------------------------------------------
const TYPED_REPLY = /^\s*marrow\s+(approve|decline|deny)\s+([A-Za-z0-9]{6})\s*$/i;
function parseTypedReply(prompt) {
    if (typeof prompt !== 'string' || prompt.length > 64)
        return null;
    const match = prompt.match(TYPED_REPLY);
    if (!match)
        return null;
    const code = match[2].toUpperCase();
    if (!host_approval_state_1.APPROVAL_CODE.test(code))
        return null;
    return { verdict: match[1].toLowerCase() === 'approve' ? 'approved' : 'declined', code };
}
function noteCursorSession(ctx, input) {
    (0, host_approval_state_1.setSessionMarker)('interactive', scopeOf(ctx), ctx.hostSessionId, input.isBackgroundAgent === false, ctx.home);
}
function cursorSessionEvidence(ctx) {
    try {
        return {
            interactive: (0, host_approval_state_1.sessionMarker)('interactive', scopeOf(ctx), ctx.hostSessionId, ctx.home),
            promptHook: (0, host_approval_state_1.sessionMarker)('prompt_hook', scopeOf(ctx), ctx.hostSessionId, ctx.home),
        };
    }
    catch {
        return { interactive: null, promptHook: null };
    }
}
/**
 * A typed reply counts only from a person: the session must be local and
 * interactive (Cursor: sessionStart says not a background agent; Codex and
 * Gemini CLI: the host process has a terminal and no scripted subcommand or
 * prompt flag), and its prompt hook must already have run, so the reply can
 * reach Marrow at all.
 */
function typedReplyAvailable(ctx, interactive = host_session_1.localInteractiveSession) {
    if (!exports.TYPED_REPLY_MARKER[ctx.host])
        return false;
    const evidence = cursorSessionEvidence(ctx);
    if (evidence.promptHook !== true)
        return false;
    if (ctx.host === 'cursor')
        return evidence.interactive === true;
    return interactive(ctx.host) === true;
}
/**
 * The host's prompt hook (Codex UserPromptSubmit, Gemini BeforeAgent, Cursor
 * beforeSubmitPrompt): records that the hook runs for this session, and records
 * "marrow approve CODE" / "marrow decline CODE" typed by the operator.
 */
async function settleTypedReply(ctx, prompt, interactive = host_session_1.localInteractiveSession) {
    const scope = scopeOf(ctx);
    try {
        (0, host_approval_state_1.setSessionMarker)('prompt_hook', scope, ctx.hostSessionId, true, ctx.home);
    }
    catch { /* evidence is best effort */ }
    const typed = parseTypedReply(prompt);
    const marker = exports.TYPED_REPLY_MARKER[ctx.host];
    if (!typed || !marker || !typedReplyAvailable(ctx, interactive))
        return null;
    let hold;
    try {
        hold = (0, host_approval_state_1.findHolds)(scope, { code: typed.code, hostSessionId: ctx.hostSessionId, mode: 'wait', states: ['open'] }, ctx.home)[0];
    }
    catch {
        return null;
    }
    if (!hold || hold.outbox)
        return null;
    const report = {
        verdict: typed.verdict,
        host: hold.host,
        host_session_id: hold.host_session_id,
        hook_event: marker,
        pre_action_event_id: hold.pre_action_event_id,
        asked_at: hold.asked_at,
        answered_at: new Date().toISOString(),
        ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
    };
    const commit = typed.verdict === 'declined'
        ? { success: false, outcome: `Denied by Marrow pre-action gate: the operator declined in ${exports.HOST_LABEL[ctx.host]} (gate receipt ${hold.gate_receipt_id}).` }
        : null;
    // An approval keeps the hold waiting: the retried action reads the status and runs once.
    (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, state: typed.verdict === 'declined' ? 'resolved' : 'open', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
    const delivery = await deliverHold(ctx, hold.id);
    const approved = typed.verdict === 'approved';
    if (!delivery || delivery.kind === 'queued') {
        return {
            ok: true, verdict: typed.verdict,
            userText: 'Marrow is recording your answer; the report is queued and resent automatically.',
            agentText: approved ? `The operator approved the held action (gate receipt ${hold.gate_receipt_id}); Marrow is recording it. Retry that exact action now.` : null,
        };
    }
    if (delivery.kind === 'recorded' || delivery.kind === 'already_approved') {
        return approved
            ? { ok: true, verdict: 'approved', userText: 'Marrow recorded your approval (client-attested).', agentText: `The operator approved the held action (gate receipt ${hold.gate_receipt_id}). Retry that exact action now; Marrow lets it run once.` }
            : { ok: true, verdict: 'declined', userText: 'Marrow recorded your decline. The held action will not run.', agentText: `The operator declined the held action (gate receipt ${hold.gate_receipt_id}). Do not run it.` };
    }
    return {
        ok: false, verdict: typed.verdict,
        userText: `Marrow could not record your answer (${'code' in delivery && delivery.code ? delivery.code : 'refused'}). ${exports.OWNER_APPROVAL_REQUEST_TEXT}`,
        agentText: null,
    };
}
//# sourceMappingURL=host-approval.js.map