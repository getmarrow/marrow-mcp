"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLAUDE_CODE_NOT_A_DECISION_PREFIXES = exports.CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK = exports.CLAUDE_CODE_USER_REJECTED = exports.LATE_MARKER_WAIT_MS = exports.HELD_FOR_YOU_TEXT = exports.TYPED_REPLY_MARKER = exports.OWNER_LINK_ON_REQUEST_TEXT = exports.HELD_UNREACHABLE_TEXT = exports.LEGACY_SERVICE_TEXT = exports.OWNER_APPROVAL_REQUEST_TEXT = exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS = exports.CURSOR_ASK_EVENTS = exports.HEADLESS_CLAUDE_ENTRYPOINTS = exports.HOST_LABEL = void 0;
exports.approvalHostFor = approvalHostFor;
exports.claudeCodeHeadless = claudeCodeHeadless;
exports.preToolBudgetMs = preToolBudgetMs;
exports.preToolDeadline = preToolDeadline;
exports.remainingMs = remainingMs;
exports.stepTimeoutMs = stepTimeoutMs;
exports.settleBudgetMs = settleBudgetMs;
exports.hostSessionIdFor = hostSessionIdFor;
exports.ownerRequestText = ownerRequestText;
exports.ownerLinkSentText = ownerLinkSentText;
exports.finalizeOwnerRequest = finalizeOwnerRequest;
exports.planHeldAction = planHeldAction;
exports.planArbitrationHold = planArbitrationHold;
exports.typedReplyUserText = typedReplyUserText;
exports.arbitrationHoldGuidance = arbitrationHoldGuidance;
exports.rememberHold = rememberHold;
exports.rememberProtection = rememberProtection;
exports.protectedAmong = protectedAmong;
exports.requestOwnerLink = requestOwnerLink;
exports.heldActionsNotice = heldActionsNotice;
exports.noteDialogShown = noteDialogShown;
exports.permissionMarkerHookPresent = permissionMarkerHookPresent;
exports.approvalSentence = approvalSentence;
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
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const index_1 = require("./index");
const hook_tool_policy_1 = require("./hook-tool-policy");
const hook_contract_1 = require("./hook-contract");
const runtime_contract_1 = require("./runtime-contract");
const host_approval_state_1 = require("./host-approval-state");
const host_session_1 = require("./host-session");
const normalized_action_1 = require("./normalized-action");
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
/** Claude Code entrypoints with no one at a dialog (claude -p, the Agent SDKs, its GitHub Action); hooks inherit it. */
exports.HEADLESS_CLAUDE_ENTRYPOINTS = new Set(['sdk-cli', 'sdk-ts', 'sdk-py', 'claude-code-github-action']);
function claudeCodeHeadless(env = process.env) {
    return exports.HEADLESS_CLAUDE_ENTRYPOINTS.has(String(env.CLAUDE_CODE_ENTRYPOINT || ''));
}
/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
exports.CURSOR_ASK_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution']);
const HOST_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4_000;
/** The status read is one key lookup. */
const STATUS_READ_TIMEOUT_MS = 2_500;
/** Time kept back for writing the hook's answer. */
const OUTPUT_RESERVE_MS = 400;
/** Below this, a network step is not started before the answer is written. */
const MIN_STEP_MS = 600;
/**
 * One total time budget for a pre-tool hook, counted from the start of the
 * hook process and set from each host's real kill timeout as
 * @getmarrow/install configures it: Codex 5 s (it then lets the call run),
 * Cursor 5 s with failClosed, the installer's Grok guard 5 s (it then blocks),
 * Gemini CLI 5 s. The margin covers npx start-up before the process starts.
 * Cold auth can take 900 ms plus a 1.6 s grace, so the control path keeps
 * room for a slow but healthy Marrow; when the budget still runs out, an
 * action that can be held stays held (never an outage allow).
 */
function preToolBudgetMs(host) {
    // Codex: 5 s kill, then it runs the call; npx start-up before this process can take ~1.3 s cold.
    if (host === 'codex')
        return 3_000;
    if (host === 'cursor' || host === 'grok' || host === 'gemini')
        return 4_000;
    return 14_000;
}
/** The hook process's deadline for its pre-tool answer and any follow-up work. */
function preToolDeadline(host) {
    return Date.now() - Math.round(process.uptime() * 1000) + preToolBudgetMs(host);
}
/** Time left before the hook must have written its answer (Infinity without a deadline). */
function remainingMs(ctx) {
    return ctx.deadlineAt ? ctx.deadlineAt - Date.now() : Number.POSITIVE_INFINITY;
}
/** A step's timeout inside the budget, or null when there is no time for it before the answer. */
function stepTimeoutMs(ctx, max, reserve = OUTPUT_RESERVE_MS) {
    const left = remainingMs(ctx) - reserve;
    if (left < MIN_STEP_MS)
        return null;
    return Math.min(max, left);
}
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
    if (!guidance.hostApprovalSupported)
        return exports.LEGACY_SERVICE_TEXT;
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
/**
 * Stands in a plan's text for what happened to the owner's one-tap link; it is
 * always replaced (finalizeOwnerRequest) before anyone sees the text, so no
 * text says a request was sent when none was.
 */
exports.OWNER_APPROVAL_REQUEST_TEXT = '[owner-request]';
/** An older Marrow service: no host approvals and no links; only the account owner can approve. */
exports.LEGACY_SERVICE_TEXT = 'This Marrow service does not support chat or terminal approvals yet, so only the account owner can approve it.';
/** Marrow could not be read while this action waits for an approval: it stays held. */
exports.HELD_UNREACHABLE_TEXT = 'Marrow could not confirm the owner\'s approval; this action stays held. Retry when Marrow is reachable.';
/** The sentence for what happened to the owner's link. Never claims a send that did not happen. */
function ownerRequestText(outcome) {
    switch (outcome.kind) {
        case 'sent': return ownerLinkSentText(outcome.channel);
        case 'already_sent': return 'An approval link was sent to the account owner.';
        case 'not_sent': return 'Nothing was sent to anyone; it waits quietly until a person approves it.';
        // Deferred: tried right after this answer is written; until a retry confirms it, it is not "sent".
        case 'deferred':
        case 'retryable': return 'Marrow could not send the account owner an approval link yet; retrying this exact action tries again.';
        case 'failed': return `Marrow could not send the account owner an approval link${outcome.code ? ` (${outcome.code})` : ''}; tell the operator this action is waiting for the account owner's approval.`;
        default: return 'Tell the operator this action is waiting for the account owner\'s approval.';
    }
}
/** Shown when the owner's link is sent only if the operator asks for it. */
exports.OWNER_LINK_ON_REQUEST_TEXT = 'To ask the account owner, retry this exact action; Marrow then sends the owner a one-tap approval link.';
/** The sentence that replaces OWNER_APPROVAL_REQUEST_TEXT once Marrow sent the owner a one-tap link. */
function ownerLinkSentText(channel) {
    return `An approval link was sent to the account owner (${channel}).`;
}
/** Puts what happened to the owner's link into the plan's text (always, before output). */
function finalizeOwnerRequest(plan, outcome) {
    if (plan.kind !== 'deny')
        return plan;
    const text = ownerRequestText(outcome);
    return { ...plan, agentText: plan.agentText.replace(exports.OWNER_APPROVAL_REQUEST_TEXT, text), userText: plan.userText.replace(exports.OWNER_APPROVAL_REQUEST_TEXT, text) };
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
 * When no one can answer here, the action waits quietly (the owner's link only
 * for owner-locked categories, the owner's own decline when the operator asks,
 * or unattended runs with the owner's pings on).
 * No text makes a dashboard login the step to take.
 */
function planHeldAction(input) {
    const { guidance, host } = input;
    const unattended = input.unattended === true;
    const reason = input.reason ? ` Reason: ${bounded(input.reason, 200)}` : '';
    const id = guidance.gateReceiptId;
    // Shown in the host's own prompt (to the operator, never to the agent).
    const notice = guidance.operatorNotice ? ` Note: ${guidance.operatorNotice}` : '';
    const held = `Marrow is holding this action for approval (gate receipt ${id}), so it did not run.${reason}`;
    const tail = ' When it is approved, retry this exact action; Marrow checks the approval then. Do not report or claim an approval yourself.';
    const claudePrompt = bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer (gate receipt ${id}).${notice}${reason}`, 500);
    // Owner rule: the owner's link only for (a) an owner-locked category, (b) the
    // owner's standing decline once the operator asks, (c) an unattended run with pings on.
    const policy = (0, runtime_contract_1.ownerLinkPolicy)(guidance, { unattended });
    if (guidance.hostApprovalAccepted) {
        if (host === 'claude-code' && input.claudePrompt?.available) {
            return { kind: 'ask', promptText: claudePrompt };
        }
        // After an operator decline only a marked answer counts; Cursor's dialog carries no marker.
        if (host === 'cursor' && exports.CURSOR_ASK_EVENTS.has(input.hookEvent) && input.cursorInteractive === true && !guidance.operatorOnly) {
            return {
                kind: 'ask',
                promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action (gate receipt ${id}).${notice}${reason}`, 500),
            };
        }
        if (input.typedReply && exports.TYPED_REPLY_MARKER[host] && !unattended) {
            return {
                kind: 'deny',
                agentText: bounded(`${held} The operator was asked to approve it here.${tail}`, 500),
                userText: bounded(`Marrow holds this action for your approval (gate receipt ${id}).${notice}${reason}`, 400),
                code: true,
            };
        }
    }
    if (!guidance.hostApprovalSupported) {
        // An older service: no host approvals and no links. The hold waits, and
        // the retried action reads its status, so an owner's approval still counts.
        const agentText = bounded(`${held} ${exports.LEGACY_SERVICE_TEXT} Retry this exact action after the owner approves it; Marrow checks the approval then. Do not report or claim an approval yourself.`, 500);
        return { kind: 'deny', agentText, userText: agentText, code: false };
    }
    if (!guidance.hostApprovalAccepted) {
        if (guidance.hostApprovalRefusal === 'approval_state_unavailable'
            || (guidance.hostApprovalRefusal === null && guidance.verifiedApprovalRequired === null)) {
            // Nothing to wait for yet: the next attempt asks Marrow again.
            const agentText = bounded(`${held} ${ownerOnlyReason(guidance)} Retry this exact action in a moment. Do not report or claim an approval yourself.`, 500);
            return { kind: 'deny', agentText, userText: agentText, code: false, retryFresh: true };
        }
        if (guidance.hostApprovalRefusal === 'owner_decline_stands') {
            // The owner just said no: the owner is asked again only when the operator asks.
            const why = `${ownerOnlyReason(guidance)} Only the account owner can reverse that.`;
            const ask = policy === 'on_request' ? ` ${exports.OWNER_LINK_ON_REQUEST_TEXT}` : '';
            const agentText = bounded(`${held} ${why}${ask} Retry it only if the operator asks you to; otherwise carry on with other work. Do not report or claim an approval yourself.`, 500);
            return { kind: 'deny', agentText, userText: agentText, code: false, ...(policy === 'on_request' ? { ownerLink: 'on_request' } : {}) };
        }
        // An owner-locked category: the owner's one-tap link is how it is approved.
        const request = policy === 'now' ? exports.OWNER_APPROVAL_REQUEST_TEXT : ownerRequestText({ kind: 'none' });
        const agentText = bounded(`${held} ${ownerOnlyReason(guidance)} ${request} Carry on with other work meanwhile.${tail}`, 500);
        return { kind: 'deny', agentText, userText: agentText, code: false, ...(policy === 'now' ? { ownerLink: 'now' } : {}) };
    }
    if (host === 'claude-code' && !input.claudePrompt?.headless && !unattended) {
        // The operator is present but this session shows no dialog: switching to a
        // mode with the dialog approves it here (the host's own prompt, one click).
        const agentText = bounded(`${held} Claude Code shows no approval dialog in this session (${input.claudePrompt?.unavailableReason || 'it cannot prompt'}). To approve it here, switch Claude Code to its default permission mode and retry this exact action; Claude Code then asks you. Until then carry on with other work. Do not report or claim an approval yourself.`, 500);
        return { kind: 'deny', agentText, userText: agentText, code: false, dialogLater: true, laterPrompt: claudePrompt };
    }
    if (unattended || (host === 'claude-code' && input.claudePrompt?.headless)) {
        // Unattended: the action waits quietly and the agent carries on. The person
        // sees it at their next interactive session; the owner is pinged only on opt-in.
        const pinged = policy === 'now';
        const agentText = pinged
            ? bounded(`${held} Nobody can approve it in this run. ${exports.OWNER_APPROVAL_REQUEST_TEXT} If it is approved, retrying this exact action runs it once; meanwhile carry on with other work. Do not report or claim an approval yourself.`, 500)
            : bounded(`${held} Nobody can approve it in this run, so it waits quietly; nothing was sent to anyone. Carry on with other work and do not retry it in this run. A person sees it at their next interactive session and approves it there by retrying it where the host's prompt asks. Do not report or claim an approval yourself.`, 500);
        return { kind: 'deny', agentText, userText: agentText, code: false, quiet: 'unattended', ...(pinged ? { ownerLink: 'now' } : {}) };
    }
    // A person is here, but this host has no prompt Marrow can use for this call: hold quietly.
    const why = host === 'cursor'
        ? 'Cursor asks for approval only for shell and MCP calls in a local session.'
        : `${exports.HOST_LABEL[host].charAt(0).toUpperCase()}${exports.HOST_LABEL[host].slice(1)} cannot ask for approval in this session.`;
    const agentText = bounded(`${held} ${why} It stays held until the operator approves it: tell them it is held, and that they approve it by retrying it in a session with Marrow's prompt (a host permission dialog, or a typed reply). Carry on with other work. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: exports.HELD_FOR_YOU_TEXT, code: false, quiet: 'attended' };
}
/** What the person sees when this host cannot ask them: the action waits for them. */
exports.HELD_FOR_YOU_TEXT = 'This action is held until you approve it. Approve it by retrying it in a session with Marrow\'s prompt.';
/**
 * Arbitration review_required with the server's one-tap path: the owner picks
 * and approves one proposal. The hook denies, asks Marrow to send the owner a
 * link, and the retried action reads the status. Nobody is told to log in.
 */
function planArbitrationHold(guidance) {
    const agentText = bounded(`Marrow is holding this action for arbitration review (gate receipt ${guidance.gateReceiptId}), so it did not run. The account owner picks and approves one proposal. ${exports.OWNER_APPROVAL_REQUEST_TEXT} When the owner has answered, retry this exact action; Marrow checks the answer then. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: agentText, code: false, ownerLink: 'now' };
}
/** User-only text with the typed-reply code (Cursor user_message, Codex and Gemini systemMessage). */
function typedReplyUserText(userText, code) {
    return bounded(`${userText} To approve it, type: marrow approve ${code} (or: marrow decline ${code}). Then let the agent retry it.`, 600);
}
function arbitrationHoldGuidance(guidance) {
    return {
        gateReceiptId: guidance.gateReceiptId,
        decisionId: guidance.decisionId,
        proofRequired: guidance.proofRequired,
        proofFields: guidance.proofFields,
        expiresAt: guidance.expiresAt,
        approvalLinkPath: guidance.linkPath,
        hostApprovalSupported: true,
        arbitrationReceiptId: guidance.arbitrationReceiptId,
    };
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
        owner_link: !input.guidance.approvalLinkPath ? null
            : input.ownerLink === 'now' ? 'unsent'
                : input.ownerLink === 'on_request' ? 'on_request'
                    : null,
        link_attempts: 0,
        dialog_later: input.dialogLater === true,
        ask_text: input.dialogLater && input.laterPrompt ? bounded(input.laterPrompt, 500) : null,
        legacy_service: input.guidance.hostApprovalSupported === false,
        arbitration_receipt_id: input.guidance.arbitrationReceiptId && BOUNDED_ID.test(input.guidance.arbitrationReceiptId) ? input.guidance.arbitrationReceiptId : null,
        quiet: input.quiet ?? null,
    }, ctx.home);
}
/**
 * Remembers the categories the account owner protects, from a hold's guidance,
 * so an owner-protected action stays held while Marrow cannot be reached.
 */
function rememberProtection(ctx, guidance) {
    try {
        if (guidance.verifiedApprovalRequired === true) {
            (0, host_approval_state_1.noteProtectedCategories)(scopeOf(ctx), guidance.verifiedApprovalCategories, [], ctx.home);
        }
        else if (guidance.verifiedApprovalRequired === false) {
            (0, host_approval_state_1.noteProtectedCategories)(scopeOf(ctx), [], guidance.approvalCategories, ctx.home);
        }
    }
    catch { /* a convenience for outages; the server stays the authority */ }
}
/** Of these categories, the ones this key last saw the account owner protect. */
function protectedAmong(ctx, categories) {
    return (0, host_approval_state_1.protectedCategoriesAmong)(scopeOf(ctx), categories, ctx.home);
}
const OWNER_LINK_TIMEOUT_MS = 2_000;
/** The server allows three links per gate receipt. */
const MAX_LINK_ATTEMPTS = 3;
/** Link refusals that another request cannot change. */
const FINAL_LINK_CODES = new Set([
    'MARROW_APPROVAL_CHANNEL_UNAVAILABLE',
    'MARROW_APPROVAL_LINK_LIMITED',
    'MARROW_APPROVAL_LINK_NOT_HELD',
    'MARROW_APPROVAL_LINK_SCOPE_MISMATCH',
    'MARROW_APPROVAL_LINK_INVALID',
    'MARROW_APPROVAL_LINK_DECISION_REQUIRED',
    'MARROW_PRE_ACTION_GATE_USED',
    'MARROW_PRE_ACTION_GATE_EXPIRED',
    'MARROW_OWNER_APPROVAL_ALREADY_DECIDED',
    'MARROW_GATE_RECEIPT_NOT_FOUND',
]);
/**
 * Asks Marrow to send the account owner a one-tap approval link for this hold.
 * A retryable failure (network, rate limit, undelivered) is tried again on a
 * later attempt, up to the server's per-receipt limit; a final refusal is not.
 * Returns what happened. The link itself never reaches this client or the agent.
 */
async function requestOwnerLink(ctx, hold, reserve = OUTPUT_RESERVE_MS) {
    if (hold.owner_link === 'sent')
        return { kind: 'already_sent' };
    if (hold.owner_link === 'failed')
        return { kind: 'failed', code: null };
    if (hold.owner_link !== 'unsent' && hold.owner_link !== 'on_request')
        return { kind: 'none' };
    if ((hold.link_attempts || 0) >= MAX_LINK_ATTEMPTS)
        return { kind: 'failed', code: 'MARROW_APPROVAL_LINK_LIMITED' };
    const budget = stepTimeoutMs(ctx, OWNER_LINK_TIMEOUT_MS, reserve);
    if (budget === null)
        return { kind: 'deferred' };
    const timeout = statusTimeout(budget);
    let outcome;
    try {
        const result = await (0, index_1.marrowRequestApprovalLink)(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.decision_id, hold.session_id, hold.agent_id || undefined, timeout.signal);
        outcome = result.ok ? { kind: 'sent', channel: result.link.channel }
            : result.notSent ? { kind: 'not_sent' }
                : !result.retryable && result.code && FINAL_LINK_CODES.has(result.code) ? { kind: 'failed', code: result.code }
                    : result.retryable ? { kind: 'retryable' }
                        : { kind: 'failed', code: result.code };
    }
    catch {
        outcome = { kind: 'retryable' };
    }
    finally {
        timeout.cancel();
    }
    const attempts = (hold.link_attempts || 0) + 1;
    const state = outcome.kind === 'sent' ? 'sent'
        : outcome.kind === 'not_sent' ? null
            : outcome.kind === 'failed' || attempts >= MAX_LINK_ATTEMPTS ? 'failed'
                : 'unsent';
    try {
        (0, host_approval_state_1.updateHold)(scopeOf(ctx), hold.id, (current) => ({ ...current, owner_link: state, link_attempts: attempts }), ctx.home);
    }
    catch { /* the link state is a convenience; the hold stands */ }
    if (outcome.kind === 'retryable' && state === 'failed')
        return { kind: 'failed', code: null };
    return outcome;
}
/** The categories an owner can lock (risk-categories.ts on the service). */
const OWNER_LOCKABLE_CATEGORIES = ['production_deploy', 'package_publish', 'secrets_security', 'data_migration', 'billing_access', 'destructive_action', 'source_control'];
/**
 * Once per interactive host session (its first prompt): tells the person how
 * many held actions are waiting for them, with the action type and agent only,
 * and refreshes this machine's copy of the owner-locked categories (so they
 * stay held during an outage on a fresh machine). Returns user-only text, or null.
 */
async function heldActionsNotice(ctx, budgetMs = 1_500) {
    const scope = scopeOf(ctx);
    const marker = `held-actions-surfaced:${ctx.hostSessionId}`;
    try {
        if ((0, host_approval_state_1.sessionMarker)('prompt_hook', scope, marker, ctx.home) === true)
            return null;
        (0, host_approval_state_1.setSessionMarker)('prompt_hook', scope, marker, true, ctx.home);
    }
    catch {
        return null;
    }
    const timeout = statusTimeout(budgetMs);
    let items = null;
    let total = null;
    try {
        const [held, settings] = await Promise.all([
            (0, index_1.marrowHeldActions)(ctx.apiKey, ctx.baseUrl, { scope: 'agent', limit: 20 }, ctx.sessionId, ctx.agentId, timeout.signal).catch(() => undefined),
            (0, index_1.marrowAgentApprovalSettings)(ctx.apiKey, ctx.baseUrl, ctx.sessionId, ctx.agentId, timeout.signal).catch(() => undefined),
        ]);
        if (settings) {
            (0, host_approval_state_1.noteProtectedCategories)(scope, settings.verified_approval_categories, OWNER_LOCKABLE_CATEGORIES.filter((category) => !settings.verified_approval_categories.includes(category)), ctx.home);
        }
        if (held) {
            items = held.holds.map((hold) => ({ type: hold.decision_type || 'action', agent: hold.agent_id }));
            total = { n: held.count, capped: held.countCapped };
        }
    }
    finally {
        timeout.cancel();
    }
    if (!items) {
        // A service without the read: this machine's own waiting holds.
        try {
            const now = Date.now();
            items = (0, host_approval_state_1.findHolds)(scope, { mode: 'wait', states: ['open'] }, ctx.home)
                .filter((hold) => !hold.expires_at || Date.parse(hold.expires_at) > now)
                .map((hold) => ({ type: hold.action.type || 'action', agent: hold.agent_id }));
        }
        catch {
            items = [];
        }
    }
    if (!items.length)
        return null;
    const groups = new Map();
    for (const item of items) {
        const label = `${bounded(item.type, 40)}${item.agent ? ` by agent ${bounded(item.agent, 64)}` : ''}`;
        groups.set(label, (groups.get(label) || 0) + 1);
    }
    const list = [...groups.entries()].slice(0, 5).map(([label, count]) => (count > 1 ? `${label} (${count})` : label)).join('; ');
    const n = total?.n ?? items.length;
    const plus = total?.capped ? '+' : '';
    return bounded(`Marrow: ${n}${plus} held action${n === 1 && !plus ? ' is' : 's are'} waiting for you: ${list}. Nothing ran. To approve one, retry it here and answer Marrow's prompt.`, 500);
}
/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
function noteDialogShown(ctx, correlation) {
    try {
        // This machine runs the marker hook: a post-tool hook may wait for a late marker.
        (0, host_approval_state_1.setSessionMarker)('prompt_hook', scopeOf(ctx), PERMISSION_HOOK_SEEN, true, ctx.home);
    }
    catch { /* a convenience; the marker below is what counts */ }
    return (0, host_approval_state_1.markDialogShown)(scopeOf(ctx), { correlation, sessionId: ctx.sessionId }, new Date().toISOString(), ctx.home);
}
const PERMISSION_HOOK_SEEN = 'claude-permission-request-hook-seen';
const NORMALIZED_ACTION_REFUSED = 'host-route-refuses-normalized-action';
/**
 * The exact action the operator answered for, carried with the report (it is
 * kept with the queued report so a resend is byte-identical, secrets removed),
 * unless this service refused the field recently.
 */
function reportAction(ctx, normalizedAction) {
    if (!normalizedAction)
        return {};
    try {
        if ((0, host_approval_state_1.sessionMarker)('prompt_hook', scopeOf(ctx), NORMALIZED_ACTION_REFUSED, ctx.home) === true)
            return {};
    }
    catch {
        return {};
    }
    return { normalized_action: normalizedAction };
}
/**
 * Whether Claude Code runs Marrow's pass-through PermissionRequest hook here:
 * seen on this machine for this key, or configured in the user's or the
 * project's Claude Code settings. Without it there is no marker to wait for.
 */
function permissionMarkerHookPresent(ctx, cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd()) {
    try {
        if ((0, host_approval_state_1.sessionMarker)('prompt_hook', scopeOf(ctx), PERMISSION_HOOK_SEEN, ctx.home) === true)
            return true;
    }
    catch { /* fall through to the settings */ }
    const home = ctx.home || process.env.HOME || (0, node_os_1.homedir)();
    for (const path of [(0, node_path_1.join)(home, '.claude', 'settings.json'), (0, node_path_1.join)(cwd, '.claude', 'settings.json')]) {
        try {
            const stat = (0, node_fs_1.lstatSync)(path);
            if (!stat.isFile() || stat.size > 1_048_576)
                continue;
            const hooks = JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'))?.hooks?.PermissionRequest;
            if (Array.isArray(hooks) && JSON.stringify(hooks).includes('claude-permission-request-hook'))
                return true;
        }
        catch { /* unreadable or absent: no evidence */ }
    }
    return false;
}
function statusTimeout(ms = exports.HOST_APPROVAL_REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    timer.unref?.();
    return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}
async function readStatus(ctx, hold) {
    const budget = stepTimeoutMs(ctx, STATUS_READ_TIMEOUT_MS);
    if (budget === null)
        return { status: null, notFound: false, failed: true };
    const timeout = statusTimeout(budget);
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
/**
 * Who approved, as the status says it. "The account owner" only for the
 * owner's verified approval; anything else is named for what it is.
 */
function approvalSentence(status) {
    if (status.approval_source === 'host_prompt') {
        const who = status.approval_answered_by === 'host_operator' ? 'The operator approved'
            : status.approval_answered_by === 'owner_chat_preapproval' ? 'The account owner\'s chat pre-approval approved'
                : 'An allow rule in the host approved';
        return `${who} this held action (client-attested)`;
    }
    if (status.approval_trust === 'verified'
        && (status.approval_answered_by === 'account_owner' || status.approval_source === 'dashboard' || status.approval_source === 'one_tap')) {
        return 'The account owner approved this held action';
    }
    return 'Marrow recorded an approval for this held action';
}
/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt (compare-and-set: a second identical call is denied);
 * pending denies again without a new hold; a status Marrow cannot give keeps
 * it held; declined, expired or used fall back to the normal flow (null).
 */
async function resumeWaitingHold(ctx, input) {
    const scope = scopeOf(ctx);
    let holds;
    try {
        holds = (0, host_approval_state_1.findHolds)(scope, { correlation: input.correlation, sessionId: ctx.sessionId, mode: 'wait', states: ['open'] }, ctx.home);
    }
    catch {
        return null;
    }
    const hold = holds[holds.length - 1];
    if (!hold)
        return null;
    const read = await readStatus(ctx, hold);
    if (read.failed || read.status?.state === 'unavailable') {
        // This exact action is waiting for an approval: it stays held until Marrow answers.
        return { kind: 'deny', hold, agentText: exports.HELD_UNREACHABLE_TEXT, userText: exports.HELD_UNREACHABLE_TEXT };
    }
    const status = read.status;
    if (!status || read.notFound) {
        (0, host_approval_state_1.updateHold)(scope, hold.id, () => null, ctx.home);
        return null;
    }
    if (status.state === 'approved') {
        const claimed = (0, host_approval_state_1.claimHold)(scope, hold.id, (current) => ({
            ...current,
            state: 'allowed',
            tool_use_id: input.toolUseId,
            generation_id: input.generationId,
            decision_id: current.decision_id || status.decision_id,
        }), ctx.home);
        if (!claimed) {
            const text = bounded(`Marrow approved this held action once (gate receipt ${hold.gate_receipt_id}), and an identical call is already running on that approval, so this repeat did not run. If it is still needed, retry it after that call finishes. Do not report or claim an approval yourself.`, 500);
            return { kind: 'deny', hold, agentText: text, userText: text };
        }
        const decision = claimed.decision_id ? `decision_id ${claimed.decision_id}, ` : '';
        const contextText = claimed.arbitration_receipt_id
            ? `Marrow: the account owner approved one proposal for this arbitrated action (gate receipt ${hold.gate_receipt_id}). Run only the approved proposal, then close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, arbitration_receipt_id ${claimed.arbitration_receipt_id}${status.owner_approval_receipt_id ? `, owner_approval_receipt_id ${status.owner_approval_receipt_id}` : ''}, the real success and outcome${claimed.proof_required ? `, and proof with ${claimed.proof_fields.join(', ') || 'the required fields'}` : ''}.`
            : `${approvalSentence(status).startsWith('Marrow ') ? '' : 'Marrow: '}${approvalSentence(status)} (gate receipt ${hold.gate_receipt_id}). Run only this exact action; Marrow records its outcome on that receipt.`;
        return { kind: 'allow', hold: claimed, contextText: bounded(contextText, 600) };
    }
    const waitingStates = new Set(['pending', 'arbitration_review']);
    if (waitingStates.has(status.state) && hold.dialog_later && input.dialogAvailable === true && ctx.host === 'claude-code') {
        // The operator switched to a mode with the dialog: ask now, on the same gate receipt.
        const asked = (0, host_approval_state_1.claimHold)(scope, hold.id, (current) => ({
            ...current,
            mode: 'ask',
            dialog_later: false,
            tool_use_id: input.toolUseId,
            generation_id: input.generationId,
            asked_at: new Date().toISOString(),
            dialog_at: null,
        }), ctx.home);
        if (!asked)
            return null;
        return {
            kind: 'ask',
            hold: asked,
            promptText: hold.ask_text || bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer (gate receipt ${hold.gate_receipt_id}).`, 500),
        };
    }
    if (waitingStates.has(status.state)) {
        // A retry is how the operator asks for the owner's link (sent once per hold;
        // a retryable failure is tried again within the server's per-receipt limit).
        const link = !hold.code && hold.owner_link ? await requestOwnerLink(ctx, hold) : { kind: 'none' };
        const waiting = hold.code ? 'The operator was asked to approve it here.'
            : hold.legacy_service ? `${exports.LEGACY_SERVICE_TEXT} The account owner has not approved it yet.`
                : hold.owner_link ? ownerRequestText(link)
                    : hold.dialog_later ? 'Claude Code shows no approval dialog in this session; switch to its default permission mode and retry this exact action.'
                        : hold.quiet === 'unattended' ? 'Nobody can approve it in this run, so it waits quietly. Carry on with other work; a person approves it at their next interactive session.'
                            : hold.quiet === 'attended' ? 'It stays held until the operator approves it by retrying it in a session with Marrow\'s prompt. Carry on with other work.'
                                : ownerRequestText({ kind: 'none' });
        const expires = status.expires_at || hold.expires_at;
        const what = hold.arbitration_receipt_id ? 'for arbitration review' : 'for approval';
        const text = bounded(`Marrow is still holding this action ${what} (gate receipt ${hold.gate_receipt_id}), so it did not run. ${waiting} When it is approved${expires ? ` (before ${expires})` : ''}, retry this exact action. Do not report or claim an approval yourself.`, 500);
        return {
            kind: 'deny',
            hold,
            agentText: text,
            userText: hold.code ? `Marrow still holds this action for your approval (gate receipt ${hold.gate_receipt_id}).`
                : hold.quiet === 'attended' ? exports.HELD_FOR_YOU_TEXT
                    : text,
            ...(link.kind === 'deferred' ? { deferredLink: true } : {}),
        };
    }
    if (status.state === 'declined') {
        const who = status.approval_source === 'host_prompt' ? `the operator declined it in ${exports.HOST_LABEL[ctx.host]}` : 'the account owner declined it';
        // The action did not run: close it as a denial after the hook answers (queued, resent if needed).
        (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({
            ...current,
            state: 'resolved',
            outbox: { report: null, commit: { success: false, outcome: bounded(`Denied by Marrow pre-action gate: ${who} (gate receipt ${hold.gate_receipt_id}); the action did not run.`, 480) }, attempts: 0, next_at: 0 },
        }), ctx.home);
        return null;
    }
    (0, host_approval_state_1.updateHold)(scope, hold.id, () => null, ctx.home);
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
const REFUSED_AFTER_RUN = new Set([
    'MARROW_OWNER_APPROVAL_DECLINED',
    'MARROW_OWNER_DECLINE_STANDS',
    // An allow rule or automatic approval after the operator declined this action.
    'MARROW_EARLIER_DECLINE_STANDS',
    'MARROW_VERIFIED_OWNER_APPROVAL_REQUIRED',
    // The answer was reported for a different normalized action than the held one.
    'MARROW_HOST_APPROVAL_ACTION_MISMATCH',
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
        // A service that does not take normalized_action yet rejected the report
        // before recording it: store it without the field (remembered for a day) and send that.
        if (report.normalized_action && result && !result.ok && result.status === 400 && result.fields?.includes('normalized_action')) {
            try {
                (0, host_approval_state_1.setSessionMarker)('prompt_hook', scope, NORMALIZED_ACTION_REFUSED, true, ctx.home);
            }
            catch { /* resent below either way */ }
            const { normalized_action: _dropped, ...plain } = report;
            report = plain;
            hold = (0, host_approval_state_1.updateHold)(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, report: plain } }), ctx.home) || hold;
            result = await (0, index_1.marrowHostApproval)(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, report, hold.session_id, hold.agent_id || undefined, timeout.signal);
        }
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
    if (delivery.kind === 'refused' && delivery.code === 'MARROW_HOST_APPROVAL_ACTION_MISMATCH') {
        return bounded(`Marrow could not record an approval for this held action: the action that ran is not the one Marrow held (${delivery.code}), so its outcome stays unverified. Do not retry it to get approval; a new attempt is held and asked again.`, 400);
    }
    if (delivery.kind === 'refused') {
        return bounded(`Marrow could not record an approval for this held action (${delivery.code || 'refused'}), so its outcome stays unverified. Do not retry it to get approval; the account owner sees it with its receipts in Marrow.`, 400);
    }
    if (delivery.kind === 'dropped')
        return null;
    const approved = delivery.kind === 'already_approved' || (delivery.kind === 'recorded' && delivery.verdict === 'approved');
    if (!approved)
        return null;
    // A waited hold was approved on the server (by the owner, or a typed reply):
    // only an answer from this host's own prompt is the hook's client-attested record.
    const recorded = hold.mode === 'ask'
        ? 'Marrow recorded the approval of this held action (client-attested).'
        : `This held action was approved (gate receipt ${hold.gate_receipt_id}).`;
    if (delivery.committed === 'committed') {
        return bounded(`${hold.mode === 'ask' ? 'Marrow recorded the approval (client-attested) and closed' : 'Marrow closed'} this held action on gate receipt ${hold.gate_receipt_id}.`, 300);
    }
    const arbitration = hold.arbitration_receipt_id ? `, arbitration_receipt_id ${hold.arbitration_receipt_id} and the owner_approval_receipt_id Marrow gave when it allowed the action` : '';
    if (hold.proof_required) {
        return bounded(`${recorded} Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}${arbitration}, the real success and outcome, and proof with ${proof}. Do not call marrow_agent_runtime or marrow_think again for it.`, 600);
    }
    return bounded(`${recorded} Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}${arbitration}, and the real success and outcome.`, 500);
}
/** How long a post-tool hook waits for Claude Code's async PermissionRequest marker. */
exports.LATE_MARKER_WAIT_MS = 1_500;
/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required and the host reported it; otherwise tells the agent how
 * to close it.
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
    let hold = holds[0];
    if (!hold || hold.outbox)
        return null;
    const answeredAt = new Date().toISOString();
    let lateMarker = false;
    if (hold.mode === 'ask' && hold.host === 'claude-code' && !hold.dialog_at && permissionMarkerHookPresent(ctx)) {
        // The marker hook runs async: after a fast click it can land just after
        // this hook starts. Wait briefly so a real click is not labelled an allow rule.
        const waitUntil = Date.now() + (input.markerWaitMs ?? exports.LATE_MARKER_WAIT_MS);
        while (Date.now() < waitUntil) {
            await new Promise((resolve) => setTimeout(resolve, 100));
            const latest = (0, host_approval_state_1.findHolds)(scope, { id: hold.id }, ctx.home)[0];
            if (!latest || latest.state !== 'open' || latest.outbox)
                break;
            hold = latest;
            if (latest.dialog_at) {
                lateMarker = true;
                break;
            }
        }
    }
    // An outcome the host does not report (null) is never committed as a success or a failure.
    const commit = hold.proof_required || input.success === null ? null : { success: input.success, outcome: outcomeText(hold, input.success, ctx.host) };
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
            // A marker that landed after the call ran was written late; the dialog was
            // shown before the click, so the time the hook asked is the honest bound.
            asked_at: lateMarker ? hold.asked_at : (hold.dialog_at || hold.asked_at),
            answered_at: answeredAt,
            ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
            ...reportAction(ctx, input.normalizedAction),
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
async function settleClaudeResolution(ctx, hold, resolution, hookEvent, normalizedAction) {
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
            ...reportAction(ctx, normalizedAction),
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
        await settleClaudeResolution(ctx, hold, resolution, 'PostToolBatch', (0, normalized_action_1.normalizedHookAction)({ tool_name: toolName, tool_input: call.tool_input }));
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