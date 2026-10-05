import type { MarrowAgentRuntimeResult, MarrowRuntimePlanCapability } from './types';
export declare function runtimeAuthorizationReceiptId(runtime: MarrowAgentRuntimeResult | null | undefined): string | null;
export declare function isOutcomeObservationOnlyCorrelationId(value: unknown): boolean;
export declare function normalizeRuntimePlanCapability(value: unknown, riskGateValue?: unknown): MarrowRuntimePlanCapability | null;
export declare function isOutcomeObservationOnlyRuntime(runtime: MarrowAgentRuntimeResult | null | undefined): boolean;
export declare function isValidRuntimeResult(value: unknown): value is MarrowAgentRuntimeResult;
export declare function normalizeRuntimeResult(value: unknown): MarrowAgentRuntimeResult | null;
export declare function highRiskRuntimeCanClose(runtime: MarrowAgentRuntimeResult, proof: Record<string, unknown> | undefined, explicitReceiptId: unknown, now?: number): boolean;
/**
 * A runtime receipt is immutable authorization, while proof is commit evidence.
 * This permits one missing-to-supplied proof continuation without weakening the
 * gate; the backend still validates and binds the exact proof on commit.
 */
export declare function highRiskRuntimeCanContinueWithProof(runtime: MarrowAgentRuntimeResult, proof: Record<string, unknown> | undefined, explicitReceiptId: unknown, now?: number): boolean;
export declare const OWNER_APPROVAL_STATUS_POLL_DEFAULT_MS = 5000;
export declare const OWNER_APPROVAL_STATUS_POLL_MIN_MS = 1000;
export declare const OWNER_APPROVAL_STATUS_POLL_MAX_MS = 60000;
/** The agent-key status read of one gate receipt; built from the receipt id, never taken from a response. */
export declare function ownerApprovalStatusPath(gateReceiptId: string): string;
/** The agent-key route that asks Marrow to send the owner a one-tap approval link; built from the receipt id. */
export declare function approvalLinkPath(gateReceiptId: string): string;
/** The agent-key route a host hook uses to record the operator's answer; built from the receipt id. */
export declare function hostApprovalPath(gateReceiptId: string): string;
export declare function boundedPollAfterMs(value: unknown): number;
/**
 * The server's approval contract for an ordinary (non-arbitrated) held action,
 * read from completion_contract.owner_approval in the expanded or slim runtime
 * shape. Null when the action is not an ordinary hold, when it is arbitrated,
 * or when the server does not offer the agent-key approval status read (an
 * older backend): then a hold is denied as before.
 *
 * Endpoints are rebuilt from the gate receipt id; a response that names a
 * different path is not trusted. A chat or terminal (host) approval is offered
 * only when the server says it counts for this hold: host_approval_accepted is
 * true and verified_approval_required is false. A verified-only category, or
 * settings Marrow could not read (null), means only the account owner's
 * dashboard approval counts. A caller-written proof.owner_approval is never an
 * approval and is never produced here.
 */
export type OrdinaryApprovalGuidance = {
    gateReceiptId: string;
    decisionId: string | null;
    trustedCompletionReceiptRequired: boolean;
    statusPath: string;
    pollAfterMs: number;
    /** Set only when a host (chat or terminal) approval counts for this hold. */
    hostApprovalPath: string | null;
    hostApprovalAccepted: boolean;
    /**
     * The service reports host (chat or terminal) approvals at all. An older
     * service sends no host-approval fields: only the account owner can approve
     * there, and the status read still shows that approval.
     */
    hostApprovalSupported: boolean;
    /**
     * Why the server refuses a host approval for this hold: owner_decline_stands,
     * verified_approval_required or approval_state_unavailable (null when it counts).
     */
    hostApprovalRefusal: string | null;
    ownerDeclinedAt: string | null;
    /**
     * The operator declined this action in a host prompt earlier: only the
     * operator's own marked answer (the host's dialog or a typed reply) counts
     * now, never an allow rule.
     */
    operatorOnly: boolean;
    earlierDeclineAt: string | null;
    /** Set when the server can send the account owner a one-tap approval link (no login). */
    approvalLinkPath: string | null;
    /** Server text for the host's own prompt (an earlier decline); user-facing only. */
    operatorNotice: string | null;
    verifiedApprovalRequired: boolean | null;
    verifiedApprovalCategories: string[];
    approvalCategories: string[];
    approvalAuthority: 'host_operator_or_account_owner' | 'account_owner';
    proofRequired: boolean;
    proofFields: string[];
    expiresAt: string | null;
};
export declare function ordinaryApprovalGuidance(runtime: MarrowAgentRuntimeResult | null | undefined): OrdinaryApprovalGuidance | null;
/**
 * Arbitration review_required where the server lets the account owner pick and
 * approve a proposal through a one-tap link; the status read then hands over
 * the owner_approval_receipt_id. Null for a service without that path.
 */
export type ArbitrationApprovalGuidance = {
    gateReceiptId: string;
    decisionId: string;
    arbitrationReceiptId: string;
    statusPath: string;
    linkPath: string;
    pollAfterMs: number;
    proofRequired: boolean;
    proofFields: string[];
    expiresAt: string | null;
};
export declare function arbitrationApprovalGuidance(runtime: MarrowAgentRuntimeResult | null | undefined): ArbitrationApprovalGuidance | null;
/** Validate the server's existing decision before auto skips decision creation. */
export declare function runtimeDecisionMatchesAutoScope(runtime: MarrowAgentRuntimeResult, scope: {
    action: string;
    agentId?: string;
    sessionId?: string;
}): boolean;
//# sourceMappingURL=runtime-contract.d.ts.map