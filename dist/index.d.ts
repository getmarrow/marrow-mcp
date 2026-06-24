/**
 * @getmarrow/mcp — API Functions
 */
import type { ThinkResult, CommitResult, StatusResult, AgentPatternsResult, OrientResult, MarrowAskResult, WorkflowResult, MarrowDashboardResult, MarrowDecisionBriefRequest, MarrowDecisionBriefResult, MarrowAgentRuntimeRequest, MarrowAgentRuntimeResult, MarrowFirstValueRequest, MarrowFirstValueResult, MarrowWorkflowGateRequest, MarrowWorkflowGateResult, MarrowDigestResult, MarrowAgentStatusResult, MarrowValueReportResult, MarrowModelUsageInput, MarrowModelUsageResult, MarrowNudgeResult } from './types';
import { type CreateApiKeyParams, type CreateApiKeyResult, type GetKeyAuditParams, type GetKeyAuditResult, type ListApiKeysResult, type MarrowApiKey, type RevokeApiKeyResult, type RotateApiKeyResult } from '@getmarrow/sdk';
export type { Narrative, CommitResult } from './types';
/**
 * Validate a path parameter to prevent path traversal attacks.
 * Only allows alphanumeric, hyphens, underscores, and dots.
 */
export declare function validatePathParam(value: string, paramName: string): string;
/**
 * Validate and sanitize a base URL. Requires HTTPS.
 */
export declare function validateBaseUrl(rawUrl: string): string;
export declare function marrowCreateKey(apiKey: string, baseUrl: string, params: CreateApiKeyParams, sessionId?: string, agentId?: string): Promise<CreateApiKeyResult>;
export declare function marrowListKeys(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): Promise<ListApiKeysResult>;
export declare function marrowGetKey(apiKey: string, baseUrl: string, id: string, sessionId?: string, agentId?: string): Promise<MarrowApiKey | null>;
export declare function marrowRevokeKey(apiKey: string, baseUrl: string, id: string, sessionId?: string, agentId?: string): Promise<RevokeApiKeyResult>;
export declare function marrowRotateKey(apiKey: string, baseUrl: string, id: string, sessionId?: string, agentId?: string): Promise<RotateApiKeyResult>;
export declare function marrowGetKeyAudit(apiKey: string, baseUrl: string, params?: GetKeyAuditParams, sessionId?: string, agentId?: string): Promise<GetKeyAuditResult>;
/**
 * Log intent and get collective intelligence before acting.
 */
export declare function marrowThink(apiKey: string, baseUrl: string, params: {
    action: string;
    type?: string;
    context?: Record<string, unknown>;
    previous_decision_id?: string;
    previous_success?: boolean;
    previous_outcome?: string;
    checkLoop?: boolean;
    source_kind?: 'human_directed' | 'agent_autonomous' | 'scheduled' | 'integration' | 'system' | 'unknown';
    source_confidence?: number;
    human_directed?: boolean;
    instruction_ref?: string | null;
    instruction?: string;
    instruction_hash?: string;
    source_meta?: Record<string, unknown>;
}, sessionId?: string, agentId?: string): Promise<ThinkResult>;
/**
 * Explicitly commit the result of an action to Marrow.
 */
export declare function marrowCommit(apiKey: string, baseUrl: string, params: {
    decision_id: string;
    success: boolean;
    outcome: string;
    caused_by?: string;
    proof?: Record<string, unknown>;
    gate_receipt_id?: string;
    gate_receipt?: string;
    action?: string;
    type?: string;
    surfaces?: string[];
    auto_gate?: boolean;
    model_usage?: MarrowModelUsageInput;
    modelUsage?: MarrowModelUsageInput;
}, sessionId?: string, agentId?: string): Promise<CommitResult & {
    runtime_gate?: MarrowAgentRuntimeResult | null;
}>;
export declare function marrowModelUsage(apiKey: string, baseUrl: string, input: MarrowModelUsageInput, sessionId?: string, agentId?: string): Promise<MarrowModelUsageResult>;
/**
 * Fire-and-forget style logging helper for tool hooks and simple integrations.
 * Logs intent, and when outcome is supplied, immediately commits it.
 */
export declare function marrowAuto(apiKey: string, baseUrl: string, params: {
    action: string;
    outcome?: string;
    success?: boolean;
    type?: string;
    context?: Record<string, unknown>;
    source_meta?: Record<string, unknown>;
    proof?: Record<string, unknown>;
    gate_receipt_id?: string;
    action_for_gate?: string;
    surfaces?: string[];
}, sessionId?: string, agentId?: string, timeoutMs?: number): Promise<{
    decision_id: string;
    committed: boolean;
}>;
/**
 * Get agent patterns and failure history.
 */
export declare function marrowAgentPatterns(apiKey: string, baseUrl: string, params?: {
    type?: string;
    limit?: number;
}, sessionId?: string, agentId?: string): Promise<AgentPatternsResult>;
/**
 * Get failure warnings from history before acting.
 * When autoWarn=true, hits the enhanced orient endpoint for active warnings.
 */
export declare function marrowOrient(apiKey: string, baseUrl: string, params?: {
    taskType?: string;
    autoWarn?: boolean;
}, sessionId?: string, agentId?: string): Promise<OrientResult>;
/**
 * Query the collective hive for failure patterns and recommendations.
 */
export declare function marrowAsk(apiKey: string, baseUrl: string, params: {
    query: string;
}, sessionId?: string, agentId?: string): Promise<MarrowAskResult>;
/**
 * Get API health status.
 */
export declare function marrowStatus(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): Promise<StatusResult>;
export declare function marrowWorkflow(apiKey: string, baseUrl: string, params: {
    action: 'register' | 'list' | 'get' | 'update' | 'start' | 'advance' | 'instances';
    workflowId?: string;
    instanceId?: string;
    name?: string;
    description?: string;
    steps?: Array<{
        step: number;
        agent_role?: string;
        action_type?: string;
        description: string;
    }>;
    tags?: string[];
    agentId?: string;
    context?: Record<string, unknown>;
    inputs?: Record<string, unknown>;
    stepCompleted?: number;
    outcome?: string;
    nextAgentId?: string;
    contextUpdate?: Record<string, unknown>;
    status?: string;
}, sessionId?: string, agentId?: string): Promise<WorkflowResult>;
/**
 * Get operator dashboard — account health, top failures, workflow status, saves.
 */
export declare function marrowDashboard(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): Promise<MarrowDashboardResult>;
/**
 * Get periodic summary of agent activity and Marrow impact.
 */
export declare function marrowDigest(apiKey: string, baseUrl: string, period?: string, sessionId?: string, agentId?: string): Promise<MarrowDigestResult>;
/**
 * Get agent-native proof that Marrow is active and collecting useful signal.
 */
export declare function marrowAgentStatus(apiKey: string, baseUrl: string, period?: string, agentIdFilter?: string, sessionId?: string, agentId?: string): Promise<MarrowAgentStatusResult>;
/**
 * Get owner-ready proof of Marrow value for an agent or fleet.
 */
export declare function marrowValueReport(apiKey: string, baseUrl: string, period?: string, agentIdFilter?: string, sessionId?: string, agentId?: string): Promise<MarrowValueReportResult>;
/**
 * Get one pre-action operating brief for risky or meaningful agent work.
 */
export declare function marrowDecisionBrief(apiKey: string, baseUrl: string, input: MarrowDecisionBriefRequest, sessionId?: string, agentId?: string): Promise<MarrowDecisionBriefResult>;
export declare function marrowWorkflowGate(apiKey: string, baseUrl: string, input: MarrowWorkflowGateRequest, sessionId?: string, agentId?: string): Promise<MarrowWorkflowGateResult>;
export declare function marrowAgentRuntime(apiKey: string, baseUrl: string, input: MarrowAgentRuntimeRequest, sessionId?: string, agentId?: string): Promise<MarrowAgentRuntimeResult>;
export declare function marrowRecommendGovernanceMode(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<Record<string, unknown>>;
export declare function marrowListPolicyProfiles(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): Promise<Record<string, unknown>>;
export declare function marrowCreatePolicyProfile(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<Record<string, unknown>>;
export declare function marrowAssignProjectPolicyProfile(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<Record<string, unknown>>;
export declare function marrowResolvePolicy(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<Record<string, unknown>>;
export declare function marrowFirstValue(apiKey: string, baseUrl: string, input?: MarrowFirstValueRequest, sessionId?: string, agentId?: string): Promise<MarrowFirstValueResult>;
export declare function marrowAgentPerformance(apiKey: string, baseUrl: string, period?: string, agentIdFilter?: string, sessionId?: string, agentId?: string): Promise<unknown>;
export declare function marrowFleetLessons(apiKey: string, baseUrl: string, options?: {
    query?: string;
    type?: string;
    agentId?: string;
    limit?: number;
}, sessionId?: string, agentId?: string): Promise<unknown>;
export declare function marrowRecordDeploymentMemory(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<unknown>;
export declare function marrowCreateHandoff(apiKey: string, baseUrl: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<unknown>;
export declare function marrowUpdateHandoff(apiKey: string, baseUrl: string, handoffId: string, input: Record<string, unknown>, sessionId?: string, agentId?: string): Promise<unknown>;
export declare function marrowHandoffStatus(apiKey: string, baseUrl: string, options?: {
    status?: string;
    agentId?: string;
    limit?: number;
}, sessionId?: string, agentId?: string): Promise<unknown>;
/**
 * Get a periodic improvement nudge when Marrow has something worth surfacing.
 */
export declare function marrowNudge(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): Promise<MarrowNudgeResult>;
/**
 * Explicitly end the current session.
 */
export declare function marrowSessionEnd(apiKey: string, baseUrl: string, autoCommitOpen?: boolean, sessionId?: string, agentId?: string): Promise<unknown>;
/**
 * Convert a detected decision pattern into an enforced workflow.
 */
export declare function marrowAcceptDetected(apiKey: string, baseUrl: string, detectedId: string, sessionId?: string, agentId?: string): Promise<unknown>;
/**
 * List workflow templates with optional filters.
 */
export declare function marrowListTemplates(apiKey: string, baseUrl: string, params?: {
    industry?: string;
    category?: string;
    limit?: number;
}, sessionId?: string, agentId?: string): Promise<unknown>;
/**
 * Install a workflow template as an active workflow.
 */
export declare function marrowInstallTemplate(apiKey: string, baseUrl: string, slug: string, sessionId?: string, agentId?: string): Promise<unknown>;
//# sourceMappingURL=index.d.ts.map