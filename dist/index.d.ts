/**
 * @getmarrow/mcp — API Functions
 */
import type { ThinkResult, CommitResult, StatusResult, AgentPatternsResult, OrientResult, MarrowAskResult } from './types';
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
}, sessionId?: string): Promise<ThinkResult>;
/**
 * Explicitly commit the result of an action to Marrow.
 */
export declare function marrowCommit(apiKey: string, baseUrl: string, params: {
    decision_id: string;
    success: boolean;
    outcome: string;
    caused_by?: string;
}, sessionId?: string): Promise<CommitResult>;
/**
 * Get agent patterns and failure history.
 */
export declare function marrowAgentPatterns(apiKey: string, baseUrl: string, params?: {
    type?: string;
    limit?: number;
}, sessionId?: string): Promise<AgentPatternsResult>;
/**
 * Get failure warnings from history before acting.
 * When autoWarn=true, hits the enhanced orient endpoint for active warnings.
 */
export declare function marrowOrient(apiKey: string, baseUrl: string, params?: {
    taskType?: string;
    autoWarn?: boolean;
}, sessionId?: string): Promise<OrientResult>;
/**
 * Query the collective hive for failure patterns and recommendations.
 */
export declare function marrowAsk(apiKey: string, baseUrl: string, params: {
    query: string;
}, sessionId?: string): Promise<MarrowAskResult>;
/**
 * Get API health status.
 */
export declare function marrowStatus(apiKey: string, baseUrl: string, sessionId?: string): Promise<StatusResult>;
//# sourceMappingURL=index.d.ts.map