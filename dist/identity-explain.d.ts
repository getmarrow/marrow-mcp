import { type AgentIdOrigin, type AgentIdVariable, type ResolvedMarrowEnv } from './env';
/** The four fields the tool 403 carries as `agent_id_source`, and nothing else. */
export interface AgentIdExplanation {
    agent_id: string | null;
    variable: AgentIdVariable | null;
    origin: AgentIdOrigin;
    /** The owner file (`~/.marrow/env`) when the id came from it; null for every other origin. */
    file: string | null;
}
/** The explanation plus what only the sentence needs. */
export interface AgentIdLookup extends AgentIdExplanation {
    /** `file` as a label: the only form agent-facing text may carry. */
    fileLabel: string | null;
    /** fleet_key_match: the NAME of the key variable the id selected. */
    keyVariable?: string;
}
/**
 * The id as printed: exact, unless it fails the hook head's SAFE_AGENT_ID check (spaces, blank, control, format and
 * look-alike characters), is over 64 characters, or the redactor would hide part of it (an API key pasted into the
 * id variable by mistake is never echoed).
 */
export declare function printableAgentId(value: string | undefined): string | null;
/**
 * Explains where `resolved.agentId` came from: the variable and the origin resolveMarrowEnv picked. An owner-file id
 * names that owner file; every other origin has no file. No id: origin none.
 */
export declare function explainAgentIdSource(resolved: ResolvedMarrowEnv): AgentIdLookup;
/** The four keys with `file` as the label: the form that goes into the tool 403 (`agent_id_source`). */
export declare function explanationLabelJson(lookup: AgentIdLookup): AgentIdExplanation;
/**
 * The one sentence for the tool 403. Empty when no id is set. It names the variable and the origin only: no key,
 * no env block, no command that changes identity.
 */
export declare function agentIdSourceSentence(lookup: AgentIdLookup, subject?: string): string;
//# sourceMappingURL=identity-explain.d.ts.map