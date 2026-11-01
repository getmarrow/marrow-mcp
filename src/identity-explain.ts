import { SAFE_AGENT_ID, type AgentIdOrigin, type AgentIdVariable, type ResolvedMarrowEnv } from './env';
import { redactSensitiveText } from './redact';

// Where did this process get its agent id? resolveMarrowEnv says which variable and which origin won (names
// only); this module words them for the tool 403. It prints the agent id, a variable name and an origin: never a key,
// never an env block. Nothing here feeds a hook decision, a request header or a key choice. Only an owner-file id
// names a file, by its `~/...` label; every other origin has `file: null`.

const UNSAFE_ID = '<unsafe id>';
const MAX_PRINTED_ID = 64;

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
export function printableAgentId(value: string | undefined): string | null {
  if (!value) return null;
  if (!SAFE_AGENT_ID.test(value) || value.length > MAX_PRINTED_ID) return UNSAFE_ID;
  return redactSensitiveText(value) === value ? value : UNSAFE_ID;
}

/**
 * Explains where `resolved.agentId` came from: the variable and the origin resolveMarrowEnv picked. An owner-file id
 * names that owner file; every other origin has no file. No id: origin none.
 */
export function explainAgentIdSource(resolved: ResolvedMarrowEnv): AgentIdLookup {
  const source = resolved.agentIdSource;
  const id = resolved.agentId;
  if (!source || source.origin === 'none' || !source.variable || !id) {
    return { agent_id: null, variable: null, origin: 'none', file: null, fileLabel: null };
  }
  const base = { agent_id: printableAgentId(id), variable: source.variable, origin: source.origin, ...(source.keyVariable ? { keyVariable: source.keyVariable } : {}) };
  const file = source.origin === 'owner_file' ? source.ownerFile ?? null : null;
  return { ...base, file, fileLabel: file };
}

/** The four keys with `file` as the label: the form that goes into the tool 403 (`agent_id_source`). */
export function explanationLabelJson(lookup: AgentIdLookup): AgentIdExplanation {
  return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.fileLabel };
}

/**
 * The one sentence for the tool 403. Empty when no id is set. It names the variable and the origin only: no key,
 * no env block, no command that changes identity.
 */
export function agentIdSourceSentence(lookup: AgentIdLookup, subject = 'This server'): string {
  if (lookup.origin === 'none' || !lookup.variable) return '';
  if (lookup.origin === 'owner_file') return `${subject} took the id from ${lookup.variable} in ${lookup.fileLabel ?? '~/.marrow/env'}.`;
  let text = `${subject} took the id from ${lookup.variable} in this server's environment (set by the host or its launcher).`;
  if (lookup.origin === 'fleet_key_match' && lookup.keyVariable && /^MARROW_KEY_[A-Z0-9]+$/.test(lookup.keyVariable)) {
    text += ` The key was picked by that id from ${lookup.keyVariable}.`;
  }
  return text;
}
