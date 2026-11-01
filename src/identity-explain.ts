import * as os from 'os';
import { SAFE_AGENT_ID, type AgentIdOrigin, type AgentIdVariable, type ResolvedMarrowEnv, resolveMarrowEnv } from './env';
import { redactSensitiveText } from './redact';

// Where did this process get its agent id? resolveMarrowEnv says which variable and which origin won (names
// only); this module prints them. It opens no file of its own: no host config file, no credential store. It prints
// the agent id, a variable name and an origin: never a key, never an env block, and it makes no network call.
// Nothing here feeds a hook decision, a request header or a key choice. Only an owner-file id names a file, the
// `~/...` label resolveMarrowEnv already read; every other origin has `file: null`.

export const UNSAFE_ID = '<unsafe id>';
const MAX_PRINTED_ID = 64;

/** The four fields `marrow-mcp identity --explain --json` prints, and nothing else. */
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

/** The home directory resolveMarrowEnv uses for a process environment. */
export function explainHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.HOME || env.USERPROFILE || os.homedir();
}

/**
 * Explains where `resolved.agentId` came from: the variable and the origin resolveMarrowEnv picked. An owner-file id
 * names that owner file; every other origin has no file. No id: origin none. Nothing is read.
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

/** Resolves `env` (the process environment by default) the way the server and hooks do, then explains the id. */
export function explainEnvironment(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): AgentIdLookup {
  const home = explainHome(env);
  return explainAgentIdSource(resolveMarrowEnv({ env, home, cwd, trustedOnly: true }));
}

/** The `identity --explain --json` shape: exactly four keys. */
export function explanationJson(lookup: AgentIdExplanation): AgentIdExplanation {
  return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.file };
}

/** The same four keys with `file` as the label: the form that goes into the tool 403 (`agent_id_source`). */
export function explanationLabelJson(lookup: AgentIdLookup): AgentIdExplanation {
  return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.fileLabel };
}

/**
 * The one sentence for the credential-scope text and the tool 403. Empty when no id is set. It names the
 * variable and the origin only: no key, no env block, no command that changes identity.
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

const NO_ID_LINE = 'No agent id is set (MARROW_FLEET_AGENT_ID and MARROW_AGENT_ID are both empty): Marrow uses the agent the key is bound to.';

/**
 * `marrow-mcp identity --explain [--json]`: read-only, keyless, offline, opens no file. Prints the agent id, the
 * variable and the origin (and the owner file for an owner-file id); exit 0 (also when no id is set), 2 for a usage error.
 */
export function runIdentityCommand(
  args: string[],
  options: { env?: NodeJS.ProcessEnv; cwd?: string; out?: (text: string) => void; err?: (text: string) => void } = {},
): number {
  const out = options.out ?? ((text: string) => { process.stdout.write(text); });
  const err = options.err ?? ((text: string) => { process.stderr.write(text); });
  const known = new Set(['--explain', '--json']);
  if (!args.includes('--explain') || args.some((arg) => !known.has(arg)) || new Set(args).size !== args.length) {
    err('Usage: marrow-mcp identity --explain [--json]\n');
    return 2;
  }
  let lookup: AgentIdLookup;
  try {
    lookup = explainEnvironment(options.env ?? process.env, options.cwd ?? process.cwd());
  } catch {
    err('identity --explain could not read this environment.\n');
    return 1;
  }
  const json = explanationJson(lookup);
  if (args.includes('--json')) {
    out(`${JSON.stringify(json)}\n`);
    return 0;
  }
  out([
    `Agent id: ${json.agent_id ?? 'none'}`,
    `Variable: ${json.variable ?? 'none'}`,
    `Origin: ${json.origin}`,
    ...(lookup.fileLabel ? [`File: ${lookup.fileLabel}`] : []),
    agentIdSourceSentence(lookup) || NO_ID_LINE,
  ].join('\n') + '\n');
  return 0;
}
