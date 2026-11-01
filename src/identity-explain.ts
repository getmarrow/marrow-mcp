import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { printablePath, SAFE_AGENT_ID, type AgentIdOrigin, type AgentIdVariable, type ResolvedMarrowEnv, resolveMarrowEnv } from './env';
import { parseToml } from './own-server-identity';
import { redactSensitiveText } from './redact';

// Where did this process get its agent id? resolveMarrowEnv says which variable and which origin won (names
// only); this module adds the config file, by reading the host config files from a fixed list and comparing
// ONE variable with the id. It prints the agent id, a variable name and a path: never a key, never an env
// block, and it makes no network call. Nothing here feeds a hook decision, a request header or a key choice.
// Agent-facing text (the credential-scope sentence, `agent_id_source`, the --explain text) names a config file by its
// fixed-list LABEL only; the absolute path is data for `identity --explain --json` and never leaves it.

export const UNSAFE_ID = '<unsafe id>';
const MAX_PRINTED_ID = 64;
const MAX_CONFIG_BYTES = 2 * 1024 * 1024;
const UNSAFE_NOTE = 'a Marrow MCP config file could not be read safely, so none is named';

/** The four fields `marrow-mcp identity --explain --json` prints, and nothing else. */
export interface AgentIdExplanation {
  agent_id: string | null;
  variable: AgentIdVariable | null;
  origin: AgentIdOrigin;
  /** One absolute path, `one of: a, b` when several files hold the id, or null. Data for `identity --explain --json` only. */
  file: string | null;
}

/** The explanation plus what only the sentence needs. */
export interface AgentIdLookup extends AgentIdExplanation {
  /** `file` as fixed-list labels (`~/.mcp.json`, `<cwd>/.mcp.json`, ...): the only form agent-facing text may carry. */
  fileLabel: string | null;
  /** fleet_key_match: the NAME of the key variable the id selected. */
  keyVariable?: string;
  /** Config files on the fixed list that exist but could not be read safely (symlink, group-writable, too large, invalid). */
  unsafeConfigFiles: number;
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

type ConfigKind = 'json' | 'toml';

/** The fixed list, in print order: no other file (never ~/.hermes/config.yaml, never a .env) is read. */
export function agentIdConfigFiles(home: string, cwd: string): Array<{ file: string; label: string; kind: ConfigKind }> {
  const h = path.resolve(home);
  const c = path.resolve(cwd);
  const all: Array<{ file: string; label: string; kind: ConfigKind }> = [
    { file: path.join(h, '.mcp.json'), label: '~/.mcp.json', kind: 'json' },
    { file: path.join(c, '.mcp.json'), label: '<cwd>/.mcp.json', kind: 'json' },
    { file: path.join(h, '.cursor', 'mcp.json'), label: '~/.cursor/mcp.json', kind: 'json' },
    { file: path.join(c, '.cursor', 'mcp.json'), label: '<cwd>/.cursor/mcp.json', kind: 'json' },
    { file: path.join(h, '.codex', 'config.toml'), label: '~/.codex/config.toml', kind: 'toml' },
    { file: path.join(h, '.gemini', 'settings.json'), label: '~/.gemini/settings.json', kind: 'json' },
  ];
  return all.filter((entry, index) => all.findIndex((other) => other.file === entry.file) === index);
}

type BlockRead = { state: 'missing' } | { state: 'unsafe' } | { state: 'ok'; env: Record<string, unknown> | null };

const isTable = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const own = (table: Record<string, unknown>, key: string): unknown => (Object.hasOwn(table, key) ? table[key] : undefined);

// One bounded, non-following read of a config file. A symlink, a file others can write, a non-regular file,
// one over 2 MiB, one that changes under us, or one that does not parse is "unsafe": it is never a source.
function readMarrowEnvBlock(file: string, kind: ConfigKind): BlockRead {
  let before: fs.Stats;
  try {
    before = fs.lstatSync(file);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? { state: 'missing' } : { state: 'unsafe' };
  }
  const writableByOthers = (stat: fs.Stats) => process.platform !== 'win32' && (stat.mode & 0o022) !== 0;
  if (before.isSymbolicLink() || !before.isFile() || before.size > MAX_CONFIG_BYTES || writableByOthers(before)) return { state: 'unsafe' };
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0) | (fs.constants.O_NOFOLLOW || 0));
  } catch {
    return { state: 'unsafe' };
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.size > MAX_CONFIG_BYTES || writableByOthers(stat)) return { state: 'unsafe' };
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (read <= 0) break;
      length += read;
    }
    if (length > stat.size) return { state: 'unsafe' };
    let text = buffer.subarray(0, length).toString('utf8');
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    const parsed: unknown = kind === 'toml' ? parseToml(text) : JSON.parse(text);
    const servers = isTable(parsed) ? own(parsed, kind === 'toml' ? 'mcp_servers' : 'mcpServers') : undefined;
    const marrow = isTable(servers) ? own(servers, 'marrow') : undefined;
    const env = isTable(marrow) ? own(marrow, 'env') : undefined;
    return { state: 'ok', env: isTable(env) ? env : null };
  } catch {
    return { state: 'unsafe' };
  } finally {
    try { fs.closeSync(fd); } catch { /* closed */ }
  }
}

/**
 * Explains where `resolved.agentId` came from. An owner-file id names that file; a process-env id (the host
 * merges a config file's marrow env block over the launcher's environment) names every fixed-list config file
 * whose marrow env block holds the same value in the same variable. No id: origin none, no file read.
 */
export function explainAgentIdSource(resolved: ResolvedMarrowEnv, context: { home?: string; cwd?: string } = {}): AgentIdLookup {
  const source = resolved.agentIdSource;
  const id = resolved.agentId;
  if (!source || source.origin === 'none' || !source.variable || !id) {
    return { agent_id: null, variable: null, origin: 'none', file: null, fileLabel: null, unsafeConfigFiles: 0 };
  }
  const base = { agent_id: printableAgentId(id), variable: source.variable, origin: source.origin, ...(source.keyVariable ? { keyVariable: source.keyVariable } : {}) };
  if (source.origin === 'owner_file') {
    return { ...base, file: source.ownerFile ?? null, fileLabel: source.ownerFile ?? null, unsafeConfigFiles: 0 };
  }
  const matches: Array<{ path: string; label: string }> = [];
  let unsafe = 0;
  for (const entry of agentIdConfigFiles(context.home ?? explainHome(), context.cwd ?? process.cwd())) {
    const read = readMarrowEnvBlock(entry.file, entry.kind);
    if (read.state === 'unsafe') unsafe += 1;
    else if (read.state === 'ok' && read.env && own(read.env, source.variable) === id) matches.push({ path: printablePath(entry.file), label: entry.label });
  }
  const join = (items: string[]) => (items.length === 0 ? null : items.length === 1 ? items[0] : `one of: ${items.join(', ')}`);
  return { ...base, file: join(matches.map((m) => m.path)), fileLabel: join(matches.map((m) => m.label)), unsafeConfigFiles: unsafe };
}

/** Resolves `env` (the process environment by default) the way the server and hooks do, then explains the id. */
export function explainEnvironment(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): AgentIdLookup {
  const home = explainHome(env);
  return explainAgentIdSource(resolveMarrowEnv({ env, home, cwd, trustedOnly: true }), { home, cwd });
}

/** The `identity --explain --json` shape: exactly four keys, `file` as the absolute path (data for the installer doctor). */
export function explanationJson(lookup: AgentIdExplanation): AgentIdExplanation {
  return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.file };
}

/** The same four keys with `file` as the fixed-list label: the form that goes into the tool 403 (`agent_id_source`). */
export function explanationLabelJson(lookup: AgentIdLookup): AgentIdExplanation {
  return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.fileLabel };
}

/**
 * The one sentence for the credential-scope text and the tool 403. Empty when no id is set. It names the
 * variable and the file only: no key, no env block, no command that changes identity.
 */
export function agentIdSourceSentence(lookup: AgentIdLookup, subject = 'This server'): string {
  if (lookup.origin === 'none' || !lookup.variable) return '';
  if (lookup.origin === 'owner_file') return `${subject} took the id from ${lookup.variable} in ${lookup.fileLabel ?? '~/.marrow/env'}.`;
  let text = lookup.fileLabel
    ? `${subject} took the id from ${lookup.variable} in the marrow env block of ${lookup.fileLabel}, which overrides the host's environment.`
    : `${subject} took the id from ${lookup.variable} in this server's environment (set by the host or its launcher; ${lookup.unsafeConfigFiles > 0 ? UNSAFE_NOTE : 'no Marrow MCP config file sets it'}).`;
  if (lookup.fileLabel && lookup.unsafeConfigFiles > 0) text += ' Another Marrow MCP config file could not be read safely.';
  if (lookup.origin === 'fleet_key_match' && lookup.keyVariable && /^MARROW_KEY_[A-Z0-9]+$/.test(lookup.keyVariable)) {
    text += ` The key was picked by that id from ${lookup.keyVariable}.`;
  }
  return text;
}

const NO_ID_LINE = 'No agent id is set (MARROW_FLEET_AGENT_ID and MARROW_AGENT_ID are both empty): Marrow uses the agent the key is bound to.';

/**
 * `marrow-mcp identity --explain [--json]`: read-only, keyless, offline. Prints the agent id, the variable,
 * the origin and the file; exit 0 (also when no id is set), 2 for a usage error.
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
    `File: ${lookup.fileLabel ?? 'none'}`,
    agentIdSourceSentence(lookup) || NO_ID_LINE,
  ].join('\n') + '\n');
  return 0;
}
