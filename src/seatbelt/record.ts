// Local receipts for seatbelt decisions (SEATBELT-SPEC.md §1.5, U6): a private, readable record that
// "Marrow stopped X", written on this machine only. U5 calls recordSeatbeltDecision() once per decision.
//
// Every receipt field is an enum, a bounded integer, a fixed-format id or a keyed hash (validateReceipt
// enforces it; a record that fails it is dropped, never written). There is no command text, argument,
// flag value, path, URL, host, MCP server or tool name, or branch name anywhere. The three keys are
// HMAC-SHA256(device_salt, ...) cut to 128 bits; the salt (32 random bytes, 0600) never leaves the machine.
//
// Receipts are evidence, never authority: nothing reads them to allow anything. A failure to write one
// (unsafe store, full disk, lock timeout, cap) never changes a decision: a stop stays a stop, a pass
// passes, and the failure is counted as `receipt_drop` in state.json. Nothing here touches the network.
import * as nodeFs from 'node:fs';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { userInfo } from 'node:os';
import { basename, join } from 'node:path';
import { MCP_ADAPTER_VERSION } from '../hook-contract';
import { normalizedHookAction } from '../normalized-action';
import { CLASSIFIER_PIN } from './classifier-pin';
import { FILE_TOOL_NAMES, INERT_PROGRAMS, KNOWN_COMMANDS, SEATBELT_RULES_VERSION, SHELL_TOOL_NAMES } from './tables';

export interface SeatbeltRecord {
  v: 1;
  mode: 'seatbelt' | 'claimed_no_key' | 'account';
  /** `enforce`: the decision was the hook's answer. `watch`: computed for the record only (account floor). */
  enforcement: 'enforce' | 'watch';
  harness: string;
  decision: 'pass' | 'stop' | 'skipped';
  category: string;
  rule: string;
  reasons: string[];
  flags: string[];
  parse: string;
  latency_ms: number;
}

/**
 * What the hook knew about the event. It is used only to derive enums and keyed hashes and is never
 * stored. `home` is the trusted home (passwd, or the hook's baked --home), never the agent's $HOME.
 */
export interface SeatbeltRecordContext {
  tool_name?: unknown;
  tool_input?: unknown;
  cwd?: unknown;
  session?: unknown;
  truncated?: boolean;
  home?: string | null;
}

type Fs = typeof nodeFs;

/** Test seams (host, owner, clock, file system, caps). The hook passes none of them. */
export interface ReceiptOptions {
  home?: string | null;
  uid?: number | null;
  now?: number;
  fs?: Fs;
  maxTotalBytes?: number;
  retentionDays?: number;
  lockWaitMs?: number;
}

export const MAX_RECEIPT_BYTES = 16 * 1024;
export const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
export const RETENTION_DAYS = 90;
const LOCK_WAIT_MS = 150;
/** A stop's receipt is the first-hour record, so it waits longer for the writer lock than a pass does. */
const STOP_LOCK_WAIT_MS = 600;
const LOCK_STALE_MS = 500;
const ZERO_PREV = '0'.repeat(64);
const FILE_NAME = /^\d{4}-\d{2}-\d{2}\.jsonl$/;

export type DropReason = 'unsafe_store' | 'lock_timeout' | 'write_failed' | 'cap_full' | 'oversize' | 'platform' | 'error';
const DROP_REASONS: readonly DropReason[] = ['unsafe_store', 'lock_timeout', 'write_failed', 'cap_full', 'oversize', 'platform', 'error'];

class Refusal extends Error {
  constructor(readonly reason: DropReason) {
    super(reason);
  }
}

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

const HARNESS_ENUM: Record<string, string> = {
  'claude-code': 'claude_code', cline: 'cline', codex: 'codex', cursor: 'cursor', gemini: 'gemini', grok: 'grok', windsurf: 'windsurf', 'mcp-client': 'mcp_client',
};
const HARNESSES = new Set([...Object.values(HARNESS_ENUM), 'other']);
const READ_TOOLS = new Set(['read', 'notebookread', 'read_file', 'view', 'view_file', 'grep', 'grep_files', 'search', 'rg', 'glob', 'ls', 'list_dir', 'list_directory']);
const OTHER_TOOLS = ['webfetch', 'websearch', 'task', 'agent', 'todowrite', 'skill', 'askuserquestion', 'exitplanmode'];
const TOOL_NAMES = new Set<string>([...SHELL_TOOL_NAMES, ...FILE_TOOL_NAMES, ...OTHER_TOOLS, 'mcp', 'other']);
const TOOL_KINDS = new Set(['shell', 'file_read', 'file_write', 'mcp', 'other']);
const MODES = new Set(['seatbelt', 'claimed_no_key', 'account']);
const ENFORCEMENTS = new Set(['enforce', 'watch']);
const DECISIONS = new Set(['pass', 'stop', 'ask']);
const CATEGORIES = new Set(['none', 'S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx', 'hook', 'unknown']);
const PARSES = new Set(['ok', 'dynamic', 'unparsed', 'too_large', 'unknown']);
const TARGET_CLASSES = new Set(['protected_branch', 'other_branch', 'in_workspace', 'outside_workspace', 'home_credential', 'project_env', 'prod_env', 'unknown']);
/** Flags the mapper emits (test/seatbelt-u6-receipts reads the source to prove it) plus the two the receipt adds for the account floor. */
export const FLAG_CODES: ReadonlySet<string> = new Set([
  'depth_limit', 'dry_run_final_true', 'pages_branch_from_git', 'prod', 'protected_branch_push', 'remote_exec', 'tripwire_clear', 'delete', 'force',
  'parse_dynamic', 'parse_unparsed', 'parse_too_large', 'floor_watch', 'floor_skipped',
]);
const PROGRAMS = new Set<string>([...KNOWN_COMMANDS, ...INERT_PROGRAMS, 'other']);
const SUB_PROGRAMS = new Set(['git', 'gh', 'npm', 'pnpm', 'yarn', 'bun', 'npx', 'cargo', 'docker', 'podman', 'kubectl', 'helm', 'terraform', 'tofu', 'pulumi',
  'wrangler', 'vercel', 'netlify', 'fly', 'flyctl', 'firebase', 'heroku', 'gcloud', 'aws', 'az', 'twine', 'gem', 'uv', 'poetry', 'make', 'marrow', 'marrow-install']);
const RISKY_SUBCOMMANDS = ['push', 'publish', 'deploy', 'release', 'delete', 'destroy', 'apply', 'rm', 'unpublish', 'deprecate', 'upload', 'login', 'token', 'secret'];
const SUBCOMMANDS = new Set<string>([...RISKY_SUBCOMMANDS, 'commit', 'clean', 'reset', 'rebase', 'merge', 'checkout', 'branch', 'tag', 'status', 'diff', 'log',
  'pull', 'fetch', 'clone', 'add', 'build', 'test', 'run', 'install', 'ci', 'pack', 'create', 'edit', 'view', 'list', 'get', 'set', 'config', 'plan', 'init', 'none', 'other']);
const REASON = /^[a-z][a-z0-9_]{0,63}$/;
const RULE = /^(?:none|unknown|S[0-5x]\.[a-z0-9_]{1,48}|U5\.[a-z_]{1,32})$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// Receipt schema
// ---------------------------------------------------------------------------

export interface SeatbeltReceipt {
  v: 1;
  id: string;
  seq: number;
  prev: string;
  ts: number;
  ts_label: 'client_time';
  mode: string;
  enforcement: string;
  harness: string;
  event: 'pre_tool';
  tool_kind: string;
  tool: string;
  decision: string;
  category: string;
  rule: string;
  reasons: string[];
  programs: string[];
  subcommand: string;
  flags: string[];
  target_class: string;
  parse: string;
  action_key: string;
  workspace_key: string;
  session_key: string;
  engine: { pkg: string; contract: string; source_commit: string; rules: string; tables: string };
  latency_ms: number;
}
type ReceiptBody = Omit<SeatbeltReceipt, 'id' | 'seq' | 'prev'>;

const FIELD_NAMES = ['v', 'id', 'seq', 'prev', 'ts', 'ts_label', 'mode', 'enforcement', 'harness', 'event', 'tool_kind', 'tool', 'decision', 'category', 'rule', 'reasons',
  'programs', 'subcommand', 'flags', 'target_class', 'parse', 'action_key', 'workspace_key', 'session_key', 'engine', 'latency_ms'];
const ENGINE_FIELDS = ['pkg', 'contract', 'source_commit', 'rules', 'tables'];

const isInt = (value: unknown, min: number, max: number): value is number => typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
const isList = (value: unknown, max: number, ok: (item: string) => boolean): boolean =>
  Array.isArray(value) && value.length <= max && value.every((item) => typeof item === 'string' && ok(item));
const hasHexRun = (value: string): boolean => /[0-9a-f]{20,}/.test(value);

/** The problems with a receipt object (an empty list means valid). Used by the writer and by every consumer of the fields. */
export function validateReceipt(value: unknown): string[] {
  const bad: string[] = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ['not_an_object'];
  const r = value as Record<string, unknown>;
  for (const name of Object.keys(r)) if (!FIELD_NAMES.includes(name)) bad.push(`unknown_field:${name.slice(0, 32).replace(/[^A-Za-z0-9_]/g, '_')}`);
  for (const name of FIELD_NAMES) if (!(name in r)) bad.push(`missing:${name}`);
  const str = (name: string, ok: (s: string) => boolean) => { if (typeof r[name] !== 'string' || !ok(r[name] as string)) bad.push(`bad:${name}`); };
  if (r.v !== 1) bad.push('bad:v');
  str('id', (s) => /^sbr_[0-9a-f]{32}$/.test(s));
  if (!isInt(r.seq, 1, Number.MAX_SAFE_INTEGER)) bad.push('bad:seq');
  str('prev', (s) => HEX64.test(s));
  if (!isInt(r.ts, 0, 4_102_444_800)) bad.push('bad:ts');
  if (r.ts_label !== 'client_time') bad.push('bad:ts_label');
  str('mode', (s) => MODES.has(s));
  str('enforcement', (s) => ENFORCEMENTS.has(s));
  str('harness', (s) => HARNESSES.has(s));
  if (r.event !== 'pre_tool') bad.push('bad:event');
  str('tool_kind', (s) => TOOL_KINDS.has(s));
  str('tool', (s) => TOOL_NAMES.has(s));
  str('decision', (s) => DECISIONS.has(s));
  str('category', (s) => CATEGORIES.has(s));
  str('rule', (s) => RULE.test(s));
  if (!isList(r.reasons, 16, (s) => REASON.test(s) && !hasHexRun(s))) bad.push('bad:reasons');
  if (!isList(r.programs, 8, (s) => PROGRAMS.has(s))) bad.push('bad:programs');
  str('subcommand', (s) => SUBCOMMANDS.has(s));
  if (!isList(r.flags, 16, (s) => FLAG_CODES.has(s))) bad.push('bad:flags');
  str('target_class', (s) => TARGET_CLASSES.has(s));
  str('parse', (s) => PARSES.has(s));
  for (const name of ['action_key', 'workspace_key', 'session_key']) str(name, (s) => HEX32.test(s));
  const engine = r.engine as Record<string, unknown> | null;
  if (!engine || typeof engine !== 'object' || Array.isArray(engine)) bad.push('bad:engine');
  else {
    for (const name of Object.keys(engine)) if (!ENGINE_FIELDS.includes(name)) bad.push('bad:engine_field');
    const part = (name: string, re: RegExp) => { if (typeof engine[name] !== 'string' || !re.test(engine[name] as string)) bad.push(`bad:engine.${name}`); };
    part('pkg', /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[-+][0-9A-Za-z.-]{1,32})?$/);
    part('contract', /^marrow\.classifier\.v\d{1,3}$/);
    part('source_commit', /^[0-9a-f]{40}$/);
    part('rules', /^marrow\.seatbelt\.rules\.v\d{1,3}$/);
    part('tables', /^(?:[0-9a-f]{16}|unknown)$/);
  }
  if (!isInt(r.latency_ms, 0, 600_000)) bad.push('bad:latency_ms');
  return bad;
}

// ---------------------------------------------------------------------------
// Deriving the fields
// ---------------------------------------------------------------------------

const hmacHex = (salt: Buffer, label: string, material: string): string => createHmac('sha256', salt).update(`${label}\n`).update(material).digest('hex').slice(0, 32);
const sha256Hex = (text: string): string => createHash('sha256').update(text).digest('hex');

function sortedJson(value: unknown): string {
  const order = (item: unknown, level: number): unknown => {
    if (level > 8 || !item || typeof item !== 'object') return item;
    if (Array.isArray(item)) return item.map((entry) => order(entry, level + 1));
    return Object.fromEntries(Object.keys(item as Record<string, unknown>).sort().map((key) => [key, order((item as Record<string, unknown>)[key], level + 1)]));
  };
  return JSON.stringify(order(value, 0));
}

function toolOf(name: unknown): { tool: string; kind: string } {
  const text = typeof name === 'string' ? name.trim() : '';
  const lower = text.toLowerCase();
  if (/^(?:functions\.\s*)*(?:mcp__|mcp_|mcp:)/i.test(text)) return { tool: 'mcp', kind: 'mcp' };
  if (SHELL_TOOL_NAMES.has(lower)) return { tool: lower, kind: 'shell' };
  if (READ_TOOLS.has(lower)) return { tool: lower, kind: 'file_read' };
  if (FILE_TOOL_NAMES.has(lower)) return { tool: lower, kind: 'file_write' };
  if (OTHER_TOOLS.includes(lower)) return { tool: lower, kind: 'other' };
  return { tool: 'other', kind: 'other' };
}

/** The keyed hash of the normalized, secret-replaced action. Actions that differ outside a secret get different keys. */
function actionKey(salt: Buffer, event: { tool_name?: unknown; tool_input?: unknown; input_truncated?: boolean }): { key: string; programs: string[] } {
  const raw = (): string => {
    try { return `raw\n${String(event.tool_name)}\n${typeof event.tool_input === 'string' ? event.tool_input : JSON.stringify(event.tool_input ?? null)}`; } catch { return 'raw\nunserializable'; }
  };
  try {
    const action = normalizedHookAction(event, { deadlineAt: Date.now() + 150 });
    const input = action.tool_input as Record<string, unknown>;
    const covered = typeof input.command_sha256 === 'string' || typeof input.input_sha256 === 'string';
    const empty = event.tool_input === undefined || event.tool_input === null || event.tool_input === '';
    // A placeholder (input too large or too slow to normalize) covers nothing: key the exact input so two different inputs never share a key.
    const material = action.truncated === true && !covered && !empty ? raw() : `norm\n${sortedJson(action)}`;
    return { key: hmacHex(salt, 'action', material), programs: action.tool_kind === 'shell' ? action.programs || [] : [] };
  } catch {
    return { key: hmacHex(salt, 'action', raw()), programs: [] };
  }
}

/** The git top level of cwd, else cwd itself (both realpath), or null when the workspace is unknown. */
function workspaceRoot(fs: Fs, cwd: unknown): string | null {
  if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096) return null;
  try {
    const start = fs.realpathSync(cwd);
    let dir = start;
    for (;;) {
      try { fs.lstatSync(dir === '/' ? '/.git' : `${dir}/.git`); return dir; } catch { /* no .git here */ }
      if (dir === '/') return start;
      dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
    }
  } catch {
    return null;
  }
}

/** Program basenames, only from the classifier vocabulary; anything else is `other`. */
function programsOf(found: string[]): string[] {
  const out: string[] = [];
  for (const name of found) {
    const base = basename(String(name)).toLowerCase();
    const known = PROGRAMS.has(base) ? base : 'other';
    if (!out.includes(known)) out.push(known);
    if (out.length >= 8) break;
  }
  return out;
}

/** A subcommand word from the fixed vocabulary, found lexically after a known program. Never any other text. */
function subcommandOf(event: { tool_input?: unknown }): string {
  const input = event.tool_input;
  const command = typeof input === 'string' ? input
    : input && typeof input === 'object' && typeof (input as Record<string, unknown>).command === 'string' ? (input as Record<string, string>).command : '';
  const words = command.slice(0, 8192).split(/[\s;&|()<>`]+/).map((w) => w.replace(/^['"\\]+|['"\\]+$/g, ''));
  let found = 'none';
  for (let i = 0; i < words.length; i += 1) {
    if (!SUB_PROGRAMS.has(basename(words[i]).toLowerCase())) continue;
    for (let j = i + 1, seen = 0; j < words.length && seen < 3; j += 1) {
      const word = words[j].toLowerCase();
      if (!word || word.startsWith('-')) continue;
      seen += 1;
      if (SUBCOMMANDS.has(word) && word !== 'none' && word !== 'other') {
        if (RISKY_SUBCOMMANDS.includes(word)) return word;
        if (found === 'none' || found === 'other') found = word;
        break;
      }
      if (found === 'none') found = 'other';
    }
  }
  return found;
}

/** The mapper's hits carry no target, so only the classes its reason codes and flags prove are named; the rest is `unknown`. */
function targetClass(category: string, reasons: string[], flags: string[]): string {
  if (category === 'S1') return reasons.some((r) => r.includes('protected')) ? 'protected_branch' : 'unknown';
  if (category === 'S2') return flags.includes('prod') ? 'prod_env' : 'unknown';
  if (category === 'S5') return reasons.some((r) => r.endsWith('_outside_workspace')) ? 'outside_workspace' : 'unknown';
  if (category === 'none' && flags.includes('protected_branch_push')) return 'protected_branch';
  return 'unknown';
}

let engineCache: SeatbeltReceipt['engine'] | null = null;
function engine(fs: Fs): SeatbeltReceipt['engine'] {
  if (engineCache) return engineCache;
  let tables = 'unknown';
  try { tables = sha256Hex(fs.readFileSync(join(__dirname, 'tables.js'), 'latin1')).slice(0, 16); } catch { /* the hash is a label; a build without the file says unknown */ }
  engineCache = { pkg: MCP_ADAPTER_VERSION, contract: CLASSIFIER_PIN.contract, source_commit: CLASSIFIER_PIN.source_commit, rules: SEATBELT_RULES_VERSION, tables };
  return engineCache;
}

const codeList = (list: unknown, ok: (s: string) => boolean, max: number): string[] => {
  const out: string[] = [];
  if (Array.isArray(list)) for (const item of list) if (typeof item === 'string' && ok(item) && !out.includes(item)) { out.push(item); if (out.length >= max) break; }
  return out;
};

function buildReceipt(record: SeatbeltRecord, context: SeatbeltRecordContext, salt: Buffer, fs: Fs, now: number): ReceiptBody {
  const watch = record.enforcement === 'watch';
  const category = CATEGORIES.has(record.category) ? record.category : 'unknown';
  const reasons = codeList(record.reasons, (s) => REASON.test(s) && !hasHexRun(s), 16);
  const flags = codeList(record.flags, (s) => FLAG_CODES.has(s), 14);
  // Account floor in watch: the hook passed the action. A would-stop is a flag, never a claim that Marrow stopped it.
  const decision = (record.decision === 'stop' || record.decision === 'skipped') && !watch ? 'stop' : 'pass';
  if (watch && record.decision === 'stop') flags.push('floor_watch');
  if (watch && record.decision === 'skipped') flags.push('floor_skipped');
  const { tool, kind } = toolOf(context.tool_name);
  const event = { tool_name: context.tool_name, tool_input: context.tool_input, input_truncated: context.truncated === true };
  const action = actionKey(salt, event);
  const root = workspaceRoot(fs, context.cwd);
  const session = typeof context.session === 'string' || typeof context.session === 'number' ? String(context.session).slice(0, 256) : '';
  return {
    v: 1, ts: Math.floor(now / 1000), ts_label: 'client_time', mode: record.mode, enforcement: record.enforcement,
    harness: Object.hasOwn(HARNESS_ENUM, record.harness) ? HARNESS_ENUM[record.harness] : 'other', event: 'pre_tool', tool_kind: kind, tool, decision, category,
    rule: RULE.test(record.rule) ? record.rule : 'unknown', reasons,
    programs: kind === 'shell' ? programsOf(action.programs) : [], subcommand: kind === 'shell' ? subcommandOf(event) : 'none',
    flags, target_class: targetClass(category, reasons, flags),
    parse: PARSES.has(record.parse) ? record.parse : 'unknown',
    action_key: action.key, workspace_key: hmacHex(salt, 'workspace', root === null ? 'unknown' : `path\n${root}`),
    session_key: hmacHex(salt, 'session', session === '' ? 'none' : `id\n${session}`),
    engine: engine(fs), latency_ms: Number.isFinite(record.latency_ms) ? Math.min(600_000, Math.max(0, Math.round(record.latency_ms))) : 0,
  };
}

// ---------------------------------------------------------------------------
// The store: ~/.marrow/seatbelt (0700, owner-checked), no symlinks, O_NOFOLLOW
// ---------------------------------------------------------------------------

interface Store {
  fs: Fs;
  uid: number;
  dir: string;
  receipts: string;
  salt: Buffer;
}

const C = nodeFs.constants;
const NOFOLLOW = C.O_NOFOLLOW || 0;
const codeOf = (error: unknown): string => String((error as NodeJS.ErrnoException | null)?.code || '');

function lstatOrNull(fs: Fs, path: string): nodeFs.Stats | null {
  try {
    return fs.lstatSync(path);
  } catch (error) {
    if (codeOf(error) === 'ENOENT') return null;
    throw error;
  }
}

/** A directory we own. `strict`: no group or other access. `.marrow` itself may be a symlink to such a directory; nothing below it may. */
function ensureDir(fs: Fs, path: string, uid: number, strict: boolean, followLink: boolean): string {
  let st = lstatOrNull(fs, path);
  if (!st) {
    try { fs.mkdirSync(path, { mode: 0o700 }); } catch (error) { if (codeOf(error) !== 'EEXIST') throw error; }
    st = fs.lstatSync(path);
  }
  let real = path;
  if (st.isSymbolicLink()) {
    if (!followLink) throw new Refusal('unsafe_store');
    real = fs.realpathSync(path);
    st = fs.lstatSync(real);
  }
  if (!st.isDirectory() || st.uid !== uid || (st.mode & (strict ? 0o077 : 0o022)) !== 0) throw new Refusal('unsafe_store');
  return real;
}

function readSalt(fs: Fs, path: string, uid: number): Buffer {
  const fd = fs.openSync(path, C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
  try {
    const st = fs.fstatSync(fd);
    // No link-count check on the salt: it is only read, and while another hook is creating it (temp file linked into place) it briefly has two names.
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o077) !== 0 || st.size !== 32) throw new Refusal('unsafe_store');
    const buffer = Buffer.alloc(32);
    if (fs.readSync(fd, buffer, 0, 32, 0) !== 32) throw new Refusal('unsafe_store');
    return buffer;
  } finally {
    fs.closeSync(fd);
  }
}

/** 32 random bytes, created once: a temp file linked into place (link fails if anything, even a symlink, is already there). */
function loadSalt(fs: Fs, dir: string, uid: number): Buffer {
  const path = join(dir, 'salt');
  try {
    return readSalt(fs, path, uid);
  } catch (error) {
    if (codeOf(error) !== 'ENOENT') throw error;
  }
  const tmp = join(dir, `.salt.${process.pid}.${randomBytes(6).toString('hex')}`);
  const fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
  try {
    fs.writeSync(fd, randomBytes(32));
  } finally {
    fs.closeSync(fd);
  }
  try {
    try { fs.linkSync(tmp, path); } catch (error) { if (codeOf(error) !== 'EEXIST') throw error; }
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
  }
  return readSalt(fs, path, uid);
}

/** `found.dir` is set as soon as ~/.marrow/seatbelt is a real directory we own, so a refusal below it can still be counted. */
function openStore(fs: Fs, home: string, uid: number, found: { dir?: string }): Store {
  if (!home.startsWith('/')) throw new Refusal('unsafe_store');
  const realHome = fs.realpathSync(home);
  const homeStat = fs.statSync(realHome);
  if (realHome === '/' || !homeStat.isDirectory() || homeStat.uid !== uid) throw new Refusal('unsafe_store');
  const marrow = ensureDir(fs, join(realHome, '.marrow'), uid, false, true);
  const dir = join(marrow, 'seatbelt');
  const seen = lstatOrNull(fs, dir);
  if (seen && seen.isDirectory() && seen.uid === uid) found.dir = dir;
  ensureDir(fs, dir, uid, true, false);
  found.dir = dir;
  const receipts = join(dir, 'receipts');
  ensureDir(fs, receipts, uid, true, false);
  return { fs, uid, dir, receipts, salt: loadSalt(fs, dir, uid) };
}

const sleep = (ms: number): void => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

/** One writer at a time (so seq/prev stay a chain). A holder that died is stolen from after LOCK_STALE_MS. */
function withLock<T>(fs: Fs, dir: string, waitMs: number, work: () => T): T {
  const path = join(dir, 'lock');
  const started = Date.now();
  let fd: number | null = null;
  while (fd === null) {
    try {
      fd = fs.openSync(path, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
    } catch (error) {
      if (codeOf(error) !== 'EEXIST') throw error;
      if (Date.now() - started > waitMs) throw new Refusal('lock_timeout');
      try {
        const st = fs.lstatSync(path);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) { fs.unlinkSync(path); continue; }
      } catch { /* released meanwhile, or not ours to remove */ }
      sleep(2);
    }
  }
  try {
    return work();
  } finally {
    try { fs.closeSync(fd); } catch { /* ignore */ }
    try { fs.unlinkSync(path); } catch { /* ignore */ }
  }
}

interface State { v: 1; receipt_drop: number; drop_reasons: Record<string, number>; evicted_files: number; evicted_bytes: number }

function readState(fs: Fs, dir: string): State {
  const state: State = { v: 1, receipt_drop: 0, drop_reasons: {}, evicted_files: 0, evicted_bytes: 0 };
  try {
    const fd = fs.openSync(join(dir, 'state.json'), C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
    try {
      const buffer = Buffer.alloc(8192);
      const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
      const parsed = JSON.parse(buffer.subarray(0, length).toString('utf8')) as Partial<State>;
      const count = (n: unknown): number => (typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? n : 0);
      state.receipt_drop = count(parsed.receipt_drop);
      state.evicted_files = count(parsed.evicted_files);
      state.evicted_bytes = count(parsed.evicted_bytes);
      for (const reason of DROP_REASONS) if (parsed.drop_reasons && count(parsed.drop_reasons[reason])) state.drop_reasons[reason] = count(parsed.drop_reasons[reason]);
    } finally {
      fs.closeSync(fd);
    }
  } catch { /* missing, unreadable or not a regular file: counting starts again */ }
  return state;
}

/** Atomic replace (temp file + rename), so a crash or a full disk never leaves a half-written state.json. */
function updateState(fs: Fs, dir: string, change: (state: State) => void): void {
  const state = readState(fs, dir);
  change(state);
  const tmp = join(dir, `.state.${process.pid}.${randomBytes(6).toString('hex')}`);
  try {
    const fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
    try {
      fs.writeSync(fd, `${JSON.stringify(state)}\n`);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, join(dir, 'state.json'));
  } catch (error) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw error;
  }
}

const ymd = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

interface ManagedFile { name: string; path: string; size: number }

function managedFiles(fs: Fs, dir: string): ManagedFile[] {
  const out: ManagedFile[] = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (!FILE_NAME.test(name)) continue;
    const path = join(dir, name);
    const st = lstatOrNull(fs, path);
    if (st) out.push({ name, path, size: st.isFile() ? st.size : 0 });
  }
  return out;
}

/** The last line of a receipt file: its sha256 and seq, or null when the file has no line. `open`: the file does not end in a newline. */
function tailOf(fs: Fs, fd: number, size: number): { hash: string; seq: number | null; open: boolean } | null {
  if (size <= 0) return null;
  const length = Math.min(size, MAX_RECEIPT_BYTES + 2);
  const buffer = Buffer.alloc(length);
  const got = fs.readSync(fd, buffer, 0, length, size - length);
  const text = buffer.subarray(0, got).toString('utf8');
  const open = !text.endsWith('\n');
  const body = open ? text : text.slice(0, -1);
  const line = body.slice(body.lastIndexOf('\n') + 1);
  let seq: number | null = null;
  try {
    const parsed = JSON.parse(line) as { seq?: unknown };
    if (isInt(parsed.seq, 1, Number.MAX_SAFE_INTEGER - 1)) seq = parsed.seq;
  } catch { /* a damaged last line: the chain restarts at 1 and the break shows */ }
  return { hash: sha256Hex(line), seq, open };
}

/** Under the lock: retention and cap, then one O_APPEND write of the next link in the chain. */
function append(store: Store, body: ReceiptBody, now: number, options: ReceiptOptions): void {
  const { fs } = store;
  const cap = options.maxTotalBytes ?? MAX_TOTAL_BYTES;
  const todayName = `${ymd(now)}.jsonl`;
  let files = managedFiles(fs, store.receipts);
  // Retention counts from the newest earlier file when the clock is further ahead than that: a clock that jumped forward
  // (a resumed VM, a reset RTC) must not wipe the history. Day names are dates, so one day of slack is a plain string step.
  const newestEarlier = files.filter((file) => file.name < todayName).pop();
  const basis = newestEarlier ? Math.min(now, Date.parse(`${newestEarlier.name.slice(0, 10)}T00:00:00Z`) + 2 * 86_400_000) : now;
  const cutoff = `${ymd(basis - (options.retentionDays ?? RETENTION_DAYS) * 86_400_000)}.jsonl`;
  let evictedFiles = 0;
  let evictedBytes = 0;
  const evict = (file: ManagedFile): void => {
    try { fs.unlinkSync(file.path); } catch (error) { if (codeOf(error) !== 'ENOENT') throw error; }
    evictedFiles += 1;
    evictedBytes += file.size;
    files = files.filter((other) => other !== file);
  };
  // Retention first, then oldest-first until the new record fits. Today's file is never evicted.
  for (const file of [...files]) if (file.name < cutoff && file.name !== todayName) evict(file);
  let total = files.reduce((sum, file) => sum + file.size, 0);
  for (const file of [...files]) {
    if (total + MAX_RECEIPT_BYTES <= cap) break;
    if (file.name === todayName) continue;
    evict(file);
    total -= file.size;
  }
  if (evictedFiles > 0) {
    try { updateState(fs, store.dir, (state) => { state.evicted_files += evictedFiles; state.evicted_bytes += evictedBytes; }); } catch { /* the count is best effort */ }
  }
  if (total + MAX_RECEIPT_BYTES > cap) throw new Refusal('cap_full');

  // O_NONBLOCK: a FIFO planted as a day file must not hang the hook (it is then refused: not a regular file).
  const fd = fs.openSync(join(store.receipts, todayName), C.O_RDWR | C.O_APPEND | C.O_CREAT | NOFOLLOW | (C.O_NONBLOCK || 0), 0o600);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== store.uid || (st.mode & 0o077) !== 0) throw new Refusal('unsafe_store');
    let tail = tailOf(fs, fd, st.size);
    if (tail === null) {
      // First line of the day: continue the chain from the newest earlier file.
      const earlier = files.filter((file) => file.name < todayName && file.size > 0).pop();
      if (earlier) {
        try {
          const old = fs.openSync(earlier.path, C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
          try {
            const earlierStat = fs.fstatSync(old);
            if (earlierStat.isFile()) tail = tailOf(fs, old, earlierStat.size);
          } finally { fs.closeSync(old); }
        } catch { tail = null; }
      }
    }
    const { v, ...rest } = body;
    const receipt: SeatbeltReceipt = {
      v, id: `sbr_${randomBytes(16).toString('hex')}`, seq: tail && tail.seq !== null ? tail.seq + 1 : 1, prev: tail ? tail.hash : ZERO_PREV, ...rest,
    };
    if (validateReceipt(receipt).length > 0) throw new Refusal('error');
    const bytes = Buffer.from(`${st.size > 0 && tail && tail.open ? '\n' : ''}${JSON.stringify(receipt)}\n`);
    if (bytes.length > MAX_RECEIPT_BYTES) throw new Refusal('oversize');
    if (fs.writeSync(fd, bytes, 0, bytes.length) !== bytes.length) throw new Refusal('write_failed');
  } finally {
    fs.closeSync(fd);
  }
}

function dropReason(error: unknown): DropReason {
  if (error instanceof Refusal) return error.reason;
  const code = codeOf(error);
  if (code === 'ELOOP' || code === 'ENOTDIR' || code === 'EISDIR') return 'unsafe_store';
  return /^(?:ENOSPC|EACCES|EPERM|EIO|EROFS|EDQUOT|EMFILE|ENFILE|EBUSY)$/.test(code) ? 'write_failed' : 'error';
}

/** `receipt_drop` (and its reason) in state.json. Best effort: with no safe directory to count in, the drop stays invisible rather than risk a write. */
function countDrop(fs: Fs, dir: string, reason: DropReason, waitMs: number): void {
  const change = (state: State): void => { state.receipt_drop += 1; state.drop_reasons[reason] = (state.drop_reasons[reason] || 0) + 1; };
  try {
    try {
      withLock(fs, dir, Math.min(waitMs, 40), () => updateState(fs, dir, change));
    } catch (error) {
      if (!(error instanceof Refusal && error.reason === 'lock_timeout')) throw error;
      updateState(fs, dir, change);
    }
  } catch { /* see above */ }
}

function passwdHome(): string | null {
  try {
    const home = userInfo().homedir;
    return typeof home === 'string' && home.startsWith('/') ? home : null;
  } catch {
    return null;
  }
}

/** Write one receipt. Never throws; says what happened. The hook calls recordSeatbeltDecision; tests call this with options. */
export function writeSeatbeltReceipt(record: SeatbeltRecord, context: SeatbeltRecordContext = {}, options: ReceiptOptions = {}): 'written' | 'dropped' {
  const fs = options.fs || nodeFs;
  const found: { dir?: string } = {};
  let wait = options.lockWaitMs ?? LOCK_WAIT_MS;
  try {
    const uid = options.uid === undefined ? (typeof process.getuid === 'function' ? process.getuid() : null) : options.uid;
    if (typeof uid !== 'number') throw new Refusal('platform');
    const home = options.home || context.home || passwdHome();
    if (!home) throw new Refusal('unsafe_store');
    const now = options.now ?? Date.now();
    const store = openStore(fs, home, uid, found);
    const body = buildReceipt(record, context, store.salt, fs, now);
    wait = options.lockWaitMs ?? (body.decision === 'stop' ? STOP_LOCK_WAIT_MS : LOCK_WAIT_MS);
    withLock(fs, store.dir, wait, () => append(store, body, now, options));
    return 'written';
  } catch (error) {
    if (found.dir) countDrop(fs, found.dir, dropReason(error), wait);
    return 'dropped';
  }
}

/** The record hook U5 calls once per decision. It never throws, writes no output and never changes a decision. */
export function recordSeatbeltDecision(record: SeatbeltRecord, context?: SeatbeltRecordContext): void {
  try {
    writeSeatbeltReceipt(record, context || {});
  } catch { /* the record hook never changes a decision */ }
}
