import { createHmac, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Owner-only local state for held actions (~/.marrow/host-approvals/state.json,
 * 0700/0600, never a symlink). It links the hook process that saw a hold to
 * the later hook processes that see the operator's answer (PermissionRequest,
 * PostToolUse, PostToolBatch, a typed reply) and keeps an unsent report so it
 * is resent unchanged. It stores identifiers, timestamps and Marrow's own
 * coarse action classification only: no prompts, commands, tool output or
 * credentials. Records are bound to the API key, base URL and agent by a keyed
 * hash, so another key on the same machine never sees them.
 */

const STATE_VERSION = 1;
const STATE_DIRECTORY = 'host-approvals';
const STATE_FILENAME = 'state.json';
const STATE_MAX_BYTES = 512 * 1024;
const MAX_HOLDS = 64;
const MAX_MARKERS = 128;
/** A hold outlives its 30-minute gate receipt only long enough to settle a late report. */
export const HOLD_RECORD_TTL_MS = 2 * 60 * 60 * 1000;
const MARKER_TTL_MS = 24 * 60 * 60 * 1000;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const APPROVAL_CODE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const HEX32 = /^[a-f0-9]{32}$/;

export type HoldMode = 'ask' | 'wait';
export type HoldState = 'open' | 'allowed' | 'resolved';

export type HoldReport = {
  verdict: 'approved' | 'declined';
  host: string;
  host_session_id: string;
  hook_event: string | null;
  pre_action_event_id: string | null;
  asked_at: string;
  answered_at: string;
  decision_id?: string;
};

export type HoldCommit = {
  success: boolean;
  outcome: string;
};

export type HoldOutbox = {
  report: HoldReport | null;
  /** The commit that follows the report (a denial, or an outcome that needs no proof). */
  commit: HoldCommit | null;
  attempts: number;
  next_at: number;
};

export type HoldRecord = {
  id: string;
  key_ref: string;
  host: string;
  harness: string;
  session_id: string;
  host_session_id: string;
  agent_id: string | null;
  correlation: string;
  tool_use_id: string | null;
  generation_id: string | null;
  tool_name: string;
  hook_event: string;
  mode: HoldMode;
  state: HoldState;
  gate_receipt_id: string;
  decision_id: string | null;
  asked_at: string;
  dialog_at: string | null;
  pre_action_event_id: string | null;
  proof_required: boolean;
  proof_fields: string[];
  expires_at: string | null;
  code: string | null;
  action: { action: string; target: string; type: string; surfaces: string[] };
  outbox: HoldOutbox | null;
  created_at: number;
  updated_at: number;
};

type Marker = { at: number; value: boolean };

type ApprovalState = {
  version: 1;
  secret: string;
  holds: Record<string, HoldRecord>;
  /** Hashed host session -> interactive flag (Cursor sessionStart: is_background_agent false). */
  interactive: Record<string, Marker>;
  /** Hashed host session -> the host's typed-reply hook has run for it. */
  prompt_hook: Record<string, Marker>;
};

export class UnsafeHostApprovalStateError extends Error {
  constructor() {
    super('Local Marrow host-approval state is unsafe or invalid. Repair ~/.marrow/host-approvals before retrying.');
    this.name = 'UnsafeHostApprovalStateError';
  }
}

function unsafe(): never { throw new UnsafeHostApprovalStateError(); }

function owned(stat: Stats): boolean {
  const current = typeof process.getuid === 'function' ? process.getuid() : null;
  return current == null || stat.uid === current;
}

function exactPrivate(stat: Stats, mode: number): boolean {
  return owned(stat) && !stat.isSymbolicLink() && (stat.mode & 0o777) === mode;
}

function paths(home = process.env.HOME || homedir()): { marrow: string; directory: string; target: string } {
  const marrow = join(home, '.marrow');
  const directory = join(marrow, STATE_DIRECTORY);
  return { marrow, directory, target: join(directory, STATE_FILENAME) };
}

function ensureDirectories(home?: string): ReturnType<typeof paths> {
  const result = paths(home);
  if (!existsSync(result.marrow)) mkdirSync(result.marrow, { mode: 0o700 });
  const marrowStat = lstatSync(result.marrow);
  if (!marrowStat.isDirectory() || marrowStat.isSymbolicLink() || !owned(marrowStat) || (marrowStat.mode & 0o022) !== 0) unsafe();
  if (!existsSync(result.directory)) mkdirSync(result.directory, { mode: 0o700 });
  const directoryStat = lstatSync(result.directory);
  if (!directoryStat.isDirectory() || !exactPrivate(directoryStat, 0o700)) unsafe();
  return result;
}

function withLock<T>(home: string | undefined, callback: () => T): T {
  const { directory } = ensureDirectories(home);
  const lock = join(directory, '.state.lock');
  let fd = -1;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      const opened = fstatSync(fd);
      if (!opened.isFile() || !exactPrivate(opened, 0o600)) return unsafe();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return unsafe();
      let stat: Stats;
      try { stat = lstatSync(lock); } catch { continue; }
      if (!stat.isFile() || !exactPrivate(stat, 0o600)) return unsafe();
      if (Date.now() - stat.mtimeMs > 10_000) {
        try { unlinkSync(lock); } catch { /* another process removed it */ }
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
  if (fd < 0) return unsafe();
  try {
    return callback();
  } finally {
    closeSync(fd);
    try { unlinkSync(lock); } catch { /* a stopped process leaves a bounded stale lock */ }
  }
}

function emptyState(): ApprovalState {
  return { version: STATE_VERSION, secret: randomBytes(32).toString('base64url'), holds: {}, interactive: {}, prompt_hook: {} };
}

function isIso(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
}

function validReport(value: unknown): value is HoldReport | null {
  if (value === null) return true;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const report = value as HoldReport;
  return (report.verdict === 'approved' || report.verdict === 'declined')
    && typeof report.host === 'string' && report.host.length <= 32
    && typeof report.host_session_id === 'string' && IDENTIFIER.test(report.host_session_id)
    && (report.hook_event === null || (typeof report.hook_event === 'string' && /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/.test(report.hook_event)))
    && (report.pre_action_event_id === null || (typeof report.pre_action_event_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(report.pre_action_event_id)))
    && isIso(report.asked_at) && isIso(report.answered_at)
    && (report.decision_id === undefined || (typeof report.decision_id === 'string' && IDENTIFIER.test(report.decision_id)));
}

function validHold(value: unknown): value is HoldRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const hold = value as HoldRecord;
  const outbox = hold.outbox;
  return /^hold_[a-f0-9]{24}$/.test(hold.id)
    && HEX32.test(hold.key_ref)
    && typeof hold.host === 'string' && hold.host.length <= 32
    && typeof hold.harness === 'string' && hold.harness.length <= 32
    && typeof hold.session_id === 'string' && hold.session_id.length <= 256
    && typeof hold.host_session_id === 'string' && IDENTIFIER.test(hold.host_session_id)
    && (hold.agent_id === null || (typeof hold.agent_id === 'string' && hold.agent_id.length <= 128))
    && HEX32.test(hold.correlation)
    && (hold.tool_use_id === null || (typeof hold.tool_use_id === 'string' && hold.tool_use_id.length <= 128))
    && (hold.generation_id === null || (typeof hold.generation_id === 'string' && hold.generation_id.length <= 128))
    && typeof hold.tool_name === 'string' && hold.tool_name.length <= 256
    && typeof hold.hook_event === 'string' && hold.hook_event.length <= 64
    && (hold.mode === 'ask' || hold.mode === 'wait')
    && (hold.state === 'open' || hold.state === 'allowed' || hold.state === 'resolved')
    && typeof hold.gate_receipt_id === 'string' && IDENTIFIER.test(hold.gate_receipt_id)
    && (hold.decision_id === null || (typeof hold.decision_id === 'string' && IDENTIFIER.test(hold.decision_id)))
    && isIso(hold.asked_at)
    && (hold.dialog_at === null || isIso(hold.dialog_at))
    && (hold.pre_action_event_id === null || typeof hold.pre_action_event_id === 'string')
    && typeof hold.proof_required === 'boolean'
    && Array.isArray(hold.proof_fields) && hold.proof_fields.length <= 24 && hold.proof_fields.every((field) => typeof field === 'string' && field.length <= 64)
    && (hold.expires_at === null || isIso(hold.expires_at))
    && (hold.code === null || (typeof hold.code === 'string' && APPROVAL_CODE.test(hold.code)))
    && Boolean(hold.action) && typeof hold.action.action === 'string' && hold.action.action.length <= 512
    && typeof hold.action.target === 'string' && hold.action.target.length <= 256
    && typeof hold.action.type === 'string' && hold.action.type.length <= 64
    && Array.isArray(hold.action.surfaces) && hold.action.surfaces.length <= 16 && hold.action.surfaces.every((surface) => typeof surface === 'string' && surface.length <= 64)
    && (outbox === null || (Boolean(outbox) && typeof outbox === 'object'
      && validReport(outbox.report)
      && (outbox.commit === null || (Boolean(outbox.commit) && typeof outbox.commit.success === 'boolean' && typeof outbox.commit.outcome === 'string' && outbox.commit.outcome.length <= 600))
      && Number.isSafeInteger(outbox.attempts) && outbox.attempts >= 0 && outbox.attempts <= 1000
      && Number.isSafeInteger(outbox.next_at) && outbox.next_at >= 0))
    && Number.isSafeInteger(hold.created_at) && Number.isSafeInteger(hold.updated_at);
}

function validMarkers(value: unknown): value is Record<string, Marker> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const entries = Object.entries(value as Record<string, unknown>);
  return entries.length <= MAX_MARKERS && entries.every(([key, marker]) => /^[a-f0-9]{64}$/.test(key)
    && Boolean(marker) && typeof marker === 'object'
    && Number.isSafeInteger((marker as Marker).at) && typeof (marker as Marker).value === 'boolean');
}

function validateState(value: unknown): ApprovalState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return unsafe();
  const state = value as ApprovalState;
  if (state.version !== STATE_VERSION || !/^[A-Za-z0-9_-]{43}$/.test(state.secret)
    || !state.holds || typeof state.holds !== 'object' || Array.isArray(state.holds)
    || !validMarkers(state.interactive) || !validMarkers(state.prompt_hook)) return unsafe();
  const holds = Object.entries(state.holds);
  if (holds.length > MAX_HOLDS) return unsafe();
  // A record this client cannot read is dropped, so one bad record never blocks later hooks.
  for (const [key, hold] of holds) if (!validHold(hold) || hold.id !== key) delete state.holds[key];
  return state;
}

function readState(home?: string): { state: ApprovalState; target: string; directory: string } {
  const { target, directory } = ensureDirectories(home);
  if (!existsSync(target)) return { state: emptyState(), target, directory };
  const stat = lstatSync(target);
  if (!stat.isFile() || !exactPrivate(stat, 0o600) || stat.size < 2 || stat.size > STATE_MAX_BYTES) return unsafe();
  let fd = -1;
  try {
    fd = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== stat.ino || !exactPrivate(opened, 0o600)) return unsafe();
    const raw = readFileSync(fd, 'utf8');
    return { state: validateState(JSON.parse(raw)), target, directory };
  } catch (error) {
    if (error instanceof UnsafeHostApprovalStateError) throw error;
    return unsafe();
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

function prune(state: ApprovalState, now: number): void {
  for (const [id, hold] of Object.entries(state.holds)) {
    const expiry = hold.expires_at ? Date.parse(hold.expires_at) : NaN;
    const settled = hold.state === 'resolved' && !hold.outbox;
    const pastExpiry = Number.isFinite(expiry) && now > expiry + 10 * 60_000 && !hold.outbox;
    if (now - hold.created_at > HOLD_RECORD_TTL_MS || pastExpiry || (settled && now - hold.updated_at > 10 * 60_000)) delete state.holds[id];
  }
  const holds = Object.values(state.holds).sort((a, b) => b.updated_at - a.updated_at);
  for (const hold of holds.slice(MAX_HOLDS)) delete state.holds[hold.id];
  for (const markers of [state.interactive, state.prompt_hook]) {
    for (const [key, marker] of Object.entries(markers)) if (now - marker.at > MARKER_TTL_MS) delete markers[key];
    const ordered = Object.entries(markers).sort((a, b) => b[1].at - a[1].at);
    for (const [key] of ordered.slice(MAX_MARKERS)) delete markers[key];
  }
}

function writeState(state: ApprovalState, target: string, directory: string): void {
  prune(state, Date.now());
  const raw = `${JSON.stringify(state)}\n`;
  if (Buffer.byteLength(raw) > STATE_MAX_BYTES) unsafe();
  const temporary = join(directory, `.state-${process.pid}-${randomBytes(8).toString('hex')}.tmp`);
  let fd = -1;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    writeFileSync(fd, raw, 'utf8');
    closeSync(fd);
    fd = -1;
    renameSync(temporary, target);
  } finally {
    if (fd >= 0) closeSync(fd);
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* best effort cleanup */ }
  }
}

function keyed(secret: string, value: unknown, length = 64): string {
  return createHmac('sha256', Buffer.from(secret, 'base64url')).update(JSON.stringify(value)).digest('hex').slice(0, length);
}

export type HoldScope = { apiKey: string; baseUrl: string; agentId?: string | null };

function keyRef(state: ApprovalState, scope: HoldScope): string {
  return keyed(state.secret, ['key', scope.apiKey, scope.baseUrl.replace(/\/+$/, ''), scope.agentId || null], 32);
}

function freshCode(state: ApprovalState, gateReceiptId: string): string {
  const taken = new Set(Object.values(state.holds).map((hold) => hold.code).filter(Boolean));
  for (let round = 0; round < 32; round += 1) {
    const digest = createHmac('sha256', Buffer.from(state.secret, 'base64url')).update(`code:${round}:${gateReceiptId}`).digest();
    let code = '';
    for (let index = 0; index < 6; index += 1) code += CODE_ALPHABET[digest[index] % CODE_ALPHABET.length];
    if (!taken.has(code)) return code;
  }
  return unsafe();
}

export type NewHold = Omit<HoldRecord, 'id' | 'key_ref' | 'code' | 'outbox' | 'created_at' | 'updated_at' | 'state' | 'dialog_at'> & {
  withCode: boolean;
};

/** Records a held action. A previous open hold of the same action and session is replaced. */
export function recordHold(scope: HoldScope, input: NewHold, home?: string): HoldRecord {
  return withLock(home, () => {
    const { state, target, directory } = readState(home);
    const ref = keyRef(state, scope);
    const now = Date.now();
    for (const [id, hold] of Object.entries(state.holds)) {
      if (hold.key_ref === ref && hold.correlation === input.correlation && hold.mode === input.mode
        && hold.state !== 'resolved' && !hold.outbox && (hold.mode === 'wait' || hold.tool_use_id === input.tool_use_id)) {
        delete state.holds[id];
      }
    }
    const { withCode, ...fields } = input;
    const record: HoldRecord = {
      ...fields,
      id: `hold_${randomBytes(12).toString('hex')}`,
      key_ref: ref,
      code: withCode ? freshCode(state, input.gate_receipt_id) : null,
      outbox: null,
      state: 'open',
      dialog_at: null,
      created_at: now,
      updated_at: now,
    };
    state.holds[record.id] = record;
    writeState(state, target, directory);
    return record;
  });
}

export type HoldQuery = {
  correlation?: string;
  toolUseId?: string | null;
  sessionId?: string;
  hostSessionId?: string;
  generationId?: string | null;
  mode?: HoldMode;
  states?: HoldState[];
  code?: string;
  id?: string;
};

/** The stored form of a Marrow session id (the bound buildHeaders applies to X-Marrow-Session-Id). */
export function boundSessionId(value: string): string {
  return value.replace(/[^\x20-\x7E]/g, '').slice(0, 256);
}

function matches(hold: HoldRecord, ref: string, query: HoldQuery): boolean {
  if (hold.key_ref !== ref) return false;
  if (query.id && hold.id !== query.id) return false;
  if (query.correlation && hold.correlation !== query.correlation) return false;
  if (query.toolUseId && hold.tool_use_id && hold.tool_use_id !== query.toolUseId) return false;
  if (query.sessionId !== undefined && hold.session_id !== boundSessionId(query.sessionId)) return false;
  if (query.hostSessionId !== undefined && hold.host_session_id !== query.hostSessionId) return false;
  if (query.generationId && hold.generation_id && hold.generation_id !== query.generationId) return false;
  if (query.mode && hold.mode !== query.mode) return false;
  if (query.states && !query.states.includes(hold.state)) return false;
  if (query.code && hold.code !== query.code) return false;
  return true;
}

/** Reads without creating ~/.marrow/host-approvals when nothing was ever held. */
function peekState(home?: string): ApprovalState {
  return existsSync(paths(home).target) ? readState(home).state : emptyState();
}

export function findHolds(scope: HoldScope, query: HoldQuery, home?: string): HoldRecord[] {
  const state = peekState(home);
  const ref = keyRef(state, scope);
  return Object.values(state.holds)
    .filter((hold) => matches(hold, ref, query))
    .sort((a, b) => a.created_at - b.created_at);
}

/** Applies a change to one hold under the lock; returns the updated hold, or null when it is gone. */
export function updateHold(
  scope: HoldScope,
  id: string,
  change: (hold: HoldRecord) => HoldRecord | null,
  home?: string,
): HoldRecord | null {
  return withLock(home, () => {
    const { state, target, directory } = readState(home);
    const ref = keyRef(state, scope);
    const current = state.holds[id];
    if (!current || current.key_ref !== ref) return null;
    const next = change(structuredClone(current));
    if (next === null) delete state.holds[id];
    else state.holds[id] = { ...next, id: current.id, key_ref: current.key_ref, updated_at: Date.now() };
    writeState(state, target, directory);
    return next === null ? null : state.holds[id];
  });
}

/** Marks the oldest matching open ask whose dialog was not yet seen; returns it, if any. */
export function markDialogShown(scope: HoldScope, query: HoldQuery, at: string, home?: string): HoldRecord | null {
  return withLock(home, () => {
    const { state, target, directory } = readState(home);
    const ref = keyRef(state, scope);
    const candidate = Object.values(state.holds)
      .filter((hold) => matches(hold, ref, { ...query, mode: 'ask', states: ['open'] }) && hold.dialog_at === null)
      .sort((a, b) => a.created_at - b.created_at)[0];
    if (!candidate) return null;
    candidate.dialog_at = at;
    candidate.updated_at = Date.now();
    writeState(state, target, directory);
    return candidate;
  });
}

export function setSessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, value: boolean, home?: string): void {
  withLock(home, () => {
    const { state, target, directory } = readState(home);
    state[kind][keyed(state.secret, [kind, keyRef(state, scope), hostSessionId])] = { at: Date.now(), value };
    writeState(state, target, directory);
  });
}

export function sessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, home?: string): boolean | null {
  const state = peekState(home);
  const marker = state[kind][keyed(state.secret, [kind, keyRef(state, scope), hostSessionId])];
  return marker ? marker.value : null;
}

/** True when this key has any hold that still needs work (cheap check before network). */
export function hasPendingHolds(scope: HoldScope, query: HoldQuery = {}, home?: string): boolean {
  try {
    return findHolds(scope, { ...query, states: ['open', 'allowed'] }, home).length > 0
      || findHolds(scope, { ...query, states: ['resolved'] }, home).some((hold) => hold.outbox !== null);
  } catch {
    return false;
  }
}
