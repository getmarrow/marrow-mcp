import { createHmac, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { types } from 'node:util';
import { hookToolCommand, normalizeHookToolName } from './hook-tool-policy';
import { ensureWindowsPrivateState, realWindowsDeps, verifyWindowsPrivateState, type WinEnsure, type WinEnsureOk } from './win-private-state';

const STATE_VERSION = 1;
const STATE_DIRECTORY = 'session-loop-guard';
const STATE_FILENAME = 'state.json';
const STATE_MAX_BYTES = 256 * 1024;
const STATE_LOW_WATER_BYTES = 192 * 1024;
const LOOP_FLOOR = 3;
const STATE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 64;
const MAX_ENTRIES_PER_SESSION = 256;
// MCP-111 K2b: a compile-time switch (item 22, shipped ON). No env, file, option, hook payload or tool input reaches it;
// OFF is the 3.9.110 loop guard byte for byte (only resolveLoopEntry and the result step in record read it).
const LOOP_GUARD_SPLIT = true;
const BACKSTOP_COUNT = 4; // a padded loop (same call, junk past a cut) is stopped by its cut family at this count
const FULL_BUDGET = 4_194_304; // weighted work units; no clock, so a true repeat never changes branch under load
const FULL_DEPTH = 256;

type LoopOutcome = 'success' | 'failure';
type LoopKind = 'poll' | 'verification' | 'read' | 'mutation';

type LoopEntry = {
  fingerprint: string;
  kind: LoopKind;
  outcome: LoopOutcome | null;
  result_hash: string | null;
  unchanged_count: number;
  attempts: number;
  updated_at: number;
  receipt: string;
};

type SessionState = {
  work_epoch: number;
  instruction_epoch: number;
  updated_at: number;
  entries: Record<string, LoopEntry>;
  invocations: Record<string, string>;
};

type GuardState = {
  version: 1;
  secret: string;
  sessions: Record<string, SessionState>;
};

export type LoopGuardOperation = {
  sessionId?: string;
  agentId?: string;
  harness: string;
  toolName?: string;
  toolInput?: unknown;
  invocationId?: string;
  readOnly: boolean;
};

export type LoopGuardDecision = {
  allow: boolean;
  receipt: string;
  reason?: string;
  fingerprint: string;
};

export class UnsafeLoopGuardStateError extends Error {
  constructor() {
    super('Local Marrow session loop-guard state is unsafe or invalid. Repair ~/.marrow/session-loop-guard before retrying.');
    this.name = 'UnsafeLoopGuardStateError';
  }
}

function unsafe(): never { throw new UnsafeLoopGuardStateError(); }

function uid(): number | null {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function owned(stat: Stats): boolean {
  const current = uid();
  return current != null && stat.uid === current;
}

function exactPrivate(stat: Stats, mode: number): boolean {
  return owned(stat) && !stat.isSymbolicLink() && (stat.mode & 0o777) === mode;
}

function canonical(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[depth]';
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'string') return value.slice(0, 16_384);
  if (Array.isArray(value)) return value.slice(0, 128).map((item) => canonical(item, depth + 1));
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(source).sort().slice(0, 128).map((key) => [key.slice(0, 128), canonical(source[key], depth + 1)]));
  }
  return String(value).slice(0, 256);
}

function keyedHash(secret: string, value: unknown): string {
  return createHmac('sha256', Buffer.from(secret, 'base64url'))
    .update(JSON.stringify(canonical(value)))
    .digest('hex');
}

type Fingerprint = { fp: string; cut: string; split: boolean };

/** canonical() verbatim, plus `lossy`, set only where a cut branch loses information (a cut is `>`, never `>=`). */
export function canonicalTracked(value: unknown, depth: number, flag: { lossy: boolean; keys?: number }): unknown {
  if (depth > 8) { flag.lossy = true; return '[depth]'; }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') { if (!Number.isFinite(value)) flag.lossy = true; return Number.isFinite(value) ? value : String(value); }
  if (typeof value === 'string') { if (value.length > 16_384) flag.lossy = true; return value.slice(0, 16_384); }
  if (Array.isArray(value)) { if (value.length > 128) flag.lossy = true; return value.slice(0, 128).map((item) => canonicalTracked(item, depth + 1, flag)); }
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const names = Object.keys(source).sort();
    if (names.length > 128) { flag.lossy = true; flag.keys = (flag.keys ?? 0) + names.length; }
    return Object.fromEntries(names.slice(0, 128).map((key) => { if (key.length > 128) flag.lossy = true; return [key.slice(0, 128), canonicalTracked(source[key], depth + 1, flag)]; }));
  }
  flag.lossy = true;
  return String(value).slice(0, 256);
}

/**
 * The full form of a JSON-shaped value as one device-key HMAC: tagged, length-prefixed tokens (prefix-free), strings as
 * UTF-16LE, keys in code-unit order, no intermediate object. One loop over an explicit stack; every allocation is charged
 * to `budget` first. null means "not taken": an unsupported shape (undefined, bigint, symbol, function, Map and any other
 * prototype, Proxy, accessor, hole, a second visit of one object), depth over FULL_DEPTH, an overrun or any throw. The
 * caller then keeps the 3.9.110 fingerprint. `tap` sees every token (tests only).
 */
export function fullDigest(key: Buffer, value: unknown, tap?: (token: string) => void, budget = FULL_BUDGET): string | null {
  try {
    const hmac = createHmac('sha256', key).update('k2b-full\n');
    const put = (token: string, utf16 = false): void => { tap?.(token); hmac.update(token, utf16 ? 'utf16le' : 'utf8'); };
    const seen = new Set<object>();
    const vals: unknown[] = [value];
    const deps: number[] = [0]; // >= 0 a value at that depth, -1 a closing token, -2 a key name
    let work = 0;
    while (vals.length) {
      const v = vals.pop();
      const d = deps.pop() as number;
      if (d === -1) { put(v as string); continue; }
      if (d === -2) { if ((work += 2 * (v as string).length) > budget) return null; put(`s${(v as string).length}:`); put(v as string, true); continue; }
      if ((work += 40) > budget || d > FULL_DEPTH) return null;
      if (v === null) put('z');
      else if (typeof v === 'boolean') put(v ? 'T' : 'F');
      else if (typeof v === 'number') put(Number.isFinite(v) ? `n${JSON.stringify(v)}` : `N${v};`);
      else if (typeof v === 'string') { if ((work += 2 * v.length) > budget) return null; put(`s${v.length}:`); put(v, true); }
      else if (typeof v !== 'object' || types.isProxy(v) || seen.has(v)) return null;
      else if (Array.isArray(v)) {
        seen.add(v);
        if (Object.getPrototypeOf(v) !== Array.prototype || (work += 40 * v.length) > budget) return null;
        put(`[${v.length}:`);
        vals.push(']'); deps.push(-1);
        for (let i = v.length - 1; i >= 0; i -= 1) {
          const slot = Object.getOwnPropertyDescriptor(v, i);
          if (!slot || !('value' in slot)) return null;
          vals.push(slot.value); deps.push(d + 1);
        }
      } else {
        seen.add(v);
        const proto = Object.getPrototypeOf(v);
        if (proto !== Object.prototype && proto !== null) return null;
        const names = Object.keys(v);
        if ((work += 80 * names.length + 8 * names.length * Math.ceil(Math.log2(names.length || 1))) > budget) return null; // before the sort
        names.sort();
        put(`{${names.length}:`);
        vals.push('}'); deps.push(-1);
        for (let i = names.length - 1; i >= 0; i -= 1) {
          const slot = Object.getOwnPropertyDescriptor(v, names[i]);
          if (!slot || !('value' in slot)) return null;
          vals.push(slot.value, names[i]); deps.push(d + 1, -2);
        }
      }
    }
    return hmac.digest('hex');
  } catch { return null; } // reads nothing from the error and logs nothing: the answer is the 3.9.110 fingerprint
}

/**
 * `cut` is exactly 3.9.110's keyedHash of the value (one tracked pass instead of canonical() twice). A value that lost
 * nothing keeps it. A value a cut branch changed gets `fp`, a second HMAC over the cut text and the full digest, so two
 * calls that differ only past a cut differ. Anything the full walk cannot take keeps `cut`: exactly 3.9.110.
 */
export function loopFingerprint(secret: string, value: unknown, tap?: (token: string) => void, budget?: number, stats?: { fallbacks: number }): Fingerprint {
  const flag: { lossy: boolean; keys?: number } = { lossy: false };
  const key = Buffer.from(secret, 'base64url');
  const text = JSON.stringify(canonicalTracked(value, 0, flag));
  const cut = createHmac('sha256', key).update(text).digest('hex');
  if (!flag.lossy) return { fp: cut, cut, split: false };
  // 80 units per key is charged before any key is read: a list that big overruns the walk, so it is not started
  const full = (flag.keys ?? 0) * 80 > (budget ?? FULL_BUDGET) ? null : fullDigest(key, value, tap, budget);
  if (!full) { if (stats) stats.fallbacks += 1; return { fp: cut, cut, split: false }; }
  return { fp: createHmac('sha256', key).update(`${text}\n${full}`).digest('hex'), cut, split: true };
}

function paths(home = homedir()): { marrow: string; directory: string; target: string } {
  const marrow = join(home, '.marrow');
  const directory = join(marrow, STATE_DIRECTORY);
  return { marrow, directory, target: join(directory, STATE_FILENAME) };
}

// ---- Windows (3.9.106 spec, part A2). Chosen only by the real process.platform. ----------------------
// Mode bits and uid mean nothing on Windows, so the private-state proof is src/win-private-state.ts.
// The ACL query (it starts PowerShell) runs BEFORE the state lock is taken, never while it is held;
// inside the lock only the cheap structural half runs. The platform and the proof are one injectable
// set: production uses process.platform and the real proof; a test passes its own through
// withLoopGuardPlatform(). There is no env switch.
export interface LoopGuardPlatform {
  platform: NodeJS.Platform;
  ensure(home: string): WinEnsure;
  verify(home: string, proof: WinEnsureOk): boolean;
}
let injectedPlatform: LoopGuardPlatform | null = null;

export function withLoopGuardPlatform<T>(injected: LoopGuardPlatform, run: () => T): T {
  const previous = injectedPlatform;
  injectedPlatform = injected;
  let later = false;
  try {
    const result = run();
    if (result && typeof (result as { then?: unknown }).then === 'function') {
      later = true;
      return (result as unknown as Promise<unknown>).finally(() => { injectedPlatform = previous; }) as unknown as T;
    }
    return result;
  } finally {
    if (!later) injectedPlatform = previous;
  }
}

function isWin32(): boolean {
  return (injectedPlatform ? injectedPlatform.platform : process.platform) === 'win32';
}

type WindowsProven = { paths: ReturnType<typeof paths>; proof: WinEnsureOk };
// Set while this process holds the state lock, after the lock-time structural check passed.
let lockScoped: { home: string; paths: ReturnType<typeof paths> } | null = null;

/** The ACL proof. Refuses to run while the lock is held: no PowerShell spawn inside the lock. */
function proveWindows(home: string): WindowsProven {
  if (lockScoped) return unsafe();
  let result: WinEnsure;
  try {
    result = injectedPlatform ? injectedPlatform.ensure(home) : ensureWindowsPrivateState(home, realWindowsDeps());
  } catch { return unsafe(); }
  if (!result.ok) return unsafe();
  return { paths: { marrow: result.marrow, directory: result.directory, target: result.target }, proof: result };
}

function verifyWindows(home: string, proof: WinEnsureOk): boolean {
  try {
    return injectedPlatform ? injectedPlatform.verify(home, proof) : verifyWindowsPrivateState(home, proof, realWindowsDeps());
  } catch { return false; }
}

function ensureDirectoriesWindows(home: string): ReturnType<typeof paths> {
  const held = lockScoped;
  return held && held.home === home ? held.paths : proveWindows(home).paths;
}

/** A plain file reached through no link, not hard-linked, and the same object before and after open (no O_NOFOLLOW on Windows). */
function windowsPlainFile(fd: number | null, path: string): boolean {
  const byPath = lstatSync(path, { bigint: true });
  if (!byPath.isFile() || byPath.isSymbolicLink() || byPath.nlink !== 1n) return false;
  if (fd === null) return true;
  const opened = fstatSync(fd, { bigint: true });
  return opened.isFile() && opened.nlink === 1n && opened.dev === byPath.dev && opened.ino === byPath.ino;
}

function withStateLockWindows<T>(home: string | undefined, callback: () => T): T {
  const resolved = home ?? homedir();
  const proven = proveWindows(resolved);
  const lock = join(proven.paths.directory, '.state.lock');
  let fd = -1;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      if (!windowsPlainFile(fd, lock)) { closeSync(fd); fd = -1; return unsafe(); }
      break;
    } catch (error) {
      if (fd >= 0) { try { closeSync(fd); } catch { /* already unsafe */ } fd = -1; }
      if (error instanceof UnsafeLoopGuardStateError) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return unsafe();
      let stat;
      try { stat = lstatSync(lock, { bigint: true }); } catch (gone) {
        if ((gone as NodeJS.ErrnoException).code === 'ENOENT') continue;
        return unsafe();
      }
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) return unsafe();
      if (Date.now() - Number(stat.mtimeMs) > 30_000) {
        unlinkSync(lock);
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  if (fd < 0) return unsafe();
  try {
    // Holding the lock: only the structural half and the folder identity of the proof above.
    if (!verifyWindows(resolved, proven.proof)) return unsafe();
    lockScoped = { home: resolved, paths: proven.paths };
    return callback();
  } finally {
    lockScoped = null;
    closeSync(fd);
    try { unlinkSync(lock); } catch { /* a stopped process leaves a bounded stale lock */ }
  }
}

function readStateWindows(home: string): { state: GuardState; target: string; directory: string } {
  const { target, directory } = ensureDirectoriesWindows(home);
  let stat;
  try { stat = lstatSync(target, { bigint: true }); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { state: emptyState(), target, directory };
    return unsafe();
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 2n || stat.size > BigInt(STATE_MAX_BYTES)) return unsafe();
  let fd = -1;
  try {
    fd = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== stat.dev || opened.ino !== stat.ino) return unsafe();
    const raw = readFileSync(fd, 'utf8');
    if (Buffer.byteLength(raw) > STATE_MAX_BYTES) return unsafe();
    return { state: validateState(JSON.parse(raw)), target, directory };
  } catch (error) {
    if (error instanceof UnsafeLoopGuardStateError) throw error;
    return unsafe();
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

function ensureDirectories(home = homedir()): ReturnType<typeof paths> {
  if (isWin32()) return ensureDirectoriesWindows(home);
  const result = paths(home);
  if (!existsSync(result.marrow)) mkdirSync(result.marrow, { mode: 0o700 });
  const marrowStat = lstatSync(result.marrow);
  if (!marrowStat.isDirectory() || marrowStat.isSymbolicLink() || !owned(marrowStat) || (marrowStat.mode & 0o022) !== 0) unsafe();
  if (!existsSync(result.directory)) mkdirSync(result.directory, { mode: 0o700 });
  const directoryStat = lstatSync(result.directory);
  if (!directoryStat.isDirectory() || !exactPrivate(directoryStat, 0o700)) unsafe();
  return result;
}

function withStateLock<T>(home: string | undefined, callback: () => T): T {
  if (isWin32()) return withStateLockWindows(home, callback);
  const { directory } = ensureDirectories(home);
  const lock = join(directory, '.state.lock');
  let fd = -1;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      const opened = fstatSync(fd);
      if (!opened.isFile() || !exactPrivate(opened, 0o600)) return unsafe();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return unsafe();
      let stat: Stats;
      try {
        stat = lstatSync(lock);
      } catch (statError) {
        // The holder released the lock between our EEXIST and this lstat: take the next bounded attempt. Any other error escapes as before.
        if ((statError as NodeJS.ErrnoException).code === 'ENOENT') continue;
        throw statError;
      }
      if (!stat.isFile() || !exactPrivate(stat, 0o600)) return unsafe();
      if (Date.now() - stat.mtimeMs > 30_000) {
        unlinkSync(lock);
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
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

function emptyState(): GuardState {
  return { version: STATE_VERSION, secret: randomBytes(32).toString('base64url'), sessions: {} };
}

function validEntry(value: unknown): value is LoopEntry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const entry = value as LoopEntry;
  return /^[a-f0-9]{64}$/.test(entry.fingerprint)
    && ['poll', 'verification', 'read', 'mutation'].includes(entry.kind)
    && (entry.outcome === null || entry.outcome === 'success' || entry.outcome === 'failure')
    && (entry.result_hash === null || /^[a-f0-9]{64}$/.test(entry.result_hash))
    && Number.isSafeInteger(entry.unchanged_count) && entry.unchanged_count >= 0 && entry.unchanged_count <= 1_000_000
    && Number.isSafeInteger(entry.attempts) && entry.attempts >= 0 && entry.attempts <= 1_000_000
    && Number.isSafeInteger(entry.updated_at) && entry.updated_at > 0
    && /^lgr_[a-f0-9]{24}$/.test(entry.receipt);
}

function validateState(value: unknown): GuardState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return unsafe();
  const state = value as GuardState;
  if (state.version !== STATE_VERSION || !/^[A-Za-z0-9_-]{43}$/.test(state.secret) || !state.sessions || typeof state.sessions !== 'object' || Array.isArray(state.sessions)) unsafe();
  const sessions = Object.entries(state.sessions);
  if (sessions.length > MAX_SESSIONS || sessions.some(([key]) => !/^[a-f0-9]{64}$/.test(key))) unsafe();
  for (const [, session] of sessions) {
    if (!session || typeof session !== 'object' || Array.isArray(session)
      || !Number.isSafeInteger(session.work_epoch) || session.work_epoch < 0
      || !Number.isSafeInteger(session.instruction_epoch) || session.instruction_epoch < 0
      || !Number.isSafeInteger(session.updated_at) || session.updated_at <= 0
      || !session.entries || typeof session.entries !== 'object' || Array.isArray(session.entries)
      || !session.invocations || typeof session.invocations !== 'object' || Array.isArray(session.invocations)
      || Object.keys(session.invocations).length > MAX_ENTRIES_PER_SESSION
      || Object.entries(session.invocations).some(([key, fingerprint]) => !/^[a-f0-9]{64}$/.test(key) || !/^[a-f0-9]{64}$/.test(fingerprint))
      || Object.keys(session.entries).length > MAX_ENTRIES_PER_SESSION
      || Object.entries(session.entries).some(([key, entry]) => !/^[a-f0-9]{64}$/.test(key) || !validEntry(entry))) unsafe();
  }
  return state;
}

function readState(home = homedir()): { state: GuardState; target: string; directory: string } {
  if (isWin32()) return readStateWindows(home);
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
    if (Buffer.byteLength(raw) > STATE_MAX_BYTES) return unsafe();
    return { state: validateState(JSON.parse(raw)), target, directory };
  } catch (error) {
    if (error instanceof UnsafeLoopGuardStateError) throw error;
    return unsafe();
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}

function prune(state: GuardState, now: number): void {
  for (const [sessionKey, session] of Object.entries(state.sessions)) {
    if (now - session.updated_at > STATE_TTL_MS) delete state.sessions[sessionKey];
    else for (const [key, entry] of Object.entries(session.entries)) {
      if (now - entry.updated_at > STATE_TTL_MS) delete session.entries[key];
    }
  }
  const sessions = Object.entries(state.sessions).sort((a, b) => b[1].updated_at - a[1].updated_at);
  for (const [key] of sessions.slice(MAX_SESSIONS)) delete state.sessions[key];
  for (const session of Object.values(state.sessions)) {
    const entries = Object.entries(session.entries).sort((a, b) => b[1].updated_at - a[1].updated_at);
    for (const [key] of entries.slice(MAX_ENTRIES_PER_SESSION)) delete session.entries[key];
    const liveFingerprints = new Set(Object.keys(session.entries));
    for (const [key, fingerprint] of Object.entries(session.invocations)) {
      if (!liveFingerprints.has(fingerprint)) delete session.invocations[key];
    }
    for (const key of Object.keys(session.invocations).slice(0, Math.max(0, Object.keys(session.invocations).length - MAX_ENTRIES_PER_SESSION))) {
      delete session.invocations[key];
    }
  }
}

const byKey = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const jsonBytes = (value: unknown): number => Buffer.byteLength(JSON.stringify(value));

/**
 * Only over the cap: drop the oldest loop-guard entries of OTHER sessions (oldest session first, clamped to `now`,
 * never below LOOP_FLOOR entries and one mapping per kept entry) until the state is under the low-water mark. An entry
 * stamped after `now` (a backward clock step) stays on top of the floor and is never dropped here; master's TTL rule
 * removes it once the clock has passed it. The current session, the secret and the version are never touched.
 * Returns the serialized state, or fails closed as before.
 */
export function pruneLoopGuardStateToBytes(state: GuardState, currentKey: string | null, now: number, cap = STATE_MAX_BYTES, lowWater = STATE_LOW_WATER_BYTES): string {
  let raw = `${JSON.stringify(state)}\n`;
  let size = Buffer.byteLength(raw);
  if (size <= cap) return raw;
  const others = Object.entries(state.sessions)
    .filter(([key]) => key !== currentKey)
    .sort((a, b) => Math.min(a[1].updated_at, now) - Math.min(b[1].updated_at, now) || byKey(a[0], b[0]));
  for (const [, session] of others) {
    if (size <= lowWater) break;
    const entries = Object.entries(session.entries).sort((a, b) => b[1].updated_at - a[1].updated_at || byKey(a[0], b[0]));
    let floor = 0;
    const kept = new Set(entries.filter(([, entry]) => entry.updated_at > now || floor++ < LOOP_FLOOR).map(([key]) => key));
    const mappings = Object.entries(session.invocations);
    const newest = new Map(mappings.map(([key, fingerprint]) => [fingerprint, key]));
    // An item leaves with its key and one comma; the last item of an object has no comma.
    let entryCount = entries.length;
    let mappingCount = mappings.length;
    const dropMapping = (key: string): void => {
      size -= jsonBytes(key) + 1 + jsonBytes(session.invocations[key]) + (mappingCount-- > 1 ? 1 : 0);
      delete session.invocations[key];
    };
    for (const [key, fingerprint] of mappings) {
      if (size <= lowWater) break;
      // The newest mapping of an entry that stays is never dropped alone, so a later record still finds its entry.
      if (newest.get(fingerprint) !== key || !(fingerprint in session.entries)) dropMapping(key);
    }
    const mapped = new Map<string, string[]>();
    for (const [key, fingerprint] of mappings) mapped.set(fingerprint, [...(mapped.get(fingerprint) ?? []), key]);
    const droppable = entries.filter(([key]) => !kept.has(key)).sort((a, b) => a[1].updated_at - b[1].updated_at || byKey(a[0], b[0]));
    for (const [key, entry] of droppable) {
      if (size <= lowWater) break;
      size -= jsonBytes(key) + 1 + jsonBytes(entry) + (entryCount-- > 1 ? 1 : 0);
      delete session.entries[key];
      for (const mapping of mapped.get(key) ?? []) if (mapping in session.invocations) dropMapping(mapping);
    }
  }
  raw = `${JSON.stringify(state)}\n`;
  if (Buffer.byteLength(raw) > cap) unsafe();
  return raw;
}

function writeState(state: GuardState, target: string, directory: string, currentKey: string | null): void {
  const now = Date.now();
  prune(state, now);
  const raw = pruneLoopGuardStateToBytes(state, currentKey, now);
  const temporary = join(directory, `.state-${process.pid}-${randomBytes(8).toString('hex')}.tmp`);
  let fd = -1;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    if (isWin32() && !windowsPlainFile(fd, temporary)) unsafe();
    writeFileSync(fd, raw, 'utf8');
    closeSync(fd);
    fd = -1;
    renameSync(temporary, target);
  } finally {
    if (fd >= 0) closeSync(fd);
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* best effort cleanup */ }
  }
}

function sessionKey(state: GuardState, operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>): string {
  return keyedHash(state.secret, ['session', operation.sessionId || 'workspace-session', operation.agentId || 'credential-agent', operation.harness]);
}

function getSession(state: GuardState, operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>, now: number): SessionState {
  const key = sessionKey(state, operation);
  const existing = state.sessions[key];
  if (existing) return existing;
  const session: SessionState = { work_epoch: 0, instruction_epoch: 0, updated_at: now, entries: {}, invocations: {} };
  state.sessions[key] = session;
  return session;
}

function operationKind(operation: LoopGuardOperation): LoopKind {
  if (!operation.readOnly) return 'mutation';
  const tool = normalizeHookToolName(operation.toolName);
  const command = hookToolCommand({ tool_name: operation.toolName, tool_input: operation.toolInput }).toLowerCase();
  // Claude Code's Monitor is a watch by definition and is re-armed when it expires: a repeat is
  // refused only after it came back unchanged twice, never on the first re-arm.
  if (tool === 'monitor'
    || /(?:^|[_:.-])(?:status|poll|wait|watch|health)(?:$|[_:.-])/.test(tool)
    || /\b(?:status|poll|health|wait|watch)\b/.test(command)) return 'poll';
  if (/(?:^|[_:.-])(?:test|check|audit|verify|lint|typecheck)(?:$|[_:.-])/.test(tool)
    || /\b(?:test|check|audit|verify|lint|typecheck)\b/.test(command)) return 'verification';
  return 'read';
}

function operationIdentity(state: GuardState, session: SessionState, operation: LoopGuardOperation): string {
  return keyedHash(state.secret, [
    'operation',
    operation.harness,
    operation.agentId || 'credential-agent',
    normalizeHookToolName(operation.toolName) || 'tool',
    canonical(operation.toolInput ?? null),
    session.work_epoch,
    session.instruction_epoch,
  ]);
}

/**
 * The one resolver for consult and record. `fp` is the call's own key, `cut` the 3.9.110 key, `bk` the key of its cut
 * family (master's view of every call with the same cut text); null when the switch is off.
 */
function resolveLoopEntry(state: GuardState, session: SessionState, operation: LoopGuardOperation, mapped?: string): Fingerprint & { bk: string | null } {
  if (!LOOP_GUARD_SPLIT) { const fp = mapped ?? operationIdentity(state, session, operation); return { fp, cut: fp, split: false, bk: null }; }
  // record, with the key consult mapped to the invocation: a split call also mapped its family
  if (mapped) return { fp: mapped, cut: mapped, split: false, bk: session.invocations[keyedHash(state.secret, ['invocation-backstop', operation.invocationId])] ?? keyedHash(state.secret, ['loop-backstop', mapped]) };
  const found = loopFingerprint(state.secret, [
    'operation',
    operation.harness,
    operation.agentId || 'credential-agent',
    normalizeHookToolName(operation.toolName) || 'tool',
    operation.toolInput ?? null,
    session.work_epoch,
    session.instruction_epoch,
  ]);
  return { ...found, bk: keyedHash(state.secret, ['loop-backstop', found.cut]) };
}

// master's rule (3.9.110): a repeat with an outcome and an unchanged count at the threshold is not run again
const loopStops = (entry?: LoopEntry): boolean => !!entry?.outcome && entry.unchanged_count >= (entry.kind === 'poll' || entry.outcome === 'failure' ? 2 : 1);

/** Count one more attempt on an entry, or create it; a new entry continues from `seed` (a call whose cut family already ran). */
function touchLoopEntry(state: GuardState, session: SessionState, key: string, kind: LoopKind, now: number, seed?: LoopEntry): LoopEntry {
  const existing = session.entries[key];
  if (existing) { existing.attempts += 1; existing.updated_at = now; return existing; }
  return (session.entries[key] = {
    fingerprint: key,
    kind,
    outcome: seed?.outcome ?? null,
    result_hash: seed?.result_hash ?? null,
    unchanged_count: seed?.unchanged_count ?? 0,
    attempts: (seed?.attempts ?? 0) + 1,
    updated_at: now,
    receipt: `lgr_${keyedHash(state.secret, ['receipt', key]).slice(0, 24)}`,
  });
}

const SAFE_TOOL_LABEL = /^[A-Za-z0-9_.:-]{1,64}$/;

/** The tool name only, never its input. Anything that is not a plain name reads as "call". */
function toolLabel(toolName: unknown): string {
  return typeof toolName === 'string' && SAFE_TOOL_LABEL.test(toolName) ? `${toolName} call` : 'call';
}

function denial(entry: LoopEntry, toolName: unknown): string {
  const call = toolLabel(toolName);
  return entry.outcome === 'success'
    ? `Marrow loop guard: you already ran this exact ${call} in this session and nothing has changed since, so it was not run again. Use the earlier result. If an edit just failed, re-read only the lines you need (Read with offset and limit). Receipt: ${entry.receipt}.`
    : `Marrow loop guard: this exact ${call} already failed in this session and nothing has changed since, so it was not run again. Change something before you try again. Receipt: ${entry.receipt}.`;
}

export function consultSessionLoopGuard(operation: LoopGuardOperation, options: { home?: string; now?: number } = {}): LoopGuardDecision {
  return withStateLock(options.home, () => {
    const now = options.now ?? Date.now();
    const loaded = readState(options.home);
    const session = getSession(loaded.state, operation, now);
    const id = resolveLoopEntry(loaded.state, session, operation);
    const kind = operationKind(operation);
    const existing = session.entries[id.fp];
    const family = id.bk ? session.entries[id.bk] : undefined;
    // Every deny needs master's view of the cut family too (never stricter than master), or the backstop count.
    const hit = loopStops(existing) && (!family || loopStops(family)) ? existing
      : family?.outcome && family.unchanged_count >= BACKSTOP_COUNT ? family : undefined;
    if (hit) return { allow: false, receipt: hit.receipt, reason: denial(hit, operation.toolName), fingerprint: id.fp };
    // A split call continues from its family (or from 3.9.110's entry at the cut key): one extra run for a call that straddles the upgrade.
    const entry = touchLoopEntry(loaded.state, session, id.fp, kind, now, id.split ? family ?? session.entries[id.cut] : undefined);
    if (id.bk && (family || id.split)) touchLoopEntry(loaded.state, session, id.bk, kind, now, session.entries[id.cut]);
    session.updated_at = now;
    if (operation.invocationId) {
      session.invocations[keyedHash(loaded.state.secret, ['invocation', operation.invocationId])] = id.fp;
      if (id.split && id.bk) session.invocations[keyedHash(loaded.state.secret, ['invocation-backstop', operation.invocationId])] = id.bk;
    }
    writeState(loaded.state, loaded.target, loaded.directory, sessionKey(loaded.state, operation));
    return { allow: true, receipt: entry.receipt, fingerprint: id.fp };
  });
}

export function recordSessionLoopOutcome(
  operation: LoopGuardOperation,
  success: boolean,
  result: unknown,
  options: { home?: string; now?: number } = {},
): void {
  withStateLock(options.home, () => {
    const now = options.now ?? Date.now();
    const loaded = readState(options.home);
    const session = getSession(loaded.state, operation, now);
    const invocationKey = operation.invocationId
      ? keyedHash(loaded.state.secret, ['invocation', operation.invocationId])
      : null;
    const id = resolveLoopEntry(loaded.state, session, operation, invocationKey ? session.invocations[invocationKey] : undefined);
    const entry = session.entries[id.fp];
    if (!entry) return;
    const outcome: LoopOutcome = success ? 'success' : 'failure';
    const resultFp = LOOP_GUARD_SPLIT ? loopFingerprint(loaded.state.secret, ['result', result ?? null]) : undefined;
    const resultHash = resultFp?.fp ?? keyedHash(loaded.state.secret, ['result', canonical(result ?? null)]);
    const cutHash = resultFp?.cut ?? resultHash;
    // An entry 3.9.110 recorded holds the cut hash: it still counts as unchanged once, so a poll count is never reset by the upgrade.
    entry.unchanged_count = entry.outcome === outcome && (entry.result_hash === resultHash || entry.result_hash === cutHash)
      ? entry.unchanged_count + 1
      : 1;
    const family = id.bk ? session.entries[id.bk] : undefined;
    if (family) {
      family.unchanged_count = family.outcome === outcome && family.result_hash === cutHash ? family.unchanged_count + 1 : 1;
      family.outcome = outcome;
      family.result_hash = cutHash;
      family.updated_at = now;
    }
    entry.outcome = outcome;
    entry.result_hash = resultHash;
    entry.updated_at = now;
    session.updated_at = now;
    if (!operation.readOnly && success) {
      session.work_epoch += 1;
      session.entries = {};
      session.invocations = {};
    }
    writeState(loaded.state, loaded.target, loaded.directory, sessionKey(loaded.state, operation));
  });
}

export function advanceSessionInstructionEpoch(
  operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>,
  options: { home?: string; now?: number } = {},
): void {
  withStateLock(options.home, () => {
    const now = options.now ?? Date.now();
    const loaded = readState(options.home);
    const session = getSession(loaded.state, operation, now);
    session.instruction_epoch += 1;
    session.entries = {};
    session.invocations = {};
    session.updated_at = now;
    writeState(loaded.state, loaded.target, loaded.directory, sessionKey(loaded.state, operation));
  });
}

export function clearSessionLoopGuard(
  operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>,
  options: { home?: string } = {},
): void {
  withStateLock(options.home, () => {
    const loaded = readState(options.home);
    delete loaded.state.sessions[sessionKey(loaded.state, operation)];
    writeState(loaded.state, loaded.target, loaded.directory, null);
  });
}

export function sessionLoopGuardPath(home = homedir()): string {
  return paths(home).target;
}

export function sessionLoopGuardEnabled(autoHook: unknown, localControlEnabled: boolean): boolean {
  return autoHook !== 'false' && localControlEnabled;
}

export function runSessionLoopGuardSelfTest(): {
  pass: true;
  isolated: true;
  live_hook_observed: false;
  repeat_denied: true;
  mutation_reset: true;
  owner_disabled_bypass: true;
} {
  const root = mkdtempSync(join(tmpdir(), 'marrow-loop-guard-self-test-'));
  const operation: LoopGuardOperation = {
    sessionId: 'self-test-session',
    agentId: 'self-test-agent',
    harness: 'self-test',
    toolName: 'Bash',
    toolInput: { command: 'npm test' },
    readOnly: true,
  };
  try {
    const first = consultSessionLoopGuard(operation, { home: root });
    recordSessionLoopOutcome(operation, true, { status: 'passed' }, { home: root });
    const repeat = consultSessionLoopGuard(operation, { home: root });
    if (!first.allow || repeat.allow) throw new Error('repeat denial was not enforced');
    const mutation: LoopGuardOperation = {
      ...operation,
      toolName: 'Edit',
      toolInput: { patch_hash: 'self-test' },
      readOnly: false,
    };
    if (!consultSessionLoopGuard(mutation, { home: root }).allow) throw new Error('mutation was unexpectedly denied');
    recordSessionLoopOutcome(mutation, true, { changed: true }, { home: root });
    if (!consultSessionLoopGuard(operation, { home: root }).allow) throw new Error('mutation did not advance the work epoch');
    if (sessionLoopGuardEnabled('true', false)) throw new Error('owner-disabled loop guard did not bypass');
    return {
      pass: true,
      isolated: true,
      live_hook_observed: false,
      repeat_denied: true,
      mutation_reset: true,
      owner_disabled_bypass: true,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
