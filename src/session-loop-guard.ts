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
import { hookToolCommand, normalizeHookToolName } from './hook-tool-policy';

const STATE_VERSION = 1;
const STATE_DIRECTORY = 'session-loop-guard';
const STATE_FILENAME = 'state.json';
const STATE_MAX_BYTES = 256 * 1024;
const STATE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 64;
const MAX_ENTRIES_PER_SESSION = 256;

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
  return current == null || stat.uid === current;
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

function paths(home = homedir()): { marrow: string; directory: string; target: string } {
  const marrow = join(home, '.marrow');
  const directory = join(marrow, STATE_DIRECTORY);
  return { marrow, directory, target: join(directory, STATE_FILENAME) };
}

function ensureDirectories(home = homedir()): ReturnType<typeof paths> {
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
      const stat = lstatSync(lock);
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

function writeState(state: GuardState, target: string, directory: string): void {
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
  if (/(?:^|[_:.-])(?:status|poll|wait|watch|health)(?:$|[_:.-])/.test(tool)
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

function denial(entry: LoopEntry): string {
  const result = entry.outcome === 'success' ? 'passed' : 'failed';
  return `Marrow local loop guard: this operation already ${result} with an unchanged result. Reuse the recorded result instead of repeating it. Receipt: ${entry.receipt}.`;
}

export function consultSessionLoopGuard(operation: LoopGuardOperation, options: { home?: string; now?: number } = {}): LoopGuardDecision {
  return withStateLock(options.home, () => {
    const now = options.now ?? Date.now();
    const loaded = readState(options.home);
    const session = getSession(loaded.state, operation, now);
    const fingerprint = operationIdentity(loaded.state, session, operation);
    const kind = operationKind(operation);
    const existing = session.entries[fingerprint];
    if (existing) {
      const threshold = existing.kind === 'poll' || existing.outcome === 'failure' ? 2 : 1;
      if (existing.outcome && existing.unchanged_count >= threshold) {
        return { allow: false, receipt: existing.receipt, reason: denial(existing), fingerprint };
      }
      existing.attempts += 1;
      existing.updated_at = now;
    } else {
      const receipt = `lgr_${keyedHash(loaded.state.secret, ['receipt', fingerprint]).slice(0, 24)}`;
      session.entries[fingerprint] = {
        fingerprint,
        kind,
        outcome: null,
        result_hash: null,
        unchanged_count: 0,
        attempts: 1,
        updated_at: now,
        receipt,
      };
    }
    session.updated_at = now;
    if (operation.invocationId) {
      session.invocations[keyedHash(loaded.state.secret, ['invocation', operation.invocationId])] = fingerprint;
    }
    writeState(loaded.state, loaded.target, loaded.directory);
    return { allow: true, receipt: session.entries[fingerprint].receipt, fingerprint };
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
    const fingerprint = invocationKey && session.invocations[invocationKey]
      ? session.invocations[invocationKey]
      : operationIdentity(loaded.state, session, operation);
    const entry = session.entries[fingerprint];
    if (!entry) return;
    const outcome: LoopOutcome = success ? 'success' : 'failure';
    const resultHash = keyedHash(loaded.state.secret, ['result', canonical(result ?? null)]);
    entry.unchanged_count = entry.outcome === outcome && entry.result_hash === resultHash
      ? entry.unchanged_count + 1
      : 1;
    entry.outcome = outcome;
    entry.result_hash = resultHash;
    entry.updated_at = now;
    session.updated_at = now;
    if (!operation.readOnly && success) {
      session.work_epoch += 1;
      session.entries = {};
      session.invocations = {};
    }
    writeState(loaded.state, loaded.target, loaded.directory);
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
    writeState(loaded.state, loaded.target, loaded.directory);
  });
}

export function clearSessionLoopGuard(
  operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>,
  options: { home?: string } = {},
): void {
  withStateLock(options.home, () => {
    const loaded = readState(options.home);
    delete loaded.state.sessions[sessionKey(loaded.state, operation)];
    writeState(loaded.state, loaded.target, loaded.directory);
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
