"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnsafeLoopGuardStateError = void 0;
exports.consultSessionLoopGuard = consultSessionLoopGuard;
exports.recordSessionLoopOutcome = recordSessionLoopOutcome;
exports.advanceSessionInstructionEpoch = advanceSessionInstructionEpoch;
exports.clearSessionLoopGuard = clearSessionLoopGuard;
exports.sessionLoopGuardPath = sessionLoopGuardPath;
exports.sessionLoopGuardEnabled = sessionLoopGuardEnabled;
exports.runSessionLoopGuardSelfTest = runSessionLoopGuardSelfTest;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const hook_tool_policy_1 = require("./hook-tool-policy");
const STATE_VERSION = 1;
const STATE_DIRECTORY = 'session-loop-guard';
const STATE_FILENAME = 'state.json';
const STATE_MAX_BYTES = 256 * 1024;
const STATE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 64;
const MAX_ENTRIES_PER_SESSION = 256;
class UnsafeLoopGuardStateError extends Error {
    constructor() {
        super('Local Marrow session loop-guard state is unsafe or invalid. Repair ~/.marrow/session-loop-guard before retrying.');
        this.name = 'UnsafeLoopGuardStateError';
    }
}
exports.UnsafeLoopGuardStateError = UnsafeLoopGuardStateError;
function unsafe() { throw new UnsafeLoopGuardStateError(); }
function uid() {
    return typeof process.getuid === 'function' ? process.getuid() : null;
}
function owned(stat) {
    const current = uid();
    return current == null || stat.uid === current;
}
function exactPrivate(stat, mode) {
    return owned(stat) && !stat.isSymbolicLink() && (stat.mode & 0o777) === mode;
}
function canonical(value, depth = 0) {
    if (depth > 8)
        return '[depth]';
    if (value === null || typeof value === 'boolean')
        return value;
    if (typeof value === 'number')
        return Number.isFinite(value) ? value : String(value);
    if (typeof value === 'string')
        return value.slice(0, 16_384);
    if (Array.isArray(value))
        return value.slice(0, 128).map((item) => canonical(item, depth + 1));
    if (value && typeof value === 'object') {
        const source = value;
        return Object.fromEntries(Object.keys(source).sort().slice(0, 128).map((key) => [key.slice(0, 128), canonical(source[key], depth + 1)]));
    }
    return String(value).slice(0, 256);
}
function keyedHash(secret, value) {
    return (0, node_crypto_1.createHmac)('sha256', Buffer.from(secret, 'base64url'))
        .update(JSON.stringify(canonical(value)))
        .digest('hex');
}
function paths(home = (0, node_os_1.homedir)()) {
    const marrow = (0, node_path_1.join)(home, '.marrow');
    const directory = (0, node_path_1.join)(marrow, STATE_DIRECTORY);
    return { marrow, directory, target: (0, node_path_1.join)(directory, STATE_FILENAME) };
}
function ensureDirectories(home = (0, node_os_1.homedir)()) {
    const result = paths(home);
    if (!(0, node_fs_1.existsSync)(result.marrow))
        (0, node_fs_1.mkdirSync)(result.marrow, { mode: 0o700 });
    const marrowStat = (0, node_fs_1.lstatSync)(result.marrow);
    if (!marrowStat.isDirectory() || marrowStat.isSymbolicLink() || !owned(marrowStat) || (marrowStat.mode & 0o022) !== 0)
        unsafe();
    if (!(0, node_fs_1.existsSync)(result.directory))
        (0, node_fs_1.mkdirSync)(result.directory, { mode: 0o700 });
    const directoryStat = (0, node_fs_1.lstatSync)(result.directory);
    if (!directoryStat.isDirectory() || !exactPrivate(directoryStat, 0o700))
        unsafe();
    return result;
}
function withStateLock(home, callback) {
    const { directory } = ensureDirectories(home);
    const lock = (0, node_path_1.join)(directory, '.state.lock');
    let fd = -1;
    for (let attempt = 0; attempt < 40; attempt += 1) {
        try {
            fd = (0, node_fs_1.openSync)(lock, node_fs_1.constants.O_WRONLY | node_fs_1.constants.O_CREAT | node_fs_1.constants.O_EXCL | (node_fs_1.constants.O_NOFOLLOW || 0), 0o600);
            const opened = (0, node_fs_1.fstatSync)(fd);
            if (!opened.isFile() || !exactPrivate(opened, 0o600))
                return unsafe();
            break;
        }
        catch (error) {
            if (error.code !== 'EEXIST')
                return unsafe();
            const stat = (0, node_fs_1.lstatSync)(lock);
            if (!stat.isFile() || !exactPrivate(stat, 0o600))
                return unsafe();
            if (Date.now() - stat.mtimeMs > 30_000) {
                (0, node_fs_1.unlinkSync)(lock);
                continue;
            }
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
        }
    }
    if (fd < 0)
        return unsafe();
    try {
        return callback();
    }
    finally {
        (0, node_fs_1.closeSync)(fd);
        try {
            (0, node_fs_1.unlinkSync)(lock);
        }
        catch { /* a stopped process leaves a bounded stale lock */ }
    }
}
function emptyState() {
    return { version: STATE_VERSION, secret: (0, node_crypto_1.randomBytes)(32).toString('base64url'), sessions: {} };
}
function validEntry(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const entry = value;
    return /^[a-f0-9]{64}$/.test(entry.fingerprint)
        && ['poll', 'verification', 'read', 'mutation'].includes(entry.kind)
        && (entry.outcome === null || entry.outcome === 'success' || entry.outcome === 'failure')
        && (entry.result_hash === null || /^[a-f0-9]{64}$/.test(entry.result_hash))
        && Number.isSafeInteger(entry.unchanged_count) && entry.unchanged_count >= 0 && entry.unchanged_count <= 1_000_000
        && Number.isSafeInteger(entry.attempts) && entry.attempts >= 0 && entry.attempts <= 1_000_000
        && Number.isSafeInteger(entry.updated_at) && entry.updated_at > 0
        && /^lgr_[a-f0-9]{24}$/.test(entry.receipt);
}
function validateState(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return unsafe();
    const state = value;
    if (state.version !== STATE_VERSION || !/^[A-Za-z0-9_-]{43}$/.test(state.secret) || !state.sessions || typeof state.sessions !== 'object' || Array.isArray(state.sessions))
        unsafe();
    const sessions = Object.entries(state.sessions);
    if (sessions.length > MAX_SESSIONS || sessions.some(([key]) => !/^[a-f0-9]{64}$/.test(key)))
        unsafe();
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
            || Object.entries(session.entries).some(([key, entry]) => !/^[a-f0-9]{64}$/.test(key) || !validEntry(entry)))
            unsafe();
    }
    return state;
}
function readState(home = (0, node_os_1.homedir)()) {
    const { target, directory } = ensureDirectories(home);
    if (!(0, node_fs_1.existsSync)(target))
        return { state: emptyState(), target, directory };
    const stat = (0, node_fs_1.lstatSync)(target);
    if (!stat.isFile() || !exactPrivate(stat, 0o600) || stat.size < 2 || stat.size > STATE_MAX_BYTES)
        return unsafe();
    let fd = -1;
    try {
        fd = (0, node_fs_1.openSync)(target, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NOFOLLOW || 0));
        const opened = (0, node_fs_1.fstatSync)(fd);
        if (!opened.isFile() || opened.ino !== stat.ino || !exactPrivate(opened, 0o600))
            return unsafe();
        const raw = (0, node_fs_1.readFileSync)(fd, 'utf8');
        if (Buffer.byteLength(raw) > STATE_MAX_BYTES)
            return unsafe();
        return { state: validateState(JSON.parse(raw)), target, directory };
    }
    catch (error) {
        if (error instanceof UnsafeLoopGuardStateError)
            throw error;
        return unsafe();
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
    }
}
function prune(state, now) {
    for (const [sessionKey, session] of Object.entries(state.sessions)) {
        if (now - session.updated_at > STATE_TTL_MS)
            delete state.sessions[sessionKey];
        else
            for (const [key, entry] of Object.entries(session.entries)) {
                if (now - entry.updated_at > STATE_TTL_MS)
                    delete session.entries[key];
            }
    }
    const sessions = Object.entries(state.sessions).sort((a, b) => b[1].updated_at - a[1].updated_at);
    for (const [key] of sessions.slice(MAX_SESSIONS))
        delete state.sessions[key];
    for (const session of Object.values(state.sessions)) {
        const entries = Object.entries(session.entries).sort((a, b) => b[1].updated_at - a[1].updated_at);
        for (const [key] of entries.slice(MAX_ENTRIES_PER_SESSION))
            delete session.entries[key];
        const liveFingerprints = new Set(Object.keys(session.entries));
        for (const [key, fingerprint] of Object.entries(session.invocations)) {
            if (!liveFingerprints.has(fingerprint))
                delete session.invocations[key];
        }
        for (const key of Object.keys(session.invocations).slice(0, Math.max(0, Object.keys(session.invocations).length - MAX_ENTRIES_PER_SESSION))) {
            delete session.invocations[key];
        }
    }
}
function writeState(state, target, directory) {
    prune(state, Date.now());
    const raw = `${JSON.stringify(state)}\n`;
    if (Buffer.byteLength(raw) > STATE_MAX_BYTES)
        unsafe();
    const temporary = (0, node_path_1.join)(directory, `.state-${process.pid}-${(0, node_crypto_1.randomBytes)(8).toString('hex')}.tmp`);
    let fd = -1;
    try {
        fd = (0, node_fs_1.openSync)(temporary, node_fs_1.constants.O_WRONLY | node_fs_1.constants.O_CREAT | node_fs_1.constants.O_EXCL | (node_fs_1.constants.O_NOFOLLOW || 0), 0o600);
        (0, node_fs_1.writeFileSync)(fd, raw, 'utf8');
        (0, node_fs_1.closeSync)(fd);
        fd = -1;
        (0, node_fs_1.renameSync)(temporary, target);
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
        try {
            if ((0, node_fs_1.existsSync)(temporary))
                (0, node_fs_1.unlinkSync)(temporary);
        }
        catch { /* best effort cleanup */ }
    }
}
function sessionKey(state, operation) {
    return keyedHash(state.secret, ['session', operation.sessionId || 'workspace-session', operation.agentId || 'credential-agent', operation.harness]);
}
function getSession(state, operation, now) {
    const key = sessionKey(state, operation);
    const existing = state.sessions[key];
    if (existing)
        return existing;
    const session = { work_epoch: 0, instruction_epoch: 0, updated_at: now, entries: {}, invocations: {} };
    state.sessions[key] = session;
    return session;
}
function operationKind(operation) {
    if (!operation.readOnly)
        return 'mutation';
    const tool = (0, hook_tool_policy_1.normalizeHookToolName)(operation.toolName);
    const command = (0, hook_tool_policy_1.hookToolCommand)({ tool_name: operation.toolName, tool_input: operation.toolInput }).toLowerCase();
    if (/(?:^|[_:.-])(?:status|poll|wait|watch|health)(?:$|[_:.-])/.test(tool)
        || /\b(?:status|poll|health|wait|watch)\b/.test(command))
        return 'poll';
    if (/(?:^|[_:.-])(?:test|check|audit|verify|lint|typecheck)(?:$|[_:.-])/.test(tool)
        || /\b(?:test|check|audit|verify|lint|typecheck)\b/.test(command))
        return 'verification';
    return 'read';
}
function operationIdentity(state, session, operation) {
    return keyedHash(state.secret, [
        'operation',
        operation.harness,
        operation.agentId || 'credential-agent',
        (0, hook_tool_policy_1.normalizeHookToolName)(operation.toolName) || 'tool',
        canonical(operation.toolInput ?? null),
        session.work_epoch,
        session.instruction_epoch,
    ]);
}
function denial(entry) {
    const result = entry.outcome === 'success' ? 'passed' : 'failed';
    return `Marrow local loop guard: this operation already ${result} with an unchanged result. Reuse the recorded result instead of repeating it. Receipt: ${entry.receipt}.`;
}
function consultSessionLoopGuard(operation, options = {}) {
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
        }
        else {
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
function recordSessionLoopOutcome(operation, success, result, options = {}) {
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
        if (!entry)
            return;
        const outcome = success ? 'success' : 'failure';
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
function advanceSessionInstructionEpoch(operation, options = {}) {
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
function clearSessionLoopGuard(operation, options = {}) {
    withStateLock(options.home, () => {
        const loaded = readState(options.home);
        delete loaded.state.sessions[sessionKey(loaded.state, operation)];
        writeState(loaded.state, loaded.target, loaded.directory);
    });
}
function sessionLoopGuardPath(home = (0, node_os_1.homedir)()) {
    return paths(home).target;
}
function sessionLoopGuardEnabled(autoHook, localControlEnabled) {
    return autoHook !== 'false' && localControlEnabled;
}
function runSessionLoopGuardSelfTest() {
    const root = (0, node_fs_1.mkdtempSync)((0, node_path_1.join)((0, node_os_1.tmpdir)(), 'marrow-loop-guard-self-test-'));
    const operation = {
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
        if (!first.allow || repeat.allow)
            throw new Error('repeat denial was not enforced');
        const mutation = {
            ...operation,
            toolName: 'Edit',
            toolInput: { patch_hash: 'self-test' },
            readOnly: false,
        };
        if (!consultSessionLoopGuard(mutation, { home: root }).allow)
            throw new Error('mutation was unexpectedly denied');
        recordSessionLoopOutcome(mutation, true, { changed: true }, { home: root });
        if (!consultSessionLoopGuard(operation, { home: root }).allow)
            throw new Error('mutation did not advance the work epoch');
        if (sessionLoopGuardEnabled('true', false))
            throw new Error('owner-disabled loop guard did not bypass');
        return {
            pass: true,
            isolated: true,
            live_hook_observed: false,
            repeat_denied: true,
            mutation_reset: true,
            owner_disabled_bypass: true,
        };
    }
    finally {
        (0, node_fs_1.rmSync)(root, { recursive: true, force: true });
    }
}
//# sourceMappingURL=session-loop-guard.js.map