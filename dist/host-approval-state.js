"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnsafeHostApprovalStateError = exports.APPROVAL_CODE = exports.HOLD_RECORD_TTL_MS = void 0;
exports.recordHold = recordHold;
exports.findHolds = findHolds;
exports.updateHold = updateHold;
exports.markDialogShown = markDialogShown;
exports.setSessionMarker = setSessionMarker;
exports.sessionMarker = sessionMarker;
exports.hasPendingHolds = hasPendingHolds;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
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
exports.HOLD_RECORD_TTL_MS = 2 * 60 * 60 * 1000;
const MARKER_TTL_MS = 24 * 60 * 60 * 1000;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
exports.APPROVAL_CODE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const HEX32 = /^[a-f0-9]{32}$/;
class UnsafeHostApprovalStateError extends Error {
    constructor() {
        super('Local Marrow host-approval state is unsafe or invalid. Repair ~/.marrow/host-approvals before retrying.');
        this.name = 'UnsafeHostApprovalStateError';
    }
}
exports.UnsafeHostApprovalStateError = UnsafeHostApprovalStateError;
function unsafe() { throw new UnsafeHostApprovalStateError(); }
function owned(stat) {
    const current = typeof process.getuid === 'function' ? process.getuid() : null;
    return current == null || stat.uid === current;
}
function exactPrivate(stat, mode) {
    return owned(stat) && !stat.isSymbolicLink() && (stat.mode & 0o777) === mode;
}
function paths(home = process.env.HOME || (0, node_os_1.homedir)()) {
    const marrow = (0, node_path_1.join)(home, '.marrow');
    const directory = (0, node_path_1.join)(marrow, STATE_DIRECTORY);
    return { marrow, directory, target: (0, node_path_1.join)(directory, STATE_FILENAME) };
}
function ensureDirectories(home) {
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
function withLock(home, callback) {
    const { directory } = ensureDirectories(home);
    const lock = (0, node_path_1.join)(directory, '.state.lock');
    let fd = -1;
    for (let attempt = 0; attempt < 200; attempt += 1) {
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
            let stat;
            try {
                stat = (0, node_fs_1.lstatSync)(lock);
            }
            catch {
                continue;
            }
            if (!stat.isFile() || !exactPrivate(stat, 0o600))
                return unsafe();
            if (Date.now() - stat.mtimeMs > 10_000) {
                try {
                    (0, node_fs_1.unlinkSync)(lock);
                }
                catch { /* another process removed it */ }
                continue;
            }
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
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
    return { version: STATE_VERSION, secret: (0, node_crypto_1.randomBytes)(32).toString('base64url'), holds: {}, interactive: {}, prompt_hook: {} };
}
function isIso(value) {
    return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
}
function validReport(value) {
    if (value === null)
        return true;
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const report = value;
    return (report.verdict === 'approved' || report.verdict === 'declined')
        && typeof report.host === 'string' && report.host.length <= 32
        && typeof report.host_session_id === 'string' && IDENTIFIER.test(report.host_session_id)
        && (report.hook_event === null || (typeof report.hook_event === 'string' && /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/.test(report.hook_event)))
        && (report.pre_action_event_id === null || (typeof report.pre_action_event_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(report.pre_action_event_id)))
        && isIso(report.asked_at) && isIso(report.answered_at)
        && (report.decision_id === undefined || (typeof report.decision_id === 'string' && IDENTIFIER.test(report.decision_id)));
}
function validHold(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const hold = value;
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
        && (hold.code === null || (typeof hold.code === 'string' && exports.APPROVAL_CODE.test(hold.code)))
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
function validMarkers(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const entries = Object.entries(value);
    return entries.length <= MAX_MARKERS && entries.every(([key, marker]) => /^[a-f0-9]{64}$/.test(key)
        && Boolean(marker) && typeof marker === 'object'
        && Number.isSafeInteger(marker.at) && typeof marker.value === 'boolean');
}
function validateState(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return unsafe();
    const state = value;
    if (state.version !== STATE_VERSION || !/^[A-Za-z0-9_-]{43}$/.test(state.secret)
        || !state.holds || typeof state.holds !== 'object' || Array.isArray(state.holds)
        || !validMarkers(state.interactive) || !validMarkers(state.prompt_hook))
        return unsafe();
    const holds = Object.entries(state.holds);
    if (holds.length > MAX_HOLDS || holds.some(([key, hold]) => !validHold(hold) || hold.id !== key))
        return unsafe();
    return state;
}
function readState(home) {
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
        return { state: validateState(JSON.parse(raw)), target, directory };
    }
    catch (error) {
        if (error instanceof UnsafeHostApprovalStateError)
            throw error;
        return unsafe();
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
    }
}
function prune(state, now) {
    for (const [id, hold] of Object.entries(state.holds)) {
        const expiry = hold.expires_at ? Date.parse(hold.expires_at) : NaN;
        const settled = hold.state === 'resolved' && !hold.outbox;
        const pastExpiry = Number.isFinite(expiry) && now > expiry + 10 * 60_000 && !hold.outbox;
        if (now - hold.created_at > exports.HOLD_RECORD_TTL_MS || pastExpiry || (settled && now - hold.updated_at > 10 * 60_000))
            delete state.holds[id];
    }
    const holds = Object.values(state.holds).sort((a, b) => b.updated_at - a.updated_at);
    for (const hold of holds.slice(MAX_HOLDS))
        delete state.holds[hold.id];
    for (const markers of [state.interactive, state.prompt_hook]) {
        for (const [key, marker] of Object.entries(markers))
            if (now - marker.at > MARKER_TTL_MS)
                delete markers[key];
        const ordered = Object.entries(markers).sort((a, b) => b[1].at - a[1].at);
        for (const [key] of ordered.slice(MAX_MARKERS))
            delete markers[key];
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
function keyed(secret, value, length = 64) {
    return (0, node_crypto_1.createHmac)('sha256', Buffer.from(secret, 'base64url')).update(JSON.stringify(value)).digest('hex').slice(0, length);
}
function keyRef(state, scope) {
    return keyed(state.secret, ['key', scope.apiKey, scope.baseUrl.replace(/\/+$/, ''), scope.agentId || null], 32);
}
function freshCode(state, gateReceiptId) {
    const taken = new Set(Object.values(state.holds).map((hold) => hold.code).filter(Boolean));
    for (let round = 0; round < 32; round += 1) {
        const digest = (0, node_crypto_1.createHmac)('sha256', Buffer.from(state.secret, 'base64url')).update(`code:${round}:${gateReceiptId}`).digest();
        let code = '';
        for (let index = 0; index < 6; index += 1)
            code += CODE_ALPHABET[digest[index] % CODE_ALPHABET.length];
        if (!taken.has(code))
            return code;
    }
    return unsafe();
}
/** Records a held action. A previous open hold of the same action and session is replaced. */
function recordHold(scope, input, home) {
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
        const record = {
            ...fields,
            id: `hold_${(0, node_crypto_1.randomBytes)(12).toString('hex')}`,
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
function matches(hold, ref, query) {
    if (hold.key_ref !== ref)
        return false;
    if (query.id && hold.id !== query.id)
        return false;
    if (query.correlation && hold.correlation !== query.correlation)
        return false;
    if (query.toolUseId && hold.tool_use_id && hold.tool_use_id !== query.toolUseId)
        return false;
    if (query.sessionId !== undefined && hold.session_id !== query.sessionId)
        return false;
    if (query.hostSessionId !== undefined && hold.host_session_id !== query.hostSessionId)
        return false;
    if (query.generationId && hold.generation_id && hold.generation_id !== query.generationId)
        return false;
    if (query.mode && hold.mode !== query.mode)
        return false;
    if (query.states && !query.states.includes(hold.state))
        return false;
    if (query.code && hold.code !== query.code)
        return false;
    return true;
}
/** Reads without creating ~/.marrow/host-approvals when nothing was ever held. */
function peekState(home) {
    return (0, node_fs_1.existsSync)(paths(home).target) ? readState(home).state : emptyState();
}
function findHolds(scope, query, home) {
    const state = peekState(home);
    const ref = keyRef(state, scope);
    return Object.values(state.holds)
        .filter((hold) => matches(hold, ref, query))
        .sort((a, b) => a.created_at - b.created_at);
}
/** Applies a change to one hold under the lock; returns the updated hold, or null when it is gone. */
function updateHold(scope, id, change, home) {
    return withLock(home, () => {
        const { state, target, directory } = readState(home);
        const ref = keyRef(state, scope);
        const current = state.holds[id];
        if (!current || current.key_ref !== ref)
            return null;
        const next = change(structuredClone(current));
        if (next === null)
            delete state.holds[id];
        else
            state.holds[id] = { ...next, id: current.id, key_ref: current.key_ref, updated_at: Date.now() };
        writeState(state, target, directory);
        return next === null ? null : state.holds[id];
    });
}
/** Marks the oldest matching open ask whose dialog was not yet seen; returns it, if any. */
function markDialogShown(scope, query, at, home) {
    return withLock(home, () => {
        const { state, target, directory } = readState(home);
        const ref = keyRef(state, scope);
        const candidate = Object.values(state.holds)
            .filter((hold) => matches(hold, ref, { ...query, mode: 'ask', states: ['open'] }) && hold.dialog_at === null)
            .sort((a, b) => a.created_at - b.created_at)[0];
        if (!candidate)
            return null;
        candidate.dialog_at = at;
        candidate.updated_at = Date.now();
        writeState(state, target, directory);
        return candidate;
    });
}
function setSessionMarker(kind, scope, hostSessionId, value, home) {
    withLock(home, () => {
        const { state, target, directory } = readState(home);
        state[kind][keyed(state.secret, [kind, keyRef(state, scope), hostSessionId])] = { at: Date.now(), value };
        writeState(state, target, directory);
    });
}
function sessionMarker(kind, scope, hostSessionId, home) {
    const state = peekState(home);
    const marker = state[kind][keyed(state.secret, [kind, keyRef(state, scope), hostSessionId])];
    return marker ? marker.value : null;
}
/** True when this key has any hold that still needs work (cheap check before network). */
function hasPendingHolds(scope, query = {}, home) {
    try {
        return findHolds(scope, { ...query, states: ['open', 'allowed'] }, home).length > 0
            || findHolds(scope, { ...query, states: ['resolved'] }, home).some((hold) => hold.outbox !== null);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=host-approval-state.js.map