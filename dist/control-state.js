"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnsafeControlStateError = exports.CONTROL_BYPASS_ACTION = exports.CONTROL_MAX_BYTES = exports.CONTROL_CHANGED_BY = exports.CONTROL_STATE_FILENAME = exports.CONTROL_STATE_DIRECTORY = exports.CONTROL_STATE_VERSION = void 0;
exports.controlStatePath = controlStatePath;
exports.readLocalControlState = readLocalControlState;
exports.localControlEvidence = localControlEvidence;
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
exports.CONTROL_STATE_VERSION = 1;
exports.CONTROL_STATE_DIRECTORY = '.marrow';
exports.CONTROL_STATE_FILENAME = 'control.json';
exports.CONTROL_CHANGED_BY = 'owner_cli';
exports.CONTROL_MAX_BYTES = 4096;
exports.CONTROL_BYPASS_ACTION = 'protected action bypassed while local control disabled';
class UnsafeControlStateError extends Error {
    constructor() {
        super('Local Marrow control state is unsafe or invalid. Protected actions remain blocked; inspect ~/.marrow/control.json and run npx @getmarrow/install control status.');
        this.name = 'UnsafeControlStateError';
    }
}
exports.UnsafeControlStateError = UnsafeControlStateError;
function controlStatePath(home = (0, node_os_1.homedir)()) {
    return (0, node_path_1.join)(home, exports.CONTROL_STATE_DIRECTORY, exports.CONTROL_STATE_FILENAME);
}
function unsafe() { throw new UnsafeControlStateError(); }
function ownedPrivate(stat, mode) {
    return !stat.isSymbolicLink()
        && stat.uid === (typeof process.getuid === 'function' ? process.getuid() : stat.uid)
        && (stat.mode & 0o777) === mode;
}
function readLocalControlState(options = {}) {
    const home = options.home || (0, node_os_1.homedir)();
    const directory = (0, node_path_1.join)(home, exports.CONTROL_STATE_DIRECTORY);
    const target = controlStatePath(home);
    let directoryStat;
    try {
        directoryStat = (0, node_fs_1.lstatSync)(directory);
    }
    catch (error) {
        if (error.code === 'ENOENT')
            return { enabled: true, state: 'default_enabled', changed_at: null };
        return unsafe();
    }
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink())
        return unsafe();
    let targetStat;
    try {
        targetStat = (0, node_fs_1.lstatSync)(target);
    }
    catch (error) {
        if (error.code === 'ENOENT')
            return { enabled: true, state: 'default_enabled', changed_at: null };
        return unsafe();
    }
    if (!ownedPrivate(directoryStat, 0o700))
        return unsafe();
    if (!targetStat.isFile() || !ownedPrivate(targetStat, 0o600) || targetStat.size < 2 || targetStat.size > exports.CONTROL_MAX_BYTES)
        return unsafe();
    let fd = -1;
    try {
        fd = (0, node_fs_1.openSync)(target, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NOFOLLOW || 0));
        const opened = (0, node_fs_1.fstatSync)(fd);
        if (!opened.isFile() || opened.ino !== targetStat.ino || !ownedPrivate(opened, 0o600))
            return unsafe();
        const raw = (0, node_fs_1.readFileSync)(fd, 'utf8');
        if (Buffer.byteLength(raw) > exports.CONTROL_MAX_BYTES)
            return unsafe();
        const value = JSON.parse(raw);
        const keys = Object.keys(value).sort();
        if (keys.join(',') !== 'change_id,changed_at,changed_by,enabled,version')
            return unsafe();
        const changedAt = typeof value.changed_at === 'string' ? value.changed_at : '';
        const canonicalAt = changedAt && new Date(changedAt).toISOString() === changedAt;
        const valid = value.version === exports.CONTROL_STATE_VERSION
            && typeof value.enabled === 'boolean'
            && value.changed_by === exports.CONTROL_CHANGED_BY
            && canonicalAt
            && typeof value.change_id === 'string'
            && /^ctl_[a-f0-9]{32}$/.test(value.change_id);
        if (!valid)
            return unsafe();
        return { enabled: value.enabled, state: value.enabled ? 'enabled' : 'disabled', changed_at: changedAt, change_id: value.change_id };
    }
    catch (error) {
        if (error instanceof UnsafeControlStateError)
            throw error;
        return unsafe();
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
    }
}
function localControlEvidence(bypassRecordingAvailable) {
    try {
        const control = readLocalControlState();
        return {
            enabled: control.enabled,
            state: control.state,
            changed_at: control.changed_at,
            bypass_recording_available: bypassRecordingAvailable,
            exact_next_action: control.enabled
                ? 'Run npx @getmarrow/install control disable --yes to disable local enforcement.'
                : 'Run npx @getmarrow/install control enable to resume local enforcement; hook processes poll this state without reinstalling.',
        };
    }
    catch {
        return { enabled: false, state: 'error', changed_at: null, bypass_recording_available: false, exact_next_action: 'Inspect and replace unsafe ~/.marrow/control.json, then run npx @getmarrow/install control status; protected actions remain blocked.' };
    }
}
//# sourceMappingURL=control-state.js.map