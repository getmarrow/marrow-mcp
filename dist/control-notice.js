"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONTROL_STATUS_COMMAND = void 0;
exports.unreadableControlSuffix = unreadableControlSuffix;
exports.unreadableControlNotice = unreadableControlNotice;
exports.claimUnreadableControlNotice = claimUnreadableControlNotice;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const control_state_1 = require("./control-state");
exports.CONTROL_STATUS_COMMAND = 'npx @getmarrow/install control status';
const NOTICE_DIRECTORY = 'control-notice';
const MAX_MARKERS = 200;
/** The control file's path as plain text (the file's contents are never read into a message). */
function plainPath(home) {
    let path = '~/.marrow/control.json';
    try {
        path = (0, control_state_1.controlStatePath)(home || (0, node_os_1.homedir)());
    }
    catch { /* no home directory: name the usual place */ }
    return path.replace(/[\u0000-\u001f\u007f]/g, ' ');
}
/** Appended to the pre-action deny text: the fix first, so a host's length limit trims the path before it trims the fix. */
function unreadableControlSuffix(home) {
    return ` Fix: run \`${exports.CONTROL_STATUS_COMMAND}\`. File: ${plainPath(home)}`;
}
/** One plain notice for the person: control stays ON, what to run, which file. */
function unreadableControlNotice(home) {
    return `Marrow cannot read its local control file, so Marrow keeps checking actions as if control were on. Run \`${exports.CONTROL_STATUS_COMMAND}\` to see what is wrong. File: ${plainPath(home)}`;
}
function ownDirectory(stat) {
    return stat.isDirectory() && !stat.isSymbolicLink()
        && stat.uid === (typeof process.getuid === 'function' ? process.getuid() : stat.uid);
}
/**
 * True when this session has not been told yet (and is now marked as told), false when it has.
 * The marker is an empty owner-only file named by a hash of the session key, under ~/.marrow/control-notice.
 * When a marker cannot be stored safely (no ~/.marrow, a link or another owner's directory) the answer is
 * true: a repeated notice is better than a silent one, and nothing is ever written through a link.
 */
function claimUnreadableControlNotice(sessionKey, home) {
    try {
        const marrow = (0, node_path_1.join)(home || (0, node_os_1.homedir)(), control_state_1.CONTROL_STATE_DIRECTORY);
        if (!ownDirectory((0, node_fs_1.lstatSync)(marrow)))
            return true;
        const directory = (0, node_path_1.join)(marrow, NOTICE_DIRECTORY);
        try {
            (0, node_fs_1.mkdirSync)(directory, { mode: 0o700 });
        }
        catch (error) {
            if (error.code !== 'EEXIST')
                throw error;
        }
        if (!ownDirectory((0, node_fs_1.lstatSync)(directory)))
            return true;
        const name = (0, node_crypto_1.createHash)('sha256').update(sessionKey).digest('hex').slice(0, 32);
        (0, node_fs_1.closeSync)((0, node_fs_1.openSync)((0, node_path_1.join)(directory, name), node_fs_1.constants.O_WRONLY | node_fs_1.constants.O_CREAT | node_fs_1.constants.O_EXCL | (node_fs_1.constants.O_NOFOLLOW || 0), 0o600));
        pruneMarkers(directory);
        return true;
    }
    catch (error) {
        return error.code !== 'EEXIST';
    }
}
function pruneMarkers(directory) {
    try {
        const markers = (0, node_fs_1.readdirSync)(directory)
            .map((name) => ({ name, at: (0, node_fs_1.lstatSync)((0, node_path_1.join)(directory, name)).mtimeMs }))
            .sort((a, b) => a.at - b.at);
        for (const marker of markers.slice(0, Math.max(0, markers.length - MAX_MARKERS)))
            (0, node_fs_1.unlinkSync)((0, node_path_1.join)(directory, marker.name));
    }
    catch { /* best effort: a stale marker only means one more notice */ }
}
//# sourceMappingURL=control-notice.js.map