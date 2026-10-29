"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.claimSessionMarker = claimSessionMarker;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const MARKER_FOLDER = 'session-markers';
/**
 * A once-per-host-session marker: a file named by the kind and a hash of the session id (never the id itself), created owner-only inside
 * `~/.marrow/session-markers` (mode 700). True only for the call that creates it; false for every later call of that session, and false
 * when the private folder cannot be used (a notice is then skipped rather than repeated on every hook call).
 */
function claimSessionMarker(kind, sessionId, home = (0, node_os_1.homedir)()) {
    try {
        if (!/^[a-z0-9-]{1,48}$/.test(kind) || !sessionId)
            return false;
        const marrow = (0, node_path_1.join)(home, '.marrow');
        const folder = (0, node_path_1.join)(marrow, MARKER_FOLDER);
        for (const directory of [marrow, folder]) {
            try {
                (0, node_fs_1.mkdirSync)(directory, { mode: 0o700 });
            }
            catch (error) {
                if (error.code !== 'EEXIST')
                    return false;
            }
            const stat = (0, node_fs_1.lstatSync)(directory);
            const uid = typeof process.getuid === 'function' ? process.getuid() : stat.uid;
            if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o077) !== 0)
                return false;
        }
        const name = `${kind}-${(0, node_crypto_1.createHash)('sha256').update(`${kind}\n${sessionId}`).digest('hex').slice(0, 32)}`;
        const fd = (0, node_fs_1.openSync)((0, node_path_1.join)(folder, name), node_fs_1.constants.O_CREAT | node_fs_1.constants.O_EXCL | node_fs_1.constants.O_WRONLY | (node_fs_1.constants.O_NOFOLLOW || 0), 0o600);
        (0, node_fs_1.closeSync)(fd);
        return true;
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=session-marker.js.map