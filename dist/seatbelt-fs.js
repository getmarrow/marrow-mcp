"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nodeSeatbeltFs = nodeSeatbeltFs;
const node_fs_1 = require("node:fs");
function entryOf(stat) {
    const type = stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other';
    return { type, size: stat.size, uid: stat.uid, gid: stat.gid, mode: stat.mode & 0o7777, dev: stat.dev, ino: stat.ino };
}
function swapCase(name) {
    return name.replace(/[A-Za-z]/g, (ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
}
/**
 * The host filesystem. Case-insensitivity is probed, not assumed from the
 * platform (macOS volumes can be case-sensitive; Linux dirs can casefold): the
 * nearest existing ancestor with a letter in its name is looked up with its
 * case swapped, and only the same inode proves folding. Results are cached per
 * probed directory.
 */
function nodeSeatbeltFs() {
    const probed = new Map();
    const probe = (path) => {
        let dir = path;
        for (;;) {
            const cut = dir.lastIndexOf('/');
            const name = dir.slice(cut + 1);
            if (cut < 0 || dir === '/')
                return false;
            if (/[A-Za-z]/.test(name)) {
                const cached = probed.get(dir);
                if (cached !== undefined)
                    return cached;
                let same = null;
                try {
                    const a = (0, node_fs_1.lstatSync)(dir);
                    try {
                        const b = (0, node_fs_1.lstatSync)(`${dir.slice(0, cut)}/${swapCase(name)}`);
                        same = a.dev === b.dev && a.ino === b.ino;
                    }
                    catch {
                        same = false;
                    }
                }
                catch {
                    same = null;
                }
                if (same !== null) {
                    probed.set(dir, same);
                    return same;
                }
            }
            dir = dir.slice(0, cut) || '/';
        }
    };
    return {
        lstat(path) {
            try {
                return entryOf((0, node_fs_1.lstatSync)(path));
            }
            catch (error) {
                const code = error.code;
                if (code === 'ENOENT' || code === 'ENOTDIR')
                    return null;
                throw error;
            }
        },
        readlink: (path) => (0, node_fs_1.readlinkSync)(path, 'utf8'),
        readFile(path, maxBytes) {
            // Non-blocking open so a planted FIFO cannot hang the hook; no final symlink.
            const fd = (0, node_fs_1.openSync)(path, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NONBLOCK || 0) | (node_fs_1.constants.O_NOFOLLOW || 0));
            try {
                const stat = (0, node_fs_1.fstatSync)(fd);
                if (!stat.isFile() || stat.size > maxBytes)
                    return null;
                const buffer = Buffer.alloc(stat.size + 1);
                let length = 0;
                while (length < buffer.length) {
                    const read = (0, node_fs_1.readSync)(fd, buffer, length, buffer.length - length, null);
                    if (read <= 0)
                        break;
                    length += read;
                }
                if (length > stat.size)
                    return null;
                return buffer.subarray(0, length).toString('utf8');
            }
            finally {
                (0, node_fs_1.closeSync)(fd);
            }
        },
        readdir: (path) => (0, node_fs_1.readdirSync)(path),
        caseInsensitive: (path) => probe(path),
    };
}
//# sourceMappingURL=seatbelt-fs.js.map