"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.writeGuidanceCache = writeGuidanceCache;
exports.readGuidanceCache = readGuidanceCache;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const MAX_CACHE_AGE_MS = 60 * 60 * 1000;
const MAX_CONTEXT_BYTES = 4_000;
function cachePath(apiKey, baseUrl, agentId, home = (0, os_1.homedir)()) {
    const namespace = (0, crypto_1.createHash)('sha256')
        .update(`${baseUrl}|${apiKey}|${agentId || 'account'}`)
        .digest('hex')
        .slice(0, 24);
    const directory = (0, path_1.join)(home, '.marrow', 'cache');
    if (!(0, fs_1.existsSync)(directory))
        (0, fs_1.mkdirSync)(directory, { recursive: true, mode: 0o700 });
    const stat = (0, fs_1.lstatSync)(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
        throw new Error('Marrow guidance cache directory must be owner-only and cannot be a symlink');
    }
    return (0, path_1.join)(directory, `guidance-${namespace}.json`);
}
function writeGuidanceCache(input) {
    const context = input.context.slice(0, MAX_CONTEXT_BYTES);
    const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
    if ((0, fs_1.existsSync)(path) && (0, fs_1.lstatSync)(path).isSymbolicLink())
        throw new Error('Marrow guidance cache file cannot be a symlink');
    const temporary = `${path}.tmp-${process.pid}`;
    const record = { version: 1, stored_at: new Date().toISOString(), context };
    (0, fs_1.writeFileSync)(temporary, JSON.stringify(record), { encoding: 'utf8', mode: 0o600, flag: 'w' });
    (0, fs_1.chmodSync)(temporary, 0o600);
    (0, fs_1.renameSync)(temporary, path);
}
function readGuidanceCache(input) {
    const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
    if (!(0, fs_1.existsSync)(path))
        return null;
    const stat = (0, fs_1.lstatSync)(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
        return null;
    try {
        const record = JSON.parse((0, fs_1.readFileSync)(path, 'utf8'));
        const storedAt = Date.parse(String(record.stored_at || ''));
        const staleMs = Date.now() - storedAt;
        if (record.version !== 1 || !Number.isFinite(storedAt) || staleMs < 0 || staleMs > MAX_CACHE_AGE_MS)
            return null;
        if (typeof record.context !== 'string' || !record.context || Buffer.byteLength(record.context, 'utf8') > MAX_CONTEXT_BYTES)
            return null;
        return { context: record.context, stale_ms: staleMs };
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=guidance-cache.js.map