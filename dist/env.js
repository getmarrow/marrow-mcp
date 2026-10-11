"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.nonDefaultBaseUrlHost = nonDefaultBaseUrlHost;
exports.resolveMarrowEnv = resolveMarrowEnv;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const DEFAULT_BASE_URL = 'https://api.getmarrow.ai';
const ALLOWED_ENV_KEYS = new Set([
    'MARROW_API_KEY',
    'MARROW_KEY',
    'MARROW_BASE_URL',
    'MARROW_FLEET_AGENT_ID',
    'MARROW_AGENT_ID',
    'MARROW_SESSION_ID',
]);
const MAX_ENV_FILE_BYTES = 1024 * 1024;
const REPO_KEY_FIX = 'run npx @getmarrow/install doctor, or move the line to ~/.marrow/env, then chmod 600 ~/.marrow/env';
/** Host (with port) of a non-default base URL, for status output; null for the default. */
function nonDefaultBaseUrlHost(baseUrl) {
    const normalized = normalizeBaseUrl(baseUrl);
    if (normalized === normalizeBaseUrl(DEFAULT_BASE_URL))
        return null;
    try {
        return new URL(baseUrl).host || 'invalid';
    }
    catch {
        return 'invalid';
    }
}
function normalizeBaseUrl(value) {
    try {
        return new URL(String(value || '').trim()).href.replace(/\/+$/, '');
    }
    catch {
        return `invalid:${String(value || '')}`;
    }
}
// File paths come from the working directory; keep notices on one printable line.
function printablePath(filePath) {
    return filePath.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '?');
}
function stripQuotes(value) {
    const trimmed = String(value || '').trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}
// The one trust decision for owner files, shared by the MCP and hook paths. It
// is made about the bytes that were read: the file is opened without following
// a symlink, its type, owner and mode come from fstat on that same descriptor,
// and an lstat of the path taken after the read must name the same inode. The
// file must be the owner's and private; home and ~/.marrow must be the owner's
// real directories, not writable by anyone else. Anything else supplies nothing.
function readOwnerEnvFile(filePath, home) {
    const resolvedHome = path.resolve(home);
    const resolvedFile = path.resolve(filePath);
    const read = readEnvFile(resolvedFile, true);
    if (!read) {
        try {
            fs.lstatSync(resolvedFile);
            return { status: 'rejected' };
        }
        catch {
            return { status: 'absent' };
        }
    }
    try {
        const parent = path.dirname(resolvedFile);
        const homeStat = fs.lstatSync(resolvedHome);
        const parentStat = fs.lstatSync(parent);
        const pathStat = fs.lstatSync(resolvedFile);
        const uid = typeof process.getuid === 'function' ? process.getuid() : null;
        const owned = (stat) => uid === null || stat.uid === uid;
        const safeDir = (stat, dir) => stat.isDirectory() && !stat.isSymbolicLink()
            && fs.realpathSync(dir) === dir && owned(stat) && (stat.mode & 0o022) === 0;
        const trusted = resolvedFile.startsWith(`${resolvedHome}${path.sep}`)
            && safeDir(homeStat, resolvedHome) && safeDir(parentStat, parent)
            && read.stat.isFile() && owned(read.stat) && (read.stat.mode & 0o077) === 0
            && pathStat.isFile() && pathStat.dev === read.stat.dev && pathStat.ino === read.stat.ino;
        return trusted ? { status: 'trusted', values: read.values } : { status: 'rejected' };
    }
    catch {
        return { status: 'rejected' };
    }
}
// Opens without blocking (a planted FIFO cannot hang the server) and reads only
// bounded regular files. noFollow refuses a symlink at open time where supported.
function readEnvFile(filePath, noFollow) {
    const flags = fs.constants.O_RDONLY
        | (fs.constants.O_NONBLOCK || 0)
        | (noFollow ? fs.constants.O_NOFOLLOW || 0 : 0);
    let fd;
    try {
        fd = fs.openSync(filePath, flags);
    }
    catch {
        return null;
    }
    try {
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.size > MAX_ENV_FILE_BYTES)
            return null;
        const buffer = Buffer.alloc(stat.size + 1);
        let length = 0;
        while (length < buffer.length) {
            const read = fs.readSync(fd, buffer, length, buffer.length - length, null);
            if (read <= 0)
                break;
            length += read;
        }
        if (length > stat.size)
            return null;
        return { values: parseEnvText(buffer.subarray(0, length).toString('utf8')), stat };
    }
    catch {
        return null;
    }
    finally {
        fs.closeSync(fd);
    }
}
function parseEnvText(raw) {
    const values = {};
    for (const line of raw.split(/\r?\n/)) {
        const match = line.match(/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
        if (!match)
            continue;
        if (!ALLOWED_ENV_KEYS.has(match[1]))
            continue;
        let value = match[2] || '';
        const hashIndex = value.search(/\s+#/);
        if (hashIndex >= 0)
            value = value.slice(0, hashIndex);
        values[match[1]] = stripQuotes(value);
    }
    return values;
}
function ownerEnvFiles(home) {
    return [
        path.join(home, '.marrow', 'env.local'),
        path.join(home, '.marrow', 'env'),
    ];
}
function repoEnvFiles(cwd, ownerFiles) {
    const files = [];
    let dir = path.resolve(cwd || process.cwd());
    for (let depth = 0; depth < 8; depth += 1) {
        files.push(path.join(dir, '.marrow', 'env.local'));
        files.push(path.join(dir, '.marrow', 'env'));
        files.push(path.join(dir, '.env.local'));
        files.push(path.join(dir, '.env'));
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return [...new Set(files)].filter((file) => !ownerFiles.includes(file));
}
function pickKey(env) {
    if (env.MARROW_API_KEY)
        return { key: env.MARROW_API_KEY, source: 'MARROW_API_KEY' };
    if (env.MARROW_KEY)
        return { key: env.MARROW_KEY, source: 'MARROW_KEY' };
    return { key: '', source: null };
}
function matchingFleetIdentity(env, agentId) {
    const want = String(agentId || '').trim();
    if (!want)
        return null;
    for (const [name, boundAgent] of Object.entries(env)) {
        const match = /^MARROW_AGENT_ID_([A-Z0-9]+)$/.exec(name);
        if (!match || String(boundAgent || '').trim() !== want)
            continue;
        const keyName = `MARROW_KEY_${match[1]}`;
        const key = String(env[keyName] || '').trim();
        if (!key)
            continue;
        return { key, agentId: want, source: keyName };
    }
    return null;
}
function resolveMarrowEnv(options = {}) {
    const env = options.env || process.env;
    const cwd = options.cwd || process.cwd();
    const home = options.home || env.HOME || env.USERPROFILE || os.homedir();
    const requestedAgentId = env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID;
    const matchedIdentity = matchingFleetIdentity(env, requestedAgentId);
    const direct = pickKey(env);
    if (direct.key && matchedIdentity && matchedIdentity.key !== direct.key) {
        return {
            apiKey: matchedIdentity.key,
            baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
            agentId: matchedIdentity.agentId,
            sessionId: env.MARROW_SESSION_ID,
            source: matchedIdentity.source,
            missing: false,
            exactFix: 'Marrow key is matched to the configured agent identity from the process environment.',
        };
    }
    if (direct.key) {
        return {
            apiKey: direct.key,
            baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
            agentId: requestedAgentId,
            sessionId: env.MARROW_SESSION_ID,
            source: direct.source,
            missing: false,
            exactFix: 'Marrow key is loaded from the process environment.',
        };
    }
    // Owner files, in the same order and with the same check on the MCP and hook
    // paths. A file that fails the check supplies nothing, key included.
    const ownerFiles = ownerEnvFiles(home);
    let ignored = null;
    for (const filePath of ownerFiles) {
        const read = readOwnerEnvFile(filePath, home);
        if (read.status === 'rejected') {
            if (!ignored)
                ignored = ownerFileNotice(filePath);
            continue;
        }
        if (read.status !== 'trusted')
            continue;
        const found = pickKey(read.values);
        if (found.key)
            return fromFile(filePath, found, read.values, env);
    }
    if (options.trustedOnly === true)
        return missingKey(env, ignored);
    // Repository-level files (found by walking up from cwd) never supply a key or
    // any other Marrow setting, whatever their owner or mode: a umask-077 clone or a
    // mode-preserving archive yields a private file the owner never wrote. They are
    // read (bounded, non-blocking) only to tell the owner a key there was skipped.
    for (const filePath of repoEnvFiles(cwd, ownerFiles)) {
        try {
            fs.lstatSync(filePath);
        }
        catch {
            continue;
        }
        const peek = readEnvFile(filePath, false);
        if (pickKey(peek?.values || {}).key && !ignored)
            ignored = repoKeyNotice(filePath);
    }
    return missingKey(env, ignored);
}
function repoKeyNotice(filePath) {
    return `Marrow key in ${printablePath(filePath)} ignored: keys are read only from ~/.marrow/env or your environment. Fix: ${REPO_KEY_FIX}.`;
}
function ownerFileNotice(filePath) {
    const file = printablePath(filePath);
    return `Ignored the Marrow key in ${file}: the file is not owner-only (a symlink, readable or writable by others, owned by another user, or in a directory others can write). Fix: chmod 600 ${file} && chmod 700 ${printablePath(path.dirname(filePath))}, replacing a symlink with the file itself.`;
}
function fromFile(filePath, found, parsed, env) {
    return {
        apiKey: found.key,
        baseUrl: parsed.MARROW_BASE_URL || env.MARROW_BASE_URL || DEFAULT_BASE_URL,
        agentId: parsed.MARROW_FLEET_AGENT_ID || parsed.MARROW_AGENT_ID || env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
        sessionId: parsed.MARROW_SESSION_ID || env.MARROW_SESSION_ID,
        source: `${filePath}:${found.source}`,
        missing: false,
        exactFix: `Marrow key was found in ${printablePath(filePath)}. Keep this file private and run npx @getmarrow/install doctor to verify.`,
    };
}
function missingKey(env, ignored) {
    return {
        apiKey: '',
        baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
        agentId: env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
        sessionId: env.MARROW_SESSION_ID,
        source: null,
        missing: true,
        exactFix: 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.'
            + (ignored ? `\n${ignored}` : ''),
    };
}
//# sourceMappingURL=env.js.map