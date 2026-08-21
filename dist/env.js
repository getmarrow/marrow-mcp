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
function stripQuotes(value) {
    const trimmed = String(value || '').trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}
function isPrivateOwnerFile(filePath, home) {
    try {
        const resolvedHome = path.resolve(home);
        const resolvedFile = path.resolve(filePath);
        const parent = path.dirname(resolvedFile);
        const homeStat = fs.lstatSync(resolvedHome);
        const parentStat = fs.lstatSync(parent);
        const fileStat = fs.lstatSync(resolvedFile);
        const uid = typeof process.getuid === 'function' ? process.getuid() : null;
        return resolvedFile.startsWith(`${resolvedHome}${path.sep}`)
            && homeStat.isDirectory() && !homeStat.isSymbolicLink() && fs.realpathSync(resolvedHome) === resolvedHome
            && parentStat.isDirectory() && !parentStat.isSymbolicLink() && fs.realpathSync(parent) === parent
            && fileStat.isFile() && !fileStat.isSymbolicLink()
            && (uid === null || fileStat.uid === uid && parentStat.uid === uid && homeStat.uid === uid)
            && (fileStat.mode & 0o077) === 0
            && (parentStat.mode & 0o022) === 0
            && (homeStat.mode & 0o022) === 0;
    }
    catch {
        return false;
    }
}
function parseEnvFile(filePath, trustedHome) {
    if (!fs.existsSync(filePath))
        return {};
    if (trustedHome && !isPrivateOwnerFile(filePath, trustedHome))
        return {};
    const values = {};
    const raw = fs.readFileSync(filePath, 'utf8');
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
function candidateEnvFiles(cwd, home, trustedOnly) {
    const ownerFiles = [
        path.join(home, '.marrow', 'env.local'),
        path.join(home, '.marrow', 'env'),
    ];
    if (trustedOnly)
        return ownerFiles;
    const files = [...ownerFiles];
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
    return [...new Set(files)];
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
    for (const filePath of candidateEnvFiles(cwd, home, options.trustedOnly === true)) {
        const parsed = parseEnvFile(filePath, options.trustedOnly === true ? home : undefined);
        const found = pickKey(parsed);
        if (!found.key)
            continue;
        return {
            apiKey: found.key,
            baseUrl: parsed.MARROW_BASE_URL || env.MARROW_BASE_URL || DEFAULT_BASE_URL,
            agentId: parsed.MARROW_FLEET_AGENT_ID || parsed.MARROW_AGENT_ID || env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
            sessionId: parsed.MARROW_SESSION_ID || env.MARROW_SESSION_ID,
            source: `${filePath}:${found.source}`,
            missing: false,
            exactFix: `Marrow key was found in ${filePath}. Keep this file private and run npx @getmarrow/install doctor to verify.`,
        };
    }
    return {
        apiKey: '',
        baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
        agentId: env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
        sessionId: env.MARROW_SESSION_ID,
        source: null,
        missing: true,
        exactFix: 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.',
    };
}
//# sourceMappingURL=env.js.map