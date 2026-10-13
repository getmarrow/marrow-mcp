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
exports.FLAG_CODES = exports.RETENTION_DAYS = exports.MAX_TOTAL_BYTES = exports.MAX_RECEIPT_BYTES = void 0;
exports.validateReceipt = validateReceipt;
exports.writeSeatbeltReceipt = writeSeatbeltReceipt;
exports.recordSeatbeltDecision = recordSeatbeltDecision;
// Local receipts for seatbelt decisions (SEATBELT-SPEC.md §1.5, U6): a private, readable record that
// "Marrow stopped X", written on this machine only. U5 calls recordSeatbeltDecision() once per decision.
//
// Every receipt field is an enum, a bounded integer, a fixed-format id or a keyed hash (validateReceipt
// enforces it; a record that fails it is dropped, never written). There is no command text, argument,
// flag value, path, URL, host, MCP server or tool name, or branch name anywhere. The three keys are
// HMAC-SHA256(device_salt, ...) cut to 128 bits; the salt (32 random bytes, 0600) never leaves the machine.
//
// Receipts are evidence, never authority: nothing reads them to allow anything. A failure to write one
// (unsafe store, full disk, lock timeout, cap) never changes a decision: a stop stays a stop, a pass
// passes, and the failure is counted as `receipt_drop` in state.json. Nothing here touches the network.
const nodeFs = __importStar(require("node:fs"));
const node_crypto_1 = require("node:crypto");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const hook_contract_1 = require("../hook-contract");
const normalized_action_1 = require("../normalized-action");
const classifier_pin_1 = require("./classifier-pin");
const tables_1 = require("./tables");
exports.MAX_RECEIPT_BYTES = 16 * 1024;
exports.MAX_TOTAL_BYTES = 50 * 1024 * 1024;
exports.RETENTION_DAYS = 90;
const LOCK_WAIT_MS = 150;
/** A stop's receipt is the first-hour record, so it waits longer for the writer lock than a pass does. */
const STOP_LOCK_WAIT_MS = 600;
const LOCK_STALE_MS = 500;
const ZERO_PREV = '0'.repeat(64);
const FILE_NAME = /^\d{4}-\d{2}-\d{2}\.jsonl$/;
const DROP_REASONS = ['unsafe_store', 'lock_timeout', 'write_failed', 'cap_full', 'oversize', 'platform', 'error'];
class Refusal extends Error {
    reason;
    constructor(reason) {
        super(reason);
        this.reason = reason;
    }
}
// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------
const HARNESS_ENUM = {
    'claude-code': 'claude_code', cline: 'cline', codex: 'codex', cursor: 'cursor', gemini: 'gemini', grok: 'grok', windsurf: 'windsurf', 'mcp-client': 'mcp_client',
};
const HARNESSES = new Set([...Object.values(HARNESS_ENUM), 'other']);
const READ_TOOLS = new Set(['read', 'notebookread', 'read_file', 'view', 'view_file', 'grep', 'grep_files', 'search', 'rg', 'glob', 'ls', 'list_dir', 'list_directory']);
const OTHER_TOOLS = ['webfetch', 'websearch', 'task', 'agent', 'todowrite', 'skill', 'askuserquestion', 'exitplanmode'];
const TOOL_NAMES = new Set([...tables_1.SHELL_TOOL_NAMES, ...tables_1.FILE_TOOL_NAMES, ...OTHER_TOOLS, 'mcp', 'other']);
const TOOL_KINDS = new Set(['shell', 'file_read', 'file_write', 'mcp', 'other']);
const MODES = new Set(['seatbelt', 'claimed_no_key', 'account']);
const ENFORCEMENTS = new Set(['enforce', 'watch']);
const DECISIONS = new Set(['pass', 'stop', 'ask']);
const CATEGORIES = new Set(['none', 'S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx', 'hook', 'unknown']);
const PARSES = new Set(['ok', 'dynamic', 'unparsed', 'too_large', 'unknown']);
/**
 * The receipt schema accepts every class below, but this release writes only four: `protected_branch`
 * (S1 on a protected branch, and a plain push to one), `prod_env` (S2 with the `prod` flag),
 * `outside_workspace` (S5) and `unknown` for everything else. `other_branch`, `in_workspace`,
 * `home_credential` and `project_env` need a target on each mapper hit (a later unit); read `unknown`
 * as "not computed", never as "no target".
 */
const TARGET_CLASSES = new Set(['protected_branch', 'other_branch', 'in_workspace', 'outside_workspace', 'home_credential', 'project_env', 'prod_env', 'unknown']);
/** Flags the mapper emits (test/seatbelt-u6-receipts reads the source to prove it) plus the two the receipt adds for the account floor. */
exports.FLAG_CODES = new Set([
    'depth_limit', 'dry_run_final_true', 'pages_branch_from_git', 'prod', 'protected_branch_push', 'remote_exec', 'tripwire_clear', 'delete', 'force',
    'parse_dynamic', 'parse_unparsed', 'parse_too_large', 'floor_watch', 'floor_skipped',
]);
const PROGRAMS = new Set([...tables_1.KNOWN_COMMANDS, ...tables_1.INERT_PROGRAMS, 'other']);
const SUB_PROGRAMS = new Set(['git', 'gh', 'npm', 'pnpm', 'yarn', 'bun', 'npx', 'cargo', 'docker', 'podman', 'kubectl', 'helm', 'terraform', 'tofu', 'pulumi',
    'wrangler', 'vercel', 'netlify', 'fly', 'flyctl', 'firebase', 'heroku', 'gcloud', 'aws', 'az', 'twine', 'gem', 'uv', 'poetry', 'make', 'marrow', 'marrow-install']);
const RISKY_SUBCOMMANDS = ['push', 'publish', 'deploy', 'release', 'delete', 'destroy', 'apply', 'rm', 'unpublish', 'deprecate', 'upload', 'login', 'token', 'secret'];
const SUBCOMMANDS = new Set([...RISKY_SUBCOMMANDS, 'commit', 'clean', 'reset', 'rebase', 'merge', 'checkout', 'branch', 'tag', 'status', 'diff', 'log',
    'pull', 'fetch', 'clone', 'add', 'build', 'test', 'run', 'install', 'ci', 'pack', 'create', 'edit', 'view', 'list', 'get', 'set', 'config', 'plan', 'init', 'none', 'other']);
const REASON = /^[a-z][a-z0-9_]{0,63}$/;
const RULE = /^(?:none|unknown|S[0-5x]\.[a-z0-9_]{1,48}|U5\.[a-z_]{1,32})$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const FIELD_NAMES = ['v', 'id', 'seq', 'prev', 'ts', 'ts_label', 'mode', 'enforcement', 'harness', 'event', 'tool_kind', 'tool', 'decision', 'category', 'rule', 'reasons',
    'programs', 'subcommand', 'flags', 'target_class', 'parse', 'action_key', 'workspace_key', 'session_key', 'engine', 'latency_ms'];
const ENGINE_FIELDS = ['pkg', 'contract', 'source_commit', 'rules', 'tables'];
const isInt = (value, min, max) => typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
const isList = (value, max, ok) => Array.isArray(value) && value.length <= max && value.every((item) => typeof item === 'string' && ok(item));
const hasHexRun = (value) => /[0-9a-f]{20,}/.test(value);
/** The problems with a receipt object (an empty list means valid). Used by the writer and by every consumer of the fields. */
function validateReceipt(value) {
    const bad = [];
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return ['not_an_object'];
    const r = value;
    for (const name of Object.keys(r))
        if (!FIELD_NAMES.includes(name))
            bad.push(`unknown_field:${name.slice(0, 32).replace(/[^A-Za-z0-9_]/g, '_')}`);
    for (const name of FIELD_NAMES)
        if (!(name in r))
            bad.push(`missing:${name}`);
    const str = (name, ok) => { if (typeof r[name] !== 'string' || !ok(r[name]))
        bad.push(`bad:${name}`); };
    if (r.v !== 1)
        bad.push('bad:v');
    str('id', (s) => /^sbr_[0-9a-f]{32}$/.test(s));
    if (!isInt(r.seq, 1, Number.MAX_SAFE_INTEGER))
        bad.push('bad:seq');
    str('prev', (s) => HEX64.test(s));
    if (!isInt(r.ts, 0, 4_102_444_800))
        bad.push('bad:ts');
    if (r.ts_label !== 'client_time')
        bad.push('bad:ts_label');
    str('mode', (s) => MODES.has(s));
    str('enforcement', (s) => ENFORCEMENTS.has(s));
    str('harness', (s) => HARNESSES.has(s));
    if (r.event !== 'pre_tool')
        bad.push('bad:event');
    str('tool_kind', (s) => TOOL_KINDS.has(s));
    str('tool', (s) => TOOL_NAMES.has(s));
    str('decision', (s) => DECISIONS.has(s));
    str('category', (s) => CATEGORIES.has(s));
    str('rule', (s) => RULE.test(s));
    if (!isList(r.reasons, 16, (s) => REASON.test(s) && !hasHexRun(s)))
        bad.push('bad:reasons');
    if (!isList(r.programs, 8, (s) => PROGRAMS.has(s)))
        bad.push('bad:programs');
    str('subcommand', (s) => SUBCOMMANDS.has(s));
    if (!isList(r.flags, 16, (s) => exports.FLAG_CODES.has(s)))
        bad.push('bad:flags');
    str('target_class', (s) => TARGET_CLASSES.has(s));
    str('parse', (s) => PARSES.has(s));
    for (const name of ['action_key', 'workspace_key', 'session_key'])
        str(name, (s) => HEX32.test(s));
    const engine = r.engine;
    if (!engine || typeof engine !== 'object' || Array.isArray(engine))
        bad.push('bad:engine');
    else {
        for (const name of Object.keys(engine))
            if (!ENGINE_FIELDS.includes(name))
                bad.push('bad:engine_field');
        const part = (name, re) => { if (typeof engine[name] !== 'string' || !re.test(engine[name]))
            bad.push(`bad:engine.${name}`); };
        part('pkg', /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[-+][0-9A-Za-z.-]{1,32})?$/);
        part('contract', /^marrow\.classifier\.v\d{1,3}$/);
        part('source_commit', /^[0-9a-f]{40}$/);
        part('rules', /^marrow\.seatbelt\.rules\.v\d{1,3}$/);
        part('tables', /^(?:[0-9a-f]{16}|unknown)$/);
    }
    if (!isInt(r.latency_ms, 0, 600_000))
        bad.push('bad:latency_ms');
    return bad;
}
// ---------------------------------------------------------------------------
// Deriving the fields
// ---------------------------------------------------------------------------
const hmacHex = (salt, label, material) => (0, node_crypto_1.createHmac)('sha256', salt).update(`${label}\n`).update(material).digest('hex').slice(0, 32);
const sha256Hex = (text) => (0, node_crypto_1.createHash)('sha256').update(text).digest('hex');
function sortedJson(value) {
    const order = (item, level) => {
        if (level > 8 || !item || typeof item !== 'object')
            return item;
        if (Array.isArray(item))
            return item.map((entry) => order(entry, level + 1));
        return Object.fromEntries(Object.keys(item).sort().map((key) => [key, order(item[key], level + 1)]));
    };
    return JSON.stringify(order(value, 0));
}
function toolOf(name) {
    const text = typeof name === 'string' ? name.trim() : '';
    const lower = text.toLowerCase();
    if (/^(?:functions\.\s*)*(?:mcp__|mcp_|mcp:)/i.test(text))
        return { tool: 'mcp', kind: 'mcp' };
    if (tables_1.SHELL_TOOL_NAMES.has(lower))
        return { tool: lower, kind: 'shell' };
    if (READ_TOOLS.has(lower))
        return { tool: lower, kind: 'file_read' };
    if (tables_1.FILE_TOOL_NAMES.has(lower))
        return { tool: lower, kind: 'file_write' };
    if (OTHER_TOOLS.includes(lower))
        return { tool: lower, kind: 'other' };
    return { tool: 'other', kind: 'other' };
}
/** The keyed hash of the normalized, secret-replaced action. Actions that differ outside a secret get different keys. */
function actionKey(salt, event) {
    const raw = () => {
        try {
            return `raw\n${String(event.tool_name)}\n${typeof event.tool_input === 'string' ? event.tool_input : JSON.stringify(event.tool_input ?? null)}`;
        }
        catch {
            return 'raw\nunserializable';
        }
    };
    try {
        const action = (0, normalized_action_1.normalizedHookAction)(event, { deadlineAt: Date.now() + 150 });
        const input = action.tool_input;
        const covered = typeof input.command_sha256 === 'string' || typeof input.input_sha256 === 'string';
        const empty = event.tool_input === undefined || event.tool_input === null || event.tool_input === '';
        // A placeholder (input too large or too slow to normalize) covers nothing: key the exact input so two different inputs never share a key.
        const material = action.truncated === true && !covered && !empty ? raw() : `norm\n${sortedJson(action)}`;
        return { key: hmacHex(salt, 'action', material), programs: action.tool_kind === 'shell' ? action.programs || [] : [] };
    }
    catch {
        return { key: hmacHex(salt, 'action', raw()), programs: [] };
    }
}
/** The git top level of cwd, else cwd itself (both realpath), or null when the workspace is unknown. */
function workspaceRoot(fs, cwd) {
    if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096)
        return null;
    try {
        const start = fs.realpathSync(cwd);
        let dir = start;
        for (;;) {
            try {
                fs.lstatSync(dir === '/' ? '/.git' : `${dir}/.git`);
                return dir;
            }
            catch { /* no .git here */ }
            if (dir === '/')
                return start;
            dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
        }
    }
    catch {
        return null;
    }
}
/** Program basenames, only from the classifier vocabulary; anything else is `other`. */
function programsOf(found) {
    const out = [];
    for (const name of found) {
        const base = (0, node_path_1.basename)(String(name)).toLowerCase();
        const known = PROGRAMS.has(base) ? base : 'other';
        if (!out.includes(known))
            out.push(known);
        if (out.length >= 8)
            break;
    }
    return out;
}
/** A subcommand word from the fixed vocabulary, found lexically after a known program. Never any other text. */
function subcommandOf(event) {
    const input = event.tool_input;
    const command = typeof input === 'string' ? input
        : input && typeof input === 'object' && typeof input.command === 'string' ? input.command : '';
    const words = command.slice(0, 8192).split(/[\s;&|()<>`]+/).map((w) => w.replace(/^['"\\]+|['"\\]+$/g, ''));
    let found = 'none';
    for (let i = 0; i < words.length; i += 1) {
        if (!SUB_PROGRAMS.has((0, node_path_1.basename)(words[i]).toLowerCase()))
            continue;
        for (let j = i + 1, seen = 0; j < words.length && seen < 3; j += 1) {
            const word = words[j].toLowerCase();
            if (!word || word.startsWith('-'))
                continue;
            seen += 1;
            if (SUBCOMMANDS.has(word) && word !== 'none' && word !== 'other') {
                if (RISKY_SUBCOMMANDS.includes(word))
                    return word;
                if (found === 'none' || found === 'other')
                    found = word;
                break;
            }
            if (found === 'none')
                found = 'other';
        }
    }
    return found;
}
/** The mapper's hits carry no target, so only the classes its reason codes and flags prove are named; the rest is `unknown`. */
function targetClass(category, reasons, flags) {
    if (category === 'S1')
        return reasons.some((r) => r.includes('protected')) ? 'protected_branch' : 'unknown';
    if (category === 'S2')
        return flags.includes('prod') ? 'prod_env' : 'unknown';
    if (category === 'S5')
        return reasons.some((r) => r.endsWith('_outside_workspace')) ? 'outside_workspace' : 'unknown';
    if (category === 'none' && flags.includes('protected_branch_push'))
        return 'protected_branch';
    return 'unknown';
}
let engineCache = null;
function engine(fs) {
    if (engineCache)
        return engineCache;
    let tables = 'unknown';
    try {
        tables = sha256Hex(fs.readFileSync((0, node_path_1.join)(__dirname, 'tables.js'), 'latin1')).slice(0, 16);
    }
    catch { /* the hash is a label; a build without the file says unknown */ }
    engineCache = { pkg: hook_contract_1.MCP_ADAPTER_VERSION, contract: classifier_pin_1.CLASSIFIER_PIN.contract, source_commit: classifier_pin_1.CLASSIFIER_PIN.source_commit, rules: tables_1.SEATBELT_RULES_VERSION, tables };
    return engineCache;
}
const codeList = (list, ok, max) => {
    const out = [];
    if (Array.isArray(list))
        for (const item of list)
            if (typeof item === 'string' && ok(item) && !out.includes(item)) {
                out.push(item);
                if (out.length >= max)
                    break;
            }
    return out;
};
function buildReceipt(record, context, salt, fs, now) {
    const watch = record.enforcement === 'watch';
    const category = CATEGORIES.has(record.category) ? record.category : 'unknown';
    const reasons = codeList(record.reasons, (s) => REASON.test(s) && !hasHexRun(s), 16);
    const flags = codeList(record.flags, (s) => exports.FLAG_CODES.has(s), 14);
    // Account floor in watch: the hook passed the action. A would-stop is a flag, never a claim that Marrow stopped it.
    const decision = (record.decision === 'stop' || record.decision === 'skipped') && !watch ? 'stop' : 'pass';
    if (watch && record.decision === 'stop')
        flags.push('floor_watch');
    if (watch && record.decision === 'skipped')
        flags.push('floor_skipped');
    const { tool, kind } = toolOf(context.tool_name);
    const event = { tool_name: context.tool_name, tool_input: context.tool_input, input_truncated: context.truncated === true };
    const action = actionKey(salt, event);
    const root = workspaceRoot(fs, context.cwd);
    const session = typeof context.session === 'string' || typeof context.session === 'number' ? String(context.session).slice(0, 256) : '';
    return {
        v: 1, ts: Math.floor(now / 1000), ts_label: 'client_time', mode: record.mode, enforcement: record.enforcement,
        harness: Object.hasOwn(HARNESS_ENUM, record.harness) ? HARNESS_ENUM[record.harness] : 'other', event: 'pre_tool', tool_kind: kind, tool, decision, category,
        rule: RULE.test(record.rule) ? record.rule : 'unknown', reasons,
        programs: kind === 'shell' ? programsOf(action.programs) : [], subcommand: kind === 'shell' ? subcommandOf(event) : 'none',
        flags, target_class: targetClass(category, reasons, flags),
        parse: PARSES.has(record.parse) ? record.parse : 'unknown',
        action_key: action.key, workspace_key: hmacHex(salt, 'workspace', root === null ? 'unknown' : `path\n${root}`),
        session_key: hmacHex(salt, 'session', session === '' ? 'none' : `id\n${session}`),
        engine: engine(fs), latency_ms: Number.isFinite(record.latency_ms) ? Math.min(600_000, Math.max(0, Math.round(record.latency_ms))) : 0,
    };
}
const C = nodeFs.constants;
const NOFOLLOW = C.O_NOFOLLOW || 0;
const codeOf = (error) => String(error?.code || '');
function lstatOrNull(fs, path) {
    try {
        return fs.lstatSync(path);
    }
    catch (error) {
        if (codeOf(error) === 'ENOENT')
            return null;
        throw error;
    }
}
/** A directory we own. `strict`: no group or other access. `.marrow` itself may be a symlink to such a directory; nothing below it may. */
function ensureDir(fs, path, uid, strict, followLink) {
    let st = lstatOrNull(fs, path);
    if (!st) {
        try {
            fs.mkdirSync(path, { mode: 0o700 });
        }
        catch (error) {
            if (codeOf(error) !== 'EEXIST')
                throw error;
        }
        st = fs.lstatSync(path);
    }
    let real = path;
    if (st.isSymbolicLink()) {
        if (!followLink)
            throw new Refusal('unsafe_store');
        real = fs.realpathSync(path);
        st = fs.lstatSync(real);
    }
    if (!st.isDirectory() || st.uid !== uid || (st.mode & (strict ? 0o077 : 0o022)) !== 0)
        throw new Refusal('unsafe_store');
    return real;
}
function readSalt(fs, path, uid) {
    const fd = fs.openSync(path, C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
    try {
        const st = fs.fstatSync(fd);
        // No link-count check on the salt: it is only read, and while another hook is creating it (temp file linked into place) it briefly has two names.
        if (!st.isFile() || st.uid !== uid || (st.mode & 0o077) !== 0 || st.size !== 32)
            throw new Refusal('unsafe_store');
        const buffer = Buffer.alloc(32);
        if (fs.readSync(fd, buffer, 0, 32, 0) !== 32)
            throw new Refusal('unsafe_store');
        return buffer;
    }
    finally {
        fs.closeSync(fd);
    }
}
/** 32 random bytes, created once: a temp file linked into place (link fails if anything, even a symlink, is already there). */
function loadSalt(fs, dir, uid) {
    const path = (0, node_path_1.join)(dir, 'salt');
    try {
        return readSalt(fs, path, uid);
    }
    catch (error) {
        if (codeOf(error) !== 'ENOENT')
            throw error;
    }
    const tmp = (0, node_path_1.join)(dir, `.salt.${process.pid}.${(0, node_crypto_1.randomBytes)(6).toString('hex')}`);
    const fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
    try {
        fs.writeSync(fd, (0, node_crypto_1.randomBytes)(32));
    }
    finally {
        fs.closeSync(fd);
    }
    try {
        try {
            fs.linkSync(tmp, path);
        }
        catch (error) {
            if (codeOf(error) !== 'EEXIST')
                throw error;
        }
    }
    finally {
        try {
            fs.unlinkSync(tmp);
        }
        catch { /* best effort */ }
    }
    return readSalt(fs, path, uid);
}
/** `found.dir` is set as soon as ~/.marrow/seatbelt is a real directory we own, so a refusal below it can still be counted. */
function openStore(fs, home, uid, found) {
    if (!home.startsWith('/'))
        throw new Refusal('unsafe_store');
    const realHome = fs.realpathSync(home);
    const homeStat = fs.statSync(realHome);
    if (realHome === '/' || !homeStat.isDirectory() || homeStat.uid !== uid)
        throw new Refusal('unsafe_store');
    const marrow = ensureDir(fs, (0, node_path_1.join)(realHome, '.marrow'), uid, false, true);
    const dir = (0, node_path_1.join)(marrow, 'seatbelt');
    const seen = lstatOrNull(fs, dir);
    if (seen && seen.isDirectory() && seen.uid === uid)
        found.dir = dir;
    ensureDir(fs, dir, uid, true, false);
    found.dir = dir;
    const receipts = (0, node_path_1.join)(dir, 'receipts');
    ensureDir(fs, receipts, uid, true, false);
    return { fs, uid, dir, receipts, salt: loadSalt(fs, dir, uid) };
}
const sleep = (ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };
/** One writer at a time (so seq/prev stay a chain). A holder that died is stolen from after LOCK_STALE_MS. */
function withLock(fs, dir, waitMs, work) {
    const path = (0, node_path_1.join)(dir, 'lock');
    const started = Date.now();
    let fd = null;
    while (fd === null) {
        try {
            fd = fs.openSync(path, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
        }
        catch (error) {
            if (codeOf(error) !== 'EEXIST')
                throw error;
            if (Date.now() - started > waitMs)
                throw new Refusal('lock_timeout');
            try {
                const st = fs.lstatSync(path);
                if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
                    fs.unlinkSync(path);
                    continue;
                }
            }
            catch { /* released meanwhile, or not ours to remove */ }
            sleep(2);
        }
    }
    try {
        return work();
    }
    finally {
        try {
            fs.closeSync(fd);
        }
        catch { /* ignore */ }
        try {
            fs.unlinkSync(path);
        }
        catch { /* ignore */ }
    }
}
function readState(fs, dir) {
    const state = { v: 1, receipt_drop: 0, drop_reasons: {}, evicted_files: 0, evicted_bytes: 0 };
    try {
        const fd = fs.openSync((0, node_path_1.join)(dir, 'state.json'), C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
        try {
            const buffer = Buffer.alloc(8192);
            const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
            const parsed = JSON.parse(buffer.subarray(0, length).toString('utf8'));
            const count = (n) => (typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? n : 0);
            state.receipt_drop = count(parsed.receipt_drop);
            state.evicted_files = count(parsed.evicted_files);
            state.evicted_bytes = count(parsed.evicted_bytes);
            for (const reason of DROP_REASONS)
                if (parsed.drop_reasons && count(parsed.drop_reasons[reason]))
                    state.drop_reasons[reason] = count(parsed.drop_reasons[reason]);
        }
        finally {
            fs.closeSync(fd);
        }
    }
    catch { /* missing, unreadable or not a regular file: counting starts again */ }
    return state;
}
/** Atomic replace (temp file + rename), so a crash or a full disk never leaves a half-written state.json. */
function updateState(fs, dir, change) {
    const state = readState(fs, dir);
    change(state);
    const tmp = (0, node_path_1.join)(dir, `.state.${process.pid}.${(0, node_crypto_1.randomBytes)(6).toString('hex')}`);
    try {
        const fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
        try {
            fs.writeSync(fd, `${JSON.stringify(state)}\n`);
        }
        finally {
            fs.closeSync(fd);
        }
        fs.renameSync(tmp, (0, node_path_1.join)(dir, 'state.json'));
    }
    catch (error) {
        try {
            fs.unlinkSync(tmp);
        }
        catch { /* ignore */ }
        throw error;
    }
}
const ymd = (ms) => new Date(ms).toISOString().slice(0, 10);
function managedFiles(fs, dir) {
    const out = [];
    for (const name of fs.readdirSync(dir).sort()) {
        if (!FILE_NAME.test(name))
            continue;
        const path = (0, node_path_1.join)(dir, name);
        const st = lstatOrNull(fs, path);
        if (st)
            out.push({ name, path, size: st.isFile() ? st.size : 0 });
    }
    return out;
}
/** The last line of a receipt file: its sha256 and seq, or null when the file has no line. `open`: the file does not end in a newline. */
function tailOf(fs, fd, size) {
    if (size <= 0)
        return null;
    const length = Math.min(size, exports.MAX_RECEIPT_BYTES + 2);
    const buffer = Buffer.alloc(length);
    const got = fs.readSync(fd, buffer, 0, length, size - length);
    const text = buffer.subarray(0, got).toString('utf8');
    const open = !text.endsWith('\n');
    const body = open ? text : text.slice(0, -1);
    const line = body.slice(body.lastIndexOf('\n') + 1);
    let seq = null;
    try {
        const parsed = JSON.parse(line);
        if (isInt(parsed.seq, 1, Number.MAX_SAFE_INTEGER - 1))
            seq = parsed.seq;
    }
    catch { /* a damaged last line: the chain restarts at 1 and the break shows */ }
    return { hash: sha256Hex(line), seq, open };
}
/** Under the lock: retention and cap, then one O_APPEND write of the next link in the chain. */
function append(store, body, now, options) {
    const { fs } = store;
    const cap = options.maxTotalBytes ?? exports.MAX_TOTAL_BYTES;
    const todayName = `${ymd(now)}.jsonl`;
    let files = managedFiles(fs, store.receipts);
    // Retention counts from the newest earlier file when the clock is further ahead than that: a clock that jumped forward
    // (a resumed VM, a reset RTC) must not wipe the history. Day names are dates, so one day of slack is a plain string step.
    const newestEarlier = files.filter((file) => file.name < todayName).pop();
    const basis = newestEarlier ? Math.min(now, Date.parse(`${newestEarlier.name.slice(0, 10)}T00:00:00Z`) + 2 * 86_400_000) : now;
    const cutoff = `${ymd(basis - (options.retentionDays ?? exports.RETENTION_DAYS) * 86_400_000)}.jsonl`;
    let evictedFiles = 0;
    let evictedBytes = 0;
    const evict = (file) => {
        try {
            fs.unlinkSync(file.path);
        }
        catch (error) {
            if (codeOf(error) !== 'ENOENT')
                throw error;
        }
        evictedFiles += 1;
        evictedBytes += file.size;
        files = files.filter((other) => other !== file);
    };
    // Retention first, then oldest-first until the new record fits. Today's file is never evicted.
    for (const file of [...files])
        if (file.name < cutoff && file.name !== todayName)
            evict(file);
    let total = files.reduce((sum, file) => sum + file.size, 0);
    for (const file of [...files]) {
        if (total + exports.MAX_RECEIPT_BYTES <= cap)
            break;
        if (file.name === todayName)
            continue;
        evict(file);
        total -= file.size;
    }
    if (evictedFiles > 0) {
        try {
            updateState(fs, store.dir, (state) => { state.evicted_files += evictedFiles; state.evicted_bytes += evictedBytes; });
        }
        catch { /* the count is best effort */ }
    }
    if (total + exports.MAX_RECEIPT_BYTES > cap)
        throw new Refusal('cap_full');
    // O_NONBLOCK: a FIFO planted as a day file must not hang the hook (it is then refused: not a regular file).
    const fd = fs.openSync((0, node_path_1.join)(store.receipts, todayName), C.O_RDWR | C.O_APPEND | C.O_CREAT | NOFOLLOW | (C.O_NONBLOCK || 0), 0o600);
    try {
        const st = fs.fstatSync(fd);
        if (!st.isFile() || st.nlink !== 1 || st.uid !== store.uid || (st.mode & 0o077) !== 0)
            throw new Refusal('unsafe_store');
        let tail = tailOf(fs, fd, st.size);
        if (tail === null) {
            // First line of the day: continue the chain from the newest earlier file.
            const earlier = files.filter((file) => file.name < todayName && file.size > 0).pop();
            if (earlier) {
                try {
                    const old = fs.openSync(earlier.path, C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0));
                    try {
                        const earlierStat = fs.fstatSync(old);
                        if (earlierStat.isFile())
                            tail = tailOf(fs, old, earlierStat.size);
                    }
                    finally {
                        fs.closeSync(old);
                    }
                }
                catch {
                    tail = null;
                }
            }
        }
        const { v, ...rest } = body;
        const receipt = {
            v, id: `sbr_${(0, node_crypto_1.randomBytes)(16).toString('hex')}`, seq: tail && tail.seq !== null ? tail.seq + 1 : 1, prev: tail ? tail.hash : ZERO_PREV, ...rest,
        };
        if (validateReceipt(receipt).length > 0)
            throw new Refusal('error');
        const bytes = Buffer.from(`${st.size > 0 && tail && tail.open ? '\n' : ''}${JSON.stringify(receipt)}\n`);
        if (bytes.length > exports.MAX_RECEIPT_BYTES)
            throw new Refusal('oversize');
        if (fs.writeSync(fd, bytes, 0, bytes.length) !== bytes.length)
            throw new Refusal('write_failed');
    }
    finally {
        fs.closeSync(fd);
    }
}
function dropReason(error) {
    if (error instanceof Refusal)
        return error.reason;
    const code = codeOf(error);
    if (code === 'ELOOP' || code === 'ENOTDIR' || code === 'EISDIR')
        return 'unsafe_store';
    return /^(?:ENOSPC|EACCES|EPERM|EIO|EROFS|EDQUOT|EMFILE|ENFILE|EBUSY)$/.test(code) ? 'write_failed' : 'error';
}
/** `receipt_drop` (and its reason) in state.json. Best effort: with no safe directory to count in, the drop stays invisible rather than risk a write. */
function countDrop(fs, dir, reason, waitMs) {
    const change = (state) => { state.receipt_drop += 1; state.drop_reasons[reason] = (state.drop_reasons[reason] || 0) + 1; };
    try {
        try {
            withLock(fs, dir, Math.min(waitMs, 40), () => updateState(fs, dir, change));
        }
        catch (error) {
            if (!(error instanceof Refusal && error.reason === 'lock_timeout'))
                throw error;
            updateState(fs, dir, change);
        }
    }
    catch { /* see above */ }
}
function passwdHome() {
    try {
        const home = (0, node_os_1.userInfo)().homedir;
        return typeof home === 'string' && home.startsWith('/') ? home : null;
    }
    catch {
        return null;
    }
}
/** Write one receipt. Never throws; says what happened. The hook calls recordSeatbeltDecision; tests call this with options. */
function writeSeatbeltReceipt(record, context = {}, options = {}) {
    const fs = options.fs || nodeFs;
    const found = {};
    let wait = options.lockWaitMs ?? LOCK_WAIT_MS;
    try {
        const uid = options.uid === undefined ? (typeof process.getuid === 'function' ? process.getuid() : null) : options.uid;
        if (typeof uid !== 'number')
            throw new Refusal('platform');
        const home = options.home || context.home || passwdHome();
        if (!home)
            throw new Refusal('unsafe_store');
        const now = options.now ?? Date.now();
        const store = openStore(fs, home, uid, found);
        const body = buildReceipt(record, context, store.salt, fs, now);
        wait = options.lockWaitMs ?? (body.decision === 'stop' ? STOP_LOCK_WAIT_MS : LOCK_WAIT_MS);
        withLock(fs, store.dir, wait, () => append(store, body, now, options));
        return 'written';
    }
    catch (error) {
        if (found.dir)
            countDrop(fs, found.dir, dropReason(error), wait);
        return 'dropped';
    }
}
/** The record hook U5 calls once per decision. It never throws, writes no output and never changes a decision. */
function recordSeatbeltDecision(record, context) {
    try {
        writeSeatbeltReceipt(record, context || {});
    }
    catch { /* the record hook never changes a decision */ }
}
//# sourceMappingURL=record.js.map