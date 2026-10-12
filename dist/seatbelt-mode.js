"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MODE_ENV_NAMES = exports.HOOK_CONFIG_FILES = exports.ACCOUNT_EVIDENCE = void 0;
exports.homeFlags = homeFlags;
exports.resolveSeatbeltMode = resolveSeatbeltMode;
exports.resolveSeatbeltModeOnHost = resolveSeatbeltModeOnHost;
const node_os_1 = require("node:os");
const env_1 = require("./env");
const seatbelt_fs_1 = require("./seatbelt-fs");
const seatbelt_path_1 = require("./seatbelt-path");
exports.ACCOUNT_EVIDENCE = [
    'env_file',
    'env_local_file',
    'device_binding',
    'claimed_marker',
    'host_approvals_state',
    'mcp_spool',
    'runner_holds_salt',
    'hook_claimed_marker',
    'marrow_dir',
];
/** Harness hook configs (user level) that carry the installer's `--claimed` marker after a claim. */
exports.HOOK_CONFIG_FILES = [
    '.claude/settings.json',
    '.codex/hooks.json',
    '.cursor/hooks.json',
    '.gemini/settings.json',
    '.codeium/windsurf/hooks.json',
    '.grok/hooks/marrow.json',
];
const MAX_HOOK_CONFIG_BYTES = 1024 * 1024;
const CLAIMED_TOKEN = /(?:^|[\s"'\\])--claimed(?:$|[\s"'=\\])/;
/** Every `--home` value in the hook's argv (repeated flags are all kept: a mismatch is contradictory). */
function homeFlags(argv) {
    const out = [];
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === '--home') {
            out.push(argv[i + 1] ?? '');
            i += 1;
        }
        else if (arg.startsWith('--home='))
            out.push(arg.slice('--home='.length));
    }
    return out;
}
function argvClaimed(argv) {
    return argv.some((arg) => arg === '--claimed' || arg.startsWith('--claimed='));
}
function exists(fs, path) {
    try {
        return fs.lstat(path) ? 'present' : 'absent';
    }
    catch {
        return 'unknown';
    }
}
function worst(a, b) {
    if (a === 'present' || b === 'present')
        return 'present';
    if (a === 'unknown' || b === 'unknown')
        return 'unknown';
    return 'absent';
}
function probeSpool(fs, dir) {
    try {
        const entry = fs.lstat(dir);
        if (!entry)
            return 'absent';
        if (entry.type !== 'dir')
            return 'unknown';
        return fs.readdir(dir).some((name) => /^mcp-.*\.json$/i.test(name)) ? 'present' : 'absent';
    }
    catch {
        return 'unknown';
    }
}
function probeHookConfig(fs, path) {
    try {
        const entry = fs.lstat(path);
        if (!entry)
            return 'absent';
        let target = path;
        if (entry.type === 'symlink') {
            const real = (0, seatbelt_path_1.realPath)(fs, path, { followFinal: true });
            if (real.status !== 'resolved' || !real.exists)
                return 'unknown';
            target = real.path;
        }
        const text = fs.readFile(target, MAX_HOOK_CONFIG_BYTES);
        if (text === null)
            return 'unknown';
        return CLAIMED_TOKEN.test(text) ? 'present' : 'absent';
    }
    catch {
        return 'unknown';
    }
}
// ~/.marrow itself: absent and a plain directory owned by this user are both
// fine (keyless installs keep control.json there). A symlink, a file, another
// owner, group/world write or an unreadable entry cannot be reasoned about, so it is unknown.
function probeMarrowDir(fs, dir, uid) {
    try {
        const entry = fs.lstat(dir);
        if (!entry)
            return 'absent';
        if (entry.type !== 'dir')
            return 'unknown';
        if (uid !== null && entry.uid !== uid)
            return 'unknown';
        // Others could delete evidence from a group/world-writable directory.
        if ((entry.mode & 0o022) !== 0)
            return 'unknown';
        return 'absent';
    }
    catch {
        return 'unknown';
    }
}
function probeHome(fs, home, uid) {
    const marrow = `${home}/.marrow`;
    let hooks = 'absent';
    for (const file of exports.HOOK_CONFIG_FILES)
        hooks = worst(hooks, probeHookConfig(fs, `${home}/${file}`));
    return {
        env_file: exists(fs, `${marrow}/env`),
        env_local_file: exists(fs, `${marrow}/env.local`),
        device_binding: exists(fs, `${marrow}/device/binding.json`),
        claimed_marker: exists(fs, `${marrow}/claimed`),
        // Spec: "has a protected_categories cache". Any state file counts: it is only
        // ever written after talking to a server, and counting more is stricter.
        host_approvals_state: exists(fs, `${marrow}/host-approvals/state.json`),
        mcp_spool: probeSpool(fs, `${marrow}/spool`),
        runner_holds_salt: exists(fs, `${marrow}/runner-holds/.salt`),
        hook_claimed_marker: hooks,
        marrow_dir: probeMarrowDir(fs, marrow, uid),
    };
}
/** A usable home: absolute, no `.`/`..` parts, and an existing directory after realpath. */
function trustedHome(fs, value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.split('/').some((part) => part === '..' || part === '.'))
        return null;
    const real = (0, seatbelt_path_1.realPath)(fs, value, { followFinal: true });
    if (real.status !== 'resolved' || !real.exists)
        return null;
    try {
        return fs.lstat(real.path)?.type === 'dir' ? real.path : null;
    }
    catch {
        return null;
    }
}
function resolveSeatbeltMode(input) {
    const reasons = [];
    const uid = input.uid === undefined ? null : input.uid;
    const evidence = Object.fromEntries(exports.ACCOUNT_EVIDENCE.map((id) => [id, 'absent']));
    if (argvClaimed(input.argv))
        evidence.hook_claimed_marker = 'present';
    const flags = homeFlags(input.argv);
    const candidates = [...flags, ...(input.passwdHome === null ? [] : [input.passwdHome])];
    const homes = [];
    let homeProblem = false;
    if (input.passwdHome === null && flags.length === 0) {
        homeProblem = true;
        reasons.push('home_unknown');
    }
    for (const candidate of candidates) {
        const home = trustedHome(input.fs, candidate);
        if (home === null) {
            homeProblem = true;
            reasons.push('home_unusable');
            continue;
        }
        if (!homes.includes(home))
            homes.push(home);
    }
    if (homes.length > 1) {
        homeProblem = true;
        reasons.push('home_mismatch');
    }
    // Every home named anywhere is probed: evidence in any of them counts.
    for (const home of homes) {
        const probed = probeHome(input.fs, home, uid);
        for (const id of exports.ACCOUNT_EVIDENCE)
            evidence[id] = worst(evidence[id], probed[id]);
    }
    const present = exports.ACCOUNT_EVIDENCE.filter((id) => evidence[id] === 'present');
    const unknown = exports.ACCOUNT_EVIDENCE.filter((id) => evidence[id] === 'unknown');
    if (present.length > 0)
        reasons.push('account_evidence');
    if (unknown.length > 0)
        reasons.push('evidence_unknown');
    let mode;
    if (input.key === 'present')
        mode = 'account';
    else if (input.key === 'rejected') {
        mode = 'claimed_no_key';
        reasons.push('key_rejected');
    }
    else if (homeProblem || present.length > 0 || unknown.length > 0)
        mode = 'claimed_no_key';
    else if (input.strict) {
        mode = 'claimed_no_key';
        reasons.push('strict');
    }
    else
        mode = 'seatbelt';
    return { mode, homes, evidence, reasons };
}
/** The only environment names mode resolution reads: the key lookup's names and the strict switch. */
const KEY_ENV_NAMES = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_SESSION_ID'];
exports.MODE_ENV_NAMES = [...KEY_ENV_NAMES, 'MARROW_SEATBELT_STRICT'];
function passwdHomeDirectory() {
    try {
        const home = (0, node_os_1.userInfo)().homedir;
        return typeof home === 'string' && home ? home : null;
    }
    catch {
        return null;
    }
}
/**
 * Host wiring for the hook (U5 calls this). The key comes only from the hook's
 * environment or the owner files in a trusted home (never repo .env files);
 * keyRejected is set after the server answers 401.
 */
function resolveSeatbeltModeOnHost(options = {}) {
    const env = options.env || process.env;
    const fs = options.fs || (0, seatbelt_fs_1.nodeSeatbeltFs)();
    const argv = options.argv || process.argv.slice(2);
    const passwdHome = options.passwdHome === undefined ? passwdHomeDirectory() : options.passwdHome;
    const uid = options.uid === undefined ? (typeof process.getuid === 'function' ? process.getuid() : null) : options.uid;
    // Only these names are copied out of the environment; HOME and every other
    // variable stay unread, so no variable can steer the home or the mode.
    const keyEnv = {};
    for (const name of KEY_ENV_NAMES) {
        const value = env[name];
        if (typeof value === 'string')
            keyEnv[name] = value;
    }
    const strict = env.MARROW_SEATBELT_STRICT === '1';
    const homes = [...homeFlags(argv), ...(passwdHome ? [passwdHome] : [])];
    let key = 'none';
    if (keyEnv.MARROW_API_KEY || keyEnv.MARROW_KEY)
        key = 'present';
    for (const home of homes) {
        if (key === 'present')
            break;
        const real = trustedHome(fs, home);
        if (!real)
            continue;
        if ((0, env_1.resolveMarrowEnv)({ env: keyEnv, home: real, trustedOnly: true }).apiKey)
            key = 'present';
    }
    if (key === 'present' && options.keyRejected)
        key = 'rejected';
    return resolveSeatbeltMode({ fs, passwdHome, argv, key, uid, strict });
}
//# sourceMappingURL=seatbelt-mode.js.map