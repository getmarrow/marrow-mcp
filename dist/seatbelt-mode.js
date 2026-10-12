"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MODE_ENV_NAMES = exports.HOOK_CONFIG_DIRS = exports.HOOK_CONFIG_FILES = exports.ACCOUNT_EVIDENCE = void 0;
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
    /** The home and every directory holding evidence: owned by this user and not group/world-writable. Never 'present'. */
    'evidence_dirs',
];
/** Harness hook configs (user level) that carry the installer's `--claimed` marker after a claim. */
exports.HOOK_CONFIG_FILES = [
    '.claude/settings.json',
    '.codex/hooks.json',
    '.cursor/hooks.json',
    '.gemini/settings.json',
    '.codeium/windsurf/hooks.json',
    '.grok/hooks/marrow.json',
    '.claude/settings.local.json',
    '.codex/config.toml',
];
/**
 * Hook script directories (Cline runs the executable scripts in its hooks
 * directory). Every regular file in them is scanned for the marker. U8 must
 * publish the exact paths it writes; any path it adds must be added here.
 */
exports.HOOK_CONFIG_DIRS = ['Documents/Cline/Hooks', '.cline/hooks'];
const MAX_HOOK_DIR_ENTRIES = 64;
/** Directories under a home whose owner and mode are checked (others could delete evidence in them). */
const EVIDENCE_DIRS = ['.marrow/device', '.marrow/host-approvals', '.marrow/spool', '.marrow/runner-holds', '.claude', '.codex', '.cursor', '.gemini', '.codeium', '.codeium/windsurf', '.grok', '.grok/hooks', 'Documents', 'Documents/Cline', ...exports.HOOK_CONFIG_DIRS, '.cline'];
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
function probeHookConfig(fs, path, skipNonFiles = false) {
    try {
        const entry = fs.lstat(path);
        if (!entry)
            return 'absent';
        if (skipNonFiles && entry.type === 'dir')
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
function probeHookDir(fs, dir) {
    try {
        const real = (0, seatbelt_path_1.realPath)(fs, dir, { followFinal: true });
        if (real.status !== 'resolved')
            return 'unknown';
        if (!real.exists)
            return 'absent';
        const entry = fs.lstat(real.path);
        if (!entry)
            return 'absent';
        if (entry.type !== 'dir')
            return 'unknown';
        const names = fs.readdir(real.path);
        if (names.length > MAX_HOOK_DIR_ENTRIES)
            return 'unknown';
        let state = 'absent';
        for (const name of names)
            state = worst(state, probeHookConfig(fs, `${real.path}/${name}`, true));
        return state;
    }
    catch {
        return 'unknown';
    }
}
/** A directory that holds evidence: absent is fine; otherwise its real target must be a dir owned by uid, not group/world-writable. */
function probeTrustedDir(fs, dir, uid) {
    try {
        const real = (0, seatbelt_path_1.realPath)(fs, dir, { followFinal: true });
        if (real.status !== 'resolved')
            return 'unknown';
        if (!real.exists)
            return 'absent';
        const entry = fs.lstat(real.path);
        if (!entry)
            return 'absent';
        if (entry.type !== 'dir')
            return 'unknown';
        if (uid !== null && entry.uid !== uid)
            return 'unknown';
        if ((entry.mode & 0o022) !== 0)
            return 'unknown';
        return 'absent';
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
    for (const dir of exports.HOOK_CONFIG_DIRS)
        hooks = worst(hooks, probeHookDir(fs, `${home}/${dir}`));
    let dirs = probeTrustedDir(fs, home, uid);
    for (const dir of EVIDENCE_DIRS)
        dirs = worst(dirs, probeTrustedDir(fs, `${home}/${dir}`, uid));
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
        evidence_dirs: dirs === 'present' ? 'unknown' : dirs,
    };
}
/** A usable home: absolute, no `.`/`..` parts, and an existing directory other than `/` after realpath. */
function trustedHome(fs, value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.split('/').some((part) => part === '..' || part === '.'))
        return null;
    const real = (0, seatbelt_path_1.realPath)(fs, value, { followFinal: true });
    // A service user's `/` home is shared with everything on the machine.
    if (real.status !== 'resolved' || !real.exists || real.path === '/')
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
    // Env homes ($HOME ...) only tighten: probed for evidence, and one that is
    // not a trusted home is a contradiction. They never join `homes`.
    const probeHomes = [...homes];
    for (const value of input.envHomes || []) {
        const home = trustedHome(input.fs, value);
        if (home === null) {
            homeProblem = true;
            if (!reasons.includes('env_home_unusable'))
                reasons.push('env_home_unusable');
            continue;
        }
        if (!homes.includes(home)) {
            homeProblem = true;
            if (!reasons.includes('home_mismatch'))
                reasons.push('home_mismatch');
        }
        if (!probeHomes.includes(home))
            probeHomes.push(home);
    }
    // Every home named anywhere is probed: evidence in any of them counts.
    for (const home of probeHomes) {
        const probed = probeHome(input.fs, home, uid);
        for (const id of exports.ACCOUNT_EVIDENCE)
            evidence[id] = worst(evidence[id], probed[id]);
    }
    for (const file of input.extraHookConfigs || []) {
        evidence.hook_claimed_marker = worst(evidence.hook_claimed_marker, file.startsWith('/') ? probeHookConfig(input.fs, file) : 'unknown');
    }
    for (const dir of input.extraHookDirs || []) {
        evidence.hook_claimed_marker = worst(evidence.hook_claimed_marker, dir.startsWith('/') ? probeHookDir(input.fs, dir) : 'unknown');
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
/** The only environment names mode resolution reads: the key lookup's names, the strict switch and the tighten-only evidence relocations. */
const KEY_ENV_NAMES = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_SESSION_ID'];
/** Env homes 3.9.102 writes under (src/env.ts: HOME, then USERPROFILE). */
const ENV_HOME_NAMES = ['HOME', 'USERPROFILE'];
/** Env-relocated harness config: name -> files (or, for dirs, '' meaning the dir itself is scanned). */
const ENV_HOOK_FILES = {
    CODEX_HOME: ['hooks.json', 'config.toml'],
    CLAUDE_CONFIG_DIR: ['settings.json', 'settings.local.json'],
    GEMINI_CLI_SYSTEM_SETTINGS_PATH: [''],
};
const ENV_HOOK_DIRS = { CLINE_DIR: 'hooks' };
exports.MODE_ENV_NAMES = [...KEY_ENV_NAMES, 'MARROW_SEATBELT_STRICT', ...ENV_HOME_NAMES, ...Object.keys(ENV_HOOK_FILES), ...Object.keys(ENV_HOOK_DIRS)];
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
    // Only MODE_ENV_NAMES are read. None of them can select seatbelt or the
    // trusted home: the env homes and relocated configs only add evidence.
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
    const envHomes = [];
    for (const name of ENV_HOME_NAMES) {
        const value = env[name];
        // 3.9.102 uses `env.HOME || ...`: an empty value falls through to the next.
        if (typeof value === 'string' && value !== '')
            envHomes.push(value);
    }
    const extraHookConfigs = [];
    for (const [name, files] of Object.entries(ENV_HOOK_FILES)) {
        const value = env[name];
        if (typeof value !== 'string' || value.trim() === '')
            continue;
        for (const file of files)
            extraHookConfigs.push(file ? `${value.replace(/\/+$/, '')}/${file}` : value);
    }
    const extraHookDirs = [];
    for (const [name, sub] of Object.entries(ENV_HOOK_DIRS)) {
        const value = env[name];
        if (typeof value === 'string' && value.trim() !== '')
            extraHookDirs.push(`${value.replace(/\/+$/, '')}/${sub}`);
    }
    return resolveSeatbeltMode({ fs, passwdHome, argv, key, uid, strict, envHomes, extraHookConfigs, extraHookDirs });
}
//# sourceMappingURL=seatbelt-mode.js.map