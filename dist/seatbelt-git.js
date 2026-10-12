"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BASELINE_PROTECTED_BRANCHES = exports.GIT_PUSH_LONG_OPTIONS = exports.GIT_PUSH_RISKY_OPTIONS = exports.GIT_MAYBE_COMMANDS = exports.GIT_CORE_BUILTINS = exports.GIT_EXEC_ENV = exports.GIT_RELOCATING_ENV = exports.MAX_CONFIG_FILES = exports.MAX_ALIAS_STEPS = exports.MAX_ALIAS_DEPTH = exports.MAX_INCLUDE_DEPTH = exports.MAX_GIT_CONFIG_BYTES = void 0;
exports.canonicalGitKey = canonicalGitKey;
exports.parseGitConfigText = parseGitConfigText;
exports.gitExecVectors = gitExecVectors;
exports.gitRelocatingEnv = gitRelocatingEnv;
exports.discoverGitDirs = discoverGitDirs;
exports.loadGitConfig = loadGitConfig;
exports.gitConfigValues = gitConfigValues;
exports.splitGitCmdline = splitGitCmdline;
exports.parseGitInvocation = parseGitInvocation;
exports.expandGitAliases = expandGitAliases;
exports.gitLongOptionCandidates = gitLongOptionCandidates;
exports.readGitHead = readGitHead;
exports.readRemoteDefaultBranch = readRemoteDefaultBranch;
exports.isProtectedBranch = isProtectedBranch;
exports.resolvePushRefspec = resolvePushRefspec;
exports.implicitPushTargets = implicitPushTargets;
const seatbelt_path_1 = require("./seatbelt-path");
// Local git resolution for seatbelt rule S1 (spec §1.2): config from every
// scope and include, aliases (including `!sh` aliases), HEAD, the remote
// default branch and implicit push targets. Where git would pick one value
// (last one wins), these resolvers keep every candidate so the mapper can stop
// if any of them is risky: config can only make an answer stricter.
exports.MAX_GIT_CONFIG_BYTES = 1024 * 1024;
exports.MAX_INCLUDE_DEPTH = 10;
exports.MAX_ALIAS_DEPTH = 10;
/** Total alias nodes and config files visited: a planted config cannot fan out without bound. */
exports.MAX_ALIAS_STEPS = 256;
exports.MAX_CONFIG_FILES = 64;
/** Canonical config key: git compares section and variable names case-insensitively, subsections exactly. */
function canonicalGitKey(key) {
    const first = key.indexOf('.');
    const last = key.lastIndexOf('.');
    if (first < 0)
        return key.toLowerCase();
    if (first === last)
        return key.toLowerCase();
    return `${key.slice(0, first).toLowerCase()}.${key.slice(first + 1, last)}.${key.slice(last + 1).toLowerCase()}`;
}
function unquoteConfigValue(raw) {
    let out = '';
    let quoted = false;
    for (let i = 0; i < raw.length; i += 1) {
        const ch = raw[i];
        if (ch === '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (ch === '#' || ch === ';'))
            break;
        if (ch === '\\' && i + 1 < raw.length) {
            const next = raw[i + 1];
            out += next === 'n' ? '\n' : next === 't' ? '\t' : next === 'b' ? '\b' : next;
            i += 1;
            continue;
        }
        out += ch;
    }
    return quoted ? out : out.replace(/\s+$/, '');
}
/** Parses git config text into entries (git-config(1) syntax). */
function parseGitConfigText(text, source) {
    const entries = [];
    const lines = text.replace(/\\\r?\n/g, '').split(/\r?\n/);
    let section = '';
    for (const rawLine of lines) {
        let line = rawLine.trim();
        if (!line || line.startsWith('#') || line.startsWith(';'))
            continue;
        if (line.startsWith('[')) {
            const header = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(.*)$/.exec(line);
            if (!header) {
                section = '';
                continue;
            }
            const name = header[1];
            if (header[2] !== undefined)
                section = `${name.toLowerCase()}.${header[2].replace(/\\(.)/g, '$1')}`;
            else {
                // [section.sub] (deprecated form): subsection is lower-cased by git.
                const dot = name.indexOf('.');
                section = dot < 0 ? name.toLowerCase() : `${name.slice(0, dot).toLowerCase()}.${name.slice(dot + 1).toLowerCase()}`;
            }
            line = header[3].trim();
            if (!line || line.startsWith('#') || line.startsWith(';'))
                continue;
        }
        if (!section)
            continue;
        const pair = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/.exec(line);
        if (!pair)
            continue;
        const value = pair[2] === undefined ? 'true' : unquoteConfigValue(pair[2]);
        entries.push({ key: `${section}.${pair[1].toLowerCase()}`, value, source });
    }
    return entries;
}
function readSmall(fs, path) {
    try {
        const entry = fs.lstat(path);
        if (!entry)
            return { status: 'absent' };
        if (entry.type === 'symlink') {
            const real = (0, seatbelt_path_1.realPath)(fs, path, { followFinal: true });
            if (real.status !== 'resolved' || !real.exists)
                return { status: 'unknown' };
            return readSmall(fs, real.path);
        }
        const text = fs.readFile(path, exports.MAX_GIT_CONFIG_BYTES);
        return text === null ? { status: 'unknown' } : { status: 'ok', text };
    }
    catch {
        return { status: 'unknown' };
    }
}
function joinPath(dir, rel) {
    return rel.startsWith('/') ? rel : `${dir.replace(/\/+$/, '')}/${rel}`;
}
function dirname(path) {
    const cut = path.replace(/\/+$/, '').lastIndexOf('/');
    return cut <= 0 ? '/' : path.slice(0, cut);
}
/**
 * Env that makes git use a different repository, config or work tree than
 * discovery from the cwd finds. The resolvers do not model these: any of
 * them set (in the hook env or as a prefix assignment of the git command)
 * makes discovery and config 'unknown'/incomplete, never a definite answer.
 */
exports.GIT_RELOCATING_ENV = ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_CEILING_DIRECTORIES', 'GIT_DISCOVERY_ACROSS_FILESYSTEM', 'GIT_NAMESPACE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_EXEC_PATH', 'GIT_TEMPLATE_DIR'];
/**
 * Env and config that make git run another program (ssh, pager, editor,
 * diff/merge drivers, credential helpers, hooks, fsmonitor). The mapper (U2)
 * treats any of them present as a shell command it cannot see: stop.
 */
exports.GIT_EXEC_ENV = ['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_PROXY_COMMAND', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_PAGER', 'PAGER', 'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'EDITOR', 'VISUAL', 'GIT_EXTERNAL_DIFF', 'GIT_EXEC_PATH'];
const GIT_EXEC_CONFIG = /^(?:core\.(?:sshcommand|pager|editor|fsmonitor|hookspath|gitproxy|askpass)|sequence\.editor|diff\.external|diff\..+\.(?:command|textconv)|merge\..+\.driver|filter\..+\.(?:clean|smudge|process)|credential(?:\..+)?\.helper|pager\..+|gpg(?:\..+)?\.program|uploadpack\.packobjectshook|remote\..+\.(?:receivepack|uploadpack|vcs)|url\..+\.insteadof|protocol\..+\.allow|http\..*proxy|alias\..+)$/;
/**
 * Names of exec-capable env vars and config keys present (alias.* with a
 * leading `!` only). Names only, never values. `env` is what the agent set:
 * the git command's prefix assignments and earlier `export`s in the same
 * command line, not the hook's own environment (the user's EDITOR/PAGER).
 */
function gitExecVectors(config, env) {
    const out = new Set();
    for (const name of exports.GIT_EXEC_ENV)
        if (env && env[name] !== undefined)
            out.add(name);
    for (const entry of config.entries) {
        if (!GIT_EXEC_CONFIG.test(entry.key))
            continue;
        if (entry.key.startsWith('alias.') && !entry.value.startsWith('!'))
            continue;
        // Subsections (remote names, URLs that may carry credentials) are never returned.
        const first = entry.key.indexOf('.');
        const last = entry.key.lastIndexOf('.');
        if (entry.key.startsWith('alias.'))
            out.add('alias.*');
        else
            out.add(first === last ? entry.key : `${entry.key.slice(0, first)}.*.${entry.key.slice(last + 1)}`);
    }
    return [...out];
}
/** The relocating names present in env (any value, even empty, counts). */
function gitRelocatingEnv(env) {
    if (!env)
        return [];
    return exports.GIT_RELOCATING_ENV.filter((name) => env[name] !== undefined);
}
/** git's is_git_directory: HEAD plus objects/ and refs/ (a bare repo, or cwd inside a .git dir). */
function isGitDirectory(fs, dir) {
    try {
        const base = dir === '/' ? '' : dir;
        const head = fs.lstat(`${base}/HEAD`);
        if (!head || (head.type !== 'file' && head.type !== 'symlink'))
            return false;
        const objects = fs.lstat(`${base}/objects`);
        const refs = fs.lstat(`${base}/refs`);
        return Boolean(objects && refs && objects.type !== 'file' && refs.type !== 'file');
    }
    catch {
        return 'unknown';
    }
}
/**
 * Finds the git dirs for a working directory the way git's discovery does: at
 * each level a `.git` directory, a `.git` file (`gitdir:`) plus `commondir`,
 * or the level itself as a git directory (bare repo). With relocating env
 * (`env`: hook env merged with the command's prefix assignments) the answer
 * is 'unknown'.
 */
function discoverGitDirs(fs, cwd, env) {
    if (gitRelocatingEnv(env).length > 0)
        return 'unknown';
    const real = (0, seatbelt_path_1.realPath)(fs, cwd, { followFinal: true });
    if (real.status !== 'resolved')
        return 'unknown';
    let dir = real.path;
    for (;;) {
        const dotGit = dir === '/' ? '/.git' : `${dir}/.git`;
        let entry;
        try {
            entry = fs.lstat(dotGit);
        }
        catch {
            return 'unknown';
        }
        if (entry?.type === 'dir')
            return { gitDir: dotGit, commonDir: commonDirOf(fs, dotGit) };
        if (entry?.type === 'file') {
            const pointer = readSmall(fs, dotGit);
            if (pointer.status !== 'ok')
                return 'unknown';
            const match = /^gitdir:\s*(.+?)\s*$/m.exec(pointer.text);
            if (!match)
                return 'unknown';
            const gitDir = joinPath(dir, match[1]);
            return { gitDir, commonDir: commonDirOf(fs, gitDir) };
        }
        if (entry)
            return 'unknown';
        const bare = isGitDirectory(fs, dir);
        if (bare === 'unknown')
            return 'unknown';
        if (bare)
            return { gitDir: dir, commonDir: commonDirOf(fs, dir) };
        if (dir === '/')
            return null;
        dir = dirname(dir);
    }
}
function commonDirOf(fs, gitDir) {
    const pointer = readSmall(fs, `${gitDir}/commondir`);
    return pointer.status === 'ok' && pointer.text.trim() ? joinPath(gitDir, pointer.text.trim()) : gitDir;
}
const DEFAULT_SYSTEM_FILES = ['/etc/gitconfig', '/usr/local/etc/gitconfig', '/opt/homebrew/etc/gitconfig', '/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig'];
/** Parses GIT_CONFIG_PARAMETERS ('key'='value' pairs, as git writes them). Null when malformed. */
function parseConfigParameters(raw) {
    const out = [];
    const re = /\s*'((?:[^']|'\\'')*)'(?:=(?:'((?:[^']|'\\'')*)'))?/y;
    let index = 0;
    while (index < raw.length) {
        if (/^\s*$/.test(raw.slice(index)))
            break;
        re.lastIndex = index;
        const match = re.exec(raw);
        if (!match)
            return null;
        const unq = (s) => s.replace(/'\\''/g, "'");
        const key = unq(match[1]);
        if (match[2] !== undefined)
            out.push([key, unq(match[2])]);
        else {
            const eq = key.indexOf('=');
            out.push(eq < 0 ? [key, 'true'] : [key.slice(0, eq), key.slice(eq + 1)]);
        }
        index = re.lastIndex;
    }
    return out;
}
/**
 * Loads config from every scope git reads, plus every include and includeIf
 * (conditions are not evaluated: including more can only add candidates).
 */
function loadGitConfig(fs, sources) {
    const entries = [];
    let incomplete = false;
    const env = sources.env || {};
    const home = sources.home;
    const expandIncludePath = (path, from) => {
        if (path.startsWith('~/'))
            return home ? `${home}${path.slice(1)}` : null;
        if (path.startsWith('~'))
            return null;
        return path.startsWith('/') ? path : joinPath(dirname(from), path);
    };
    const addEntries = (list, from, depth) => {
        for (const entry of list) {
            entries.push(entry);
            if (!/^include(?:if\..*)?\.path$/.test(entry.key))
                continue;
            if (depth >= exports.MAX_INCLUDE_DEPTH) {
                incomplete = true;
                continue;
            }
            const target = from === null
                ? (entry.value.startsWith('/') ? entry.value : entry.value.startsWith('~/') && home ? `${home}${entry.value.slice(1)}` : null)
                : expandIncludePath(entry.value, from);
            if (!target) {
                incomplete = true;
                continue;
            }
            addFile(target, depth + 1);
        }
    };
    let files = 0;
    const addFile = (path, depth) => {
        if (!path.startsWith('/')) {
            incomplete = true;
            return;
        }
        files += 1;
        if (files > exports.MAX_CONFIG_FILES) {
            incomplete = true;
            return;
        }
        const read = readSmall(fs, path);
        if (read.status === 'absent')
            return;
        if (read.status === 'unknown') {
            incomplete = true;
            return;
        }
        addEntries(parseGitConfigText(read.text, path), path, depth);
    };
    // Env-named config files are added to the defaults, never substituted for
    // them (a superset of candidates). A relative one depends on the command's
    // cwd, which is not modelled.
    const addEnvFile = (value) => {
        if (value === undefined || value === '')
            return;
        if (!value.startsWith('/'))
            incomplete = true;
        else
            addFile(value, 0);
    };
    if (gitRelocatingEnv(env).length > 0)
        incomplete = true;
    // GIT_CONFIG_NOSYSTEM is ignored: reading the system files anyway can only add candidates.
    for (const file of sources.systemFiles || DEFAULT_SYSTEM_FILES)
        addFile(file, 0);
    addEnvFile(env.GIT_CONFIG_SYSTEM);
    if (home) {
        addFile(`${home}/.config/git/config`, 0);
        addFile(`${home}/.gitconfig`, 0);
    }
    else {
        incomplete = true;
    }
    // git reads $HOME and $XDG_CONFIG_HOME, not the trusted home: add theirs, and
    // a different HOME also changes `~/` in include paths, so it is incomplete.
    if (env.HOME !== undefined && env.HOME !== home) {
        incomplete = true;
        if (env.HOME.startsWith('/')) {
            addFile(`${env.HOME.replace(/\/+$/, '')}/.gitconfig`, 0);
            if (env.XDG_CONFIG_HOME === undefined)
                addFile(`${env.HOME.replace(/\/+$/, '')}/.config/git/config`, 0);
        }
    }
    if (env.XDG_CONFIG_HOME !== undefined && env.XDG_CONFIG_HOME !== '') {
        if (env.XDG_CONFIG_HOME.startsWith('/'))
            addFile(`${env.XDG_CONFIG_HOME.replace(/\/+$/, '')}/git/config`, 0);
        else
            incomplete = true;
    }
    addEnvFile(env.GIT_CONFIG_GLOBAL);
    addEnvFile(env.GIT_CONFIG);
    if (sources.dirs) {
        addFile(`${sources.dirs.commonDir}/config`, 0);
        addFile(`${sources.dirs.gitDir}/config.worktree`, 0);
    }
    const fromEnv = [];
    const count = env.GIT_CONFIG_COUNT;
    if (count !== undefined) {
        const n = /^\d{1,4}$/.test(count) ? Number(count) : NaN;
        if (!Number.isFinite(n))
            incomplete = true;
        for (let i = 0; i < (Number.isFinite(n) ? n : 0); i += 1) {
            const key = env[`GIT_CONFIG_KEY_${i}`];
            const value = env[`GIT_CONFIG_VALUE_${i}`];
            if (key === undefined || value === undefined)
                incomplete = true;
            else
                fromEnv.push([key, value]);
        }
    }
    if (env.GIT_CONFIG_PARAMETERS) {
        const parsed = parseConfigParameters(env.GIT_CONFIG_PARAMETERS);
        if (parsed)
            fromEnv.push(...parsed);
        else
            incomplete = true;
    }
    const command = [...fromEnv, ...(sources.commandConfig || [])];
    addEntries(command.map(([key, value]) => ({ key: canonicalGitKey(key), value, source: 'command' })), null, 0);
    return { entries, incomplete };
}
/** Every value of a key across all scopes, in load order (git uses the last). */
function gitConfigValues(config, key) {
    const want = canonicalGitKey(key);
    return config.entries.filter((entry) => entry.key === want).map((entry) => entry.value);
}
/**
 * Built-ins of every supported git (≥2.20): git runs these before it looks at
 * aliases, so an alias with one of these names never applies.
 */
exports.GIT_CORE_BUILTINS = new Set('add am annotate apply archive bisect blame branch bundle cat-file check-attr check-ignore check-mailmap check-ref-format checkout checkout-index cherry cherry-pick clean clone column commit commit-graph commit-tree config count-objects credential credential-cache credential-cache--daemon credential-store describe diff diff-files diff-index diff-tree difftool fast-export fast-import fetch fetch-pack fmt-merge-msg for-each-ref format-patch fsck fsck-objects gc get-tar-commit-id grep hash-object help index-pack init init-db interpret-trailers log ls-files ls-remote ls-tree mailinfo mailsplit merge merge-base merge-file merge-index merge-ours merge-recursive merge-recursive-ours merge-recursive-theirs merge-subtree merge-tree mktag mktree multi-pack-index mv name-rev notes pack-objects pack-refs patch-id pickaxe prune prune-packed pull push range-diff read-tree rebase receive-pack reflog remote remote-ext remote-fd repack replace rerere reset rev-list rev-parse revert rm send-pack shortlog show show-branch show-index show-ref stage stash status stripspace symbolic-ref tag unpack-file unpack-objects update-index update-ref update-server-info upload-archive upload-pack var verify-commit verify-pack verify-tag version worktree write-tree'.split(' '));
/**
 * Commands that shadow an alias only when present: exec-path programs that may
 * not be installed (git-lfs, git-svn ...) and built-ins newer than 2.20. For
 * these the alias is kept as a candidate next to the command itself.
 */
exports.GIT_MAYBE_COMMANDS = new Set('diagnose bugreport for-each-repo maintenance hook fsmonitor--daemon sparse-checkout switch restore replay refs checkout--worker submodule--helper upload-archive--writer daemon difftool--helper filter-branch http-backend http-fetch http-push imap-send instaweb merge-octopus merge-one-file merge-resolve mergetool quiltimport whatchanged pack-redundant remote-ftp remote-ftps remote-http remote-https request-pull send-email sh-i18n--envsubst shell submodule subtree web--browse gui citool svn p4 lfs'.split(' '));
/** git's split_cmdline: whitespace-separated words with single/double quotes and backslash escapes. Null on an unclosed quote. */
function splitGitCmdline(value) {
    const words = [];
    let word = '';
    let inWord = false;
    let quote = null;
    for (let i = 0; i < value.length; i += 1) {
        const ch = value[i];
        if (quote) {
            if (ch === quote)
                quote = null;
            else if (ch === '\\' && quote === '"' && i + 1 < value.length)
                word += value[++i];
            else
                word += ch;
            continue;
        }
        if (/\s/.test(ch)) {
            if (inWord)
                words.push(word);
            word = '';
            inWord = false;
            continue;
        }
        inWord = true;
        if (ch === '"' || ch === "'")
            quote = ch;
        else if (ch === '\\' && i + 1 < value.length)
            word += value[++i];
        else
            word += ch;
    }
    if (quote)
        return null;
    if (inWord)
        words.push(word);
    return words;
}
const GLOBAL_FLAGS = new Set(['-p', '--paginate', '-P', '--no-pager', '--bare', '--no-replace-objects', '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs', '--no-optional-locks', '--no-advice', '--no-lazy-fetch']);
/** Splits `git <global options> <subcommand> <args>` (git.c handle_options: exact option names only). */
function parseGitInvocation(argv) {
    const out = { config: [], directories: [], unknownGlobals: [], configEnv: [], subcommand: null, args: [] };
    let i = 0;
    while (i < argv.length) {
        const arg = argv[i];
        if (!arg.startsWith('-') || arg === '-')
            break;
        if (arg === '--') {
            i += 1;
            break;
        }
        if (arg === '-c' || arg === '--config-env' || arg === '-C' || arg === '--git-dir' || arg === '--work-tree' || arg === '--namespace' || arg === '--exec-path' || arg === '--super-prefix' || arg === '--attr-source') {
            const value = argv[i + 1];
            if (value === undefined) {
                out.unknownGlobals.push(arg);
                i += 1;
                continue;
            }
            if (arg === '-c') {
                const eq = value.indexOf('=');
                out.config.push(eq < 0 ? [value, 'true'] : [value.slice(0, eq), value.slice(eq + 1)]);
            }
            else if (arg === '--config-env') {
                const eq = value.indexOf('=');
                if (eq < 0)
                    out.unknownGlobals.push(arg);
                else
                    out.configEnv.push([value.slice(0, eq), value.slice(eq + 1)]);
            }
            else if (arg === '-C' || arg === '--git-dir' || arg === '--work-tree')
                out.directories.push(value);
            else if (arg !== '--namespace' && arg !== '--attr-source')
                out.unknownGlobals.push(arg);
            i += 2;
            continue;
        }
        const eqForm = /^(--git-dir|--work-tree|--namespace|--exec-path|--super-prefix|--config-env|--attr-source)=(.*)$/s.exec(arg);
        if (eqForm) {
            if (eqForm[1] === '--git-dir' || eqForm[1] === '--work-tree')
                out.directories.push(eqForm[2]);
            else if (eqForm[1] === '--config-env') {
                const eq = eqForm[2].indexOf('=');
                if (eq < 0)
                    out.unknownGlobals.push(arg);
                else
                    out.configEnv.push([eqForm[2].slice(0, eq), eqForm[2].slice(eq + 1)]);
            }
            else if (eqForm[1] !== '--namespace' && eqForm[1] !== '--attr-source')
                out.unknownGlobals.push(eqForm[1]);
            i += 1;
            continue;
        }
        if (!GLOBAL_FLAGS.has(arg) && arg !== '--exec-path')
            out.unknownGlobals.push(arg);
        i += 1;
    }
    out.subcommand = i < argv.length ? argv[i] : null;
    out.args = argv.slice(i + 1);
    return out;
}
/**
 * Expands git aliases the way git would, keeping every candidate: each
 * definition of alias.<name> from any scope or include, and `-c alias.*` from
 * the command. Core built-in names are never expanded (git ignores aliases
 * for them); maybe-installed commands keep both answers. `!` aliases become shell commands with the remaining args appended.
 */
function expandGitAliases(argv, context) {
    const results = [];
    let steps = 0;
    const walk = (invocation, inherited, seen, depth) => {
        steps += 1;
        if (steps > exports.MAX_ALIAS_STEPS) {
            if (!results.some((r) => r.kind === 'unknown' && r.reason === 'too_deep'))
                results.push({ kind: 'unknown', reason: 'too_deep' });
            return;
        }
        const extra = [...inherited, ...invocation.config];
        for (const [key, envName] of invocation.configEnv) {
            const value = context.env?.[envName];
            if (value === undefined) {
                results.push({ kind: 'unknown', reason: 'dynamic_config' });
                return;
            }
            extra.push([key, value]);
        }
        const merged = { ...invocation, config: extra };
        const name = invocation.subcommand;
        // -C / --git-dir / --work-tree, or relocating env: the config this expansion
        // used is not the one git reads, so no answer here is definite.
        if (invocation.directories.length > 0 || gitRelocatingEnv(context.env).length > 0) {
            if (!results.some((r) => r.kind === 'unknown' && r.reason === 'relocated'))
                results.push({ kind: 'unknown', reason: 'relocated' });
        }
        if (name === null || exports.GIT_CORE_BUILTINS.has(name)) {
            results.push({ kind: 'git', invocation: merged });
            return;
        }
        if (exports.GIT_MAYBE_COMMANDS.has(name))
            results.push({ kind: 'git', invocation: merged });
        if (depth >= exports.MAX_ALIAS_DEPTH) {
            results.push({ kind: 'unknown', reason: 'too_deep' });
            return;
        }
        const lowered = name.toLowerCase();
        if (seen.includes(lowered)) {
            results.push({ kind: 'unknown', reason: 'loop' });
            return;
        }
        const want = `alias.${lowered}`;
        const definitions = [
            ...context.config.entries.filter((entry) => entry.key === want).map((entry) => entry.value),
            ...extra.filter(([key]) => canonicalGitKey(key) === want).map(([, value]) => value),
        ];
        if (definitions.length === 0) {
            if (!exports.GIT_MAYBE_COMMANDS.has(name))
                results.push({ kind: 'unknown', reason: context.config.incomplete ? 'config_incomplete' : 'not_found' });
            return;
        }
        // Config that could not be read in full may hold a later definition (git uses the last).
        if (context.config.incomplete && !results.some((r) => r.kind === 'unknown' && r.reason === 'config_incomplete'))
            results.push({ kind: 'unknown', reason: 'config_incomplete' });
        for (const definition of new Set(definitions)) {
            if (definition.startsWith('!')) {
                results.push({ kind: 'shell', command: definition.slice(1), args: invocation.args });
                continue;
            }
            const words = splitGitCmdline(definition);
            if (!words || words.length === 0) {
                results.push({ kind: 'unknown', reason: 'unparsed' });
                continue;
            }
            // An alias may start with global options (`-c x=y push`): re-parse them.
            walk(parseGitInvocation([...words, ...invocation.args]), extra, [...seen, lowered], depth + 1);
        }
    };
    walk(parseGitInvocation(argv), [], [], 0);
    return results;
}
/**
 * `git push` long options that can rewrite or delete remote refs (S1): the
 * mapper treats a candidate in this set as risky. `prune` deletes remote
 * branches that have no local counterpart under `--all`/a pattern refspec.
 */
exports.GIT_PUSH_RISKY_OPTIONS = ['force', 'force-with-lease', 'force-if-includes', 'mirror', 'delete', 'prune'];
/** Long options of `git push` (builtin/push.c), for prefix abbreviation. */
exports.GIT_PUSH_LONG_OPTIONS = ['repo', 'all', 'branches', 'mirror', 'delete', 'tags', 'dry-run', 'porcelain', 'force', 'force-with-lease', 'force-if-includes', 'recurse-submodules', 'thin', 'receive-pack', 'exec', 'set-upstream', 'progress', 'prune', 'no-verify', 'verify', 'follow-tags', 'signed', 'atomic', 'push-option', 'ipv4', 'ipv6', 'quiet', 'verbose'];
const GIT_PUSH_NEGATABLE = new Set(['all', 'branches', 'mirror', 'delete', 'tags', 'dry-run', 'porcelain', 'force', 'force-with-lease', 'force-if-includes', 'recurse-submodules', 'thin', 'set-upstream', 'progress', 'prune', 'follow-tags', 'signed', 'atomic', 'push-option', 'quiet', 'verbose']);
/**
 * Every long option a `--name[=value]` argument can mean under git's unique
 * prefix abbreviation. Exact names win; an ambiguous prefix keeps all matches
 * (git would refuse, but the mapper must stop if any match is risky). Negated
 * forms are returned as `no-<name>`.
 */
function gitLongOptionCandidates(arg, options = exports.GIT_PUSH_LONG_OPTIONS, negatable = GIT_PUSH_NEGATABLE) {
    if (!arg.startsWith('--') || arg === '--')
        return [];
    const name = arg.slice(2).split('=')[0].toLowerCase();
    if (options.includes(name))
        return [name];
    const negated = name.startsWith('no-') ? name.slice(3) : null;
    if (negated !== null && negatable.has(negated) && options.includes(negated))
        return [`no-${negated}`];
    const matches = options.filter((option) => option.startsWith(name));
    if (negated !== null)
        for (const option of options)
            if (negatable.has(option) && option.startsWith(negated))
                matches.push(`no-${option}`);
    // `--no-` alone, or `--n`, may prefix every negation.
    if ('no-'.startsWith(name) && name.length > 0)
        for (const option of negatable)
            matches.push(`no-${option}`);
    return [...new Set(matches)];
}
function readGitHead(fs, dirs) {
    const head = readSmall(fs, `${dirs.gitDir}/HEAD`);
    if (head.status !== 'ok')
        return { kind: 'unknown' };
    const match = /^ref:\s*refs\/heads\/(\S+)\s*$/.exec(head.text.trim());
    if (match)
        return { kind: 'branch', branch: match[1] };
    if (/^[0-9a-f]{40,64}$/.test(head.text.trim()))
        return { kind: 'detached' };
    return { kind: 'unknown' };
}
/** The remote's default branch from refs/remotes/<remote>/HEAD; null when absent; 'unknown' when unreadable. */
function readRemoteDefaultBranch(fs, dirs, remote) {
    if (!/^[A-Za-z0-9._-]+$/.test(remote) || remote.includes('..'))
        return 'unknown';
    const ref = readSmall(fs, `${dirs.commonDir}/refs/remotes/${remote}/HEAD`);
    if (ref.status === 'absent')
        return null;
    if (ref.status !== 'ok')
        return 'unknown';
    const match = new RegExp(`^ref:\\s*refs/remotes/${remote.replace(/[.]/g, '\\.')}/(\\S+)\\s*$`).exec(ref.text.trim());
    return match ? match[1] : 'unknown';
}
exports.BASELINE_PROTECTED_BRANCHES = ['main', 'master', 'production', 'prod', 'release', 'release/*', 'releases/*', 'live', 'stable', 'trunk', 'hotfix/*', 'deploy', 'deploy/*', 'gh-pages'];
/** PB membership (§1.2). Compared case-insensitively; an unresolved target is protected. */
function isProtectedBranch(branch, extra = []) {
    if (branch === null)
        return true;
    const name = branch.replace(/^refs\/heads\//, '').toLowerCase();
    if (!name)
        return true;
    return [...exports.BASELINE_PROTECTED_BRANCHES, ...extra].some((pattern) => {
        const p = pattern.toLowerCase();
        return p.endsWith('/*') ? name.startsWith(p.slice(0, -1)) && name.length > p.length - 1 : name === p;
    });
}
const AMBIGUOUS_REF_PREFIX = /^(?:refs|heads|tags|remotes)(?:\/|$)/i;
/** Resolves one push refspec's destination against HEAD and the upstream config. */
function resolvePushRefspec(refspec, head) {
    let spec = refspec;
    const force = spec.startsWith('+');
    if (force)
        spec = spec.slice(1);
    if (spec === ':')
        return { force, delete: false, destination: null, all: true };
    const colon = spec.indexOf(':');
    const src = colon < 0 ? spec : spec.slice(0, colon);
    const dst = colon < 0 ? null : spec.slice(colon + 1);
    const del = colon >= 0 && src === '';
    if (spec.includes('*'))
        return { force, delete: del, destination: null, all: true };
    // git matches a short name with ref_rev_parse_rules (`%s`, `refs/%s`,
    // `refs/tags/%s`, `refs/heads/%s`, `refs/remotes/%s`, `refs/remotes/%s/HEAD`):
    // `heads/main` is refs/heads/main, `tags/x` or `remotes/x` may name a
    // branch too. Any short name whose first part is one of those namespaces
    // (compared case-insensitively: loose refs on a case-insensitive volume)
    // has more than one reading, so it is unresolved, which is protected.
    const name = (ref) => {
        if (ref === 'HEAD' || ref === '@')
            return head.kind === 'branch' ? head.branch : null;
        if (/[$`~^:?*[\\\s{}]|@\{|\.\.|\/\/|^\/|\/$|\.lock(?:\/|$)/.test(ref))
            return null;
        if (ref.startsWith('refs/heads/')) {
            const branch = ref.slice('refs/heads/'.length);
            return branch && !AMBIGUOUS_REF_PREFIX.test(branch) ? branch : null;
        }
        if (/^refs\//i.test(ref))
            return null;
        if (AMBIGUOUS_REF_PREFIX.test(ref) || /^(?:head|fetch_head|orig_head|merge_head)$/i.test(ref))
            return null;
        return ref || null;
    };
    return { force, delete: del, destination: dst !== null ? name(dst) : name(src), all: false };
}
/**
 * Targets of `git push` with no refspec (and optionally no remote), as the
 * union of every config candidate: remote.<r>.push, push.default and the
 * branch's upstream.
 */
function implicitPushTargets(config, head, remote) {
    const out = { branches: [], all: false, unknown: config.incomplete, forceFromConfig: false, mirror: false, remotes: [] };
    const current = head.kind === 'branch' ? head.branch : null;
    if (remote)
        out.remotes.push(remote);
    else {
        const candidates = current
            ? [...gitConfigValues(config, `branch.${current}.pushremote`), ...gitConfigValues(config, 'remote.pushdefault'), ...gitConfigValues(config, `branch.${current}.remote`)]
            : [...gitConfigValues(config, 'remote.pushdefault')];
        out.remotes.push(...new Set(candidates.length > 0 ? candidates : ['origin']));
    }
    for (const r of out.remotes) {
        if (gitConfigValues(config, `remote.${r}.mirror`).some((v) => !/^(false|no|off|0)$/i.test(v)))
            out.mirror = true;
        const refspecs = gitConfigValues(config, `remote.${r}.push`);
        for (const refspec of refspecs) {
            const resolved = resolvePushRefspec(refspec, head);
            if (resolved.force)
                out.forceFromConfig = true;
            if (resolved.all)
                out.all = true;
            else if (resolved.destination === null)
                out.unknown = true;
            else
                out.branches.push(resolved.destination);
        }
    }
    const defaults = gitConfigValues(config, 'push.default');
    for (const mode of defaults.length > 0 ? defaults : ['simple']) {
        const m = mode.toLowerCase();
        if (m === 'nothing')
            continue;
        if (m === 'matching') {
            out.all = true;
            continue;
        }
        if (!current) {
            out.unknown = true;
            continue;
        }
        out.branches.push(current);
        if (m === 'upstream' || m === 'tracking' || m === 'simple') {
            for (const merge of gitConfigValues(config, `branch.${current}.merge`)) {
                const upstream = merge.startsWith('refs/heads/') ? merge.slice('refs/heads/'.length) || null : null;
                if (upstream)
                    out.branches.push(upstream);
                else
                    out.unknown = true;
            }
        }
        else if (m !== 'current')
            out.unknown = true;
    }
    out.branches = [...new Set(out.branches)];
    return out;
}
//# sourceMappingURL=seatbelt-git.js.map