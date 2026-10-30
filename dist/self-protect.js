"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.protectedMention = protectedMention;
exports.selfProtectKind = selfProtectKind;
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const hook_tool_policy_1 = require("./hook-tool-policy");
const BEFORE = String.raw `(?:^|[/\s"'=:~}])`;
const CONTROL_FILES = [
    new RegExp(`${BEFORE}\\.marrow(?![A-Za-z0-9_.-])`, 'i'),
    /\.claude\/settings[^/\s"']*\.json/i,
    /\.(?:codex|cursor|windsurf)\/hooks\.json/i,
    /\.grok\/hooks(?![A-Za-z0-9_-])/i,
    /\.gemini\/settings\.json/i,
];
const PERSISTENCE_FILES = [
    new RegExp(`${BEFORE}\\.(?:bashrc|bash_profile|bash_aliases|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|zlogout)(?![A-Za-z0-9_-])`, 'i'),
    /\.config\/fish(?![A-Za-z0-9_-])/i,
    /\.claude\/shell-snapshots(?![A-Za-z0-9_-])/i,
    /\/var\/spool\/cron/i,
    /\/etc\/cron/i,
    /\.config\/systemd(?![A-Za-z0-9_-])/i,
];
// Programs that only read their operands: naming a protected file to one of them is not a write.
const READING_PROGRAMS = new Set([
    'cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'stat', 'file', 'wc', 'diff', 'cmp', 'du', 'echo', 'printf',
    'test', '[', 'readlink', 'realpath', 'basename', 'dirname', 'sha256sum', 'sha1sum', 'md5sum', 'which', 'type', 'jq', 'shellcheck', 'source', '.', 'pwd',
]);
// Programs that only read or print unless one of their writing flags is given (`prettier --check FILE`, `tree DIR`): naming a protected
// file to them is not a write. A writing flag, or an arg the table does not know how to read, keeps the word in the scan.
const READING_UNLESS = {
    prettier: /^(?:--write|-w|--cache(?:-[a-z]+)?(?:=.*)?)$/,
    tree: /^(?:-[A-Za-z]*o.*|--output(?:=.*)?)$/,
};
const RUNNERS = new Set(['npx', 'pnpx', 'bunx']);
function innerProgram(program, args) {
    let name = program;
    let rest = args;
    if ((name === 'pnpm' || name === 'npm') && rest[0] === 'exec') {
        name = 'npx';
        rest = rest.slice(1);
    }
    if (!RUNNERS.has(name))
        return { program, args };
    let at = 0;
    while (at < rest.length && /^-[A-Za-z-]*$/.test(rest[at]))
        at += 1;
    return at < rest.length ? { program: baseName(rest[at]), args: rest.slice(at + 1) } : { program, args };
}
function readsOnly(program, args) {
    const inner = innerProgram(program, args);
    if (READING_PROGRAMS.has(program) || READING_PROGRAMS.has(inner.program))
        return true;
    const writing = READING_UNLESS[inner.program];
    return writing !== undefined && !inner.args.some((arg) => writing.test(arg));
}
// A folder a host keeps hooks settings in: moving into it is held, so a later relative write there cannot slip past the path test.
const HOST_CONFIG_FOLDER = /\.(?:claude|codex|cursor|windsurf|gemini|grok)(?:\/(?:hooks|shell-snapshots))?\/?$/i;
const FIND_WRITES = /^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/;
/** The kind of protected file a path or word names, or null. Control files win over persistence files. */
function protectedMention(text) {
    if (CONTROL_FILES.some((pattern) => pattern.test(text)))
        return 'marrow-control';
    if (PERSISTENCE_FILES.some((pattern) => pattern.test(text)))
        return 'persistence';
    return null;
}
function home() {
    return process.env.HOME || (0, node_os_1.homedir)();
}
function resolvedPaths(raw, cwd) {
    const expanded = raw === '~' ? home() : raw.startsWith('~/') ? (0, node_path_1.join)(home(), raw.slice(2))
        : raw.startsWith('$HOME/') ? (0, node_path_1.join)(home(), raw.slice(6)) : raw.startsWith('${HOME}/') ? (0, node_path_1.join)(home(), raw.slice(8)) : raw;
    const base = (0, node_path_1.isAbsolute)(expanded) ? expanded : cwd ? (0, node_path_1.join)(cwd, expanded) : expanded;
    const lexical = (0, node_path_1.normalize)(base);
    const paths = [lexical];
    // A link (or a link in a parent folder) can lead a harmless-looking name to a protected file: judge where it really points as well.
    try {
        let existing = lexical;
        const tail = [];
        while (existing.length > 1 && !(0, node_fs_1.existsSync)(existing)) {
            tail.unshift(existing.slice((0, node_path_1.dirname)(existing).length + 1));
            existing = (0, node_path_1.dirname)(existing);
        }
        const real = (0, node_path_1.join)((0, node_fs_1.realpathSync)(existing), ...tail);
        if (real !== lexical)
            paths.push(real);
    }
    catch { /* an unreadable path is judged by its text only */ }
    return paths;
}
function pathKind(raw, cwd) {
    let found = null;
    for (const candidate of [raw, ...resolvedPaths(raw, cwd)]) {
        const kind = protectedMention(candidate);
        if (kind === 'marrow-control')
            return kind;
        if (kind)
            found = kind;
    }
    return found;
}
function crontabWrites(args) {
    // Only a plain listing (`crontab -l`, optionally for a user) is a read; `-`, a file, -e and -r all replace or edit the table.
    const rest = args.filter((arg, index) => arg !== '-u' && args[index - 1] !== '-u');
    return !(rest.length === 1 && rest[0] === '-l');
}
function baseName(word) {
    const cut = word.lastIndexOf('/');
    return cut < 0 ? word : word.slice(cut + 1);
}
function shellKind(command) {
    const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
    // A command the parser cannot read (heredoc, substitution, brace group) is judged by its whole text.
    if (!segments)
        return protectedMention(command);
    let persistence = null;
    const take = (kind) => {
        if (kind === 'marrow-control')
            return kind;
        if (kind)
            persistence = kind;
        return null;
    };
    for (const segment of segments) {
        for (const output of segment.outputs) {
            const kind = take(protectedMention(output));
            if (kind)
                return kind;
        }
        let at = 0;
        while (at < segment.words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(segment.words[at]))
            at += 1;
        const program = at < segment.words.length ? baseName(segment.words[at]) : '';
        const args = segment.words.slice(at + 1);
        if (program === 'crontab' && crontabWrites(args)) {
            const kind = take('persistence');
            if (kind)
                return kind;
        }
        if ((program === 'cd' || program === 'pushd') && args.some((arg) => HOST_CONFIG_FOLDER.test(arg)))
            return 'marrow-control';
        if (readsOnly(program, args))
            continue;
        if (program === 'find' && !args.some((arg) => FIND_WRITES.test(arg)))
            continue;
        for (const word of segment.words) {
            const kind = take(protectedMention(word));
            if (kind)
                return kind;
        }
    }
    return persistence;
}
/**
 * The kind of protected file a mutating call touches, or null. `cwd` resolves relative targets. Call it only for a call that is not
 * read-only: a Read of ~/.bashrc stays a read.
 */
function selfProtectKind(event, cwd) {
    if ((0, hook_tool_policy_1.isShellTextTool)(event)) {
        const input = event.tool_input && typeof event.tool_input === 'object' ? event.tool_input : {};
        const texts = typeof event.tool_input === 'string' ? [event.tool_input]
            : ['command', 'cmd', 'script'].map((key) => input[key]).filter((value) => typeof value === 'string' && value.length > 0);
        let found = null;
        for (const text of texts) {
            const kind = shellKind(text);
            if (kind === 'marrow-control')
                return kind;
            if (kind)
                found = kind;
        }
        return found;
    }
    let found = null;
    for (const target of (0, hook_tool_policy_1.toolTargetPaths)(event)) {
        const kind = pathKind(target, cwd);
        if (kind === 'marrow-control')
            return kind;
        if (kind)
            found = kind;
    }
    return found;
}
//# sourceMappingURL=self-protect.js.map