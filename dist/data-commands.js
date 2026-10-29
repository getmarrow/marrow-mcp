"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DATA_COMMANDS_USAGE = exports.DATA_COMMANDS_MAX_SCRIPT_BYTES = exports.DATA_COMMANDS_MAX_ENTRIES = exports.DATA_COMMANDS_MAX_BYTES = exports.DATA_COMMANDS_FILENAME = exports.DATA_COMMANDS_DIRECTORY = exports.DATA_COMMANDS_VERSION = void 0;
exports.dataCommandsPath = dataCommandsPath;
exports.readDataCommands = readDataCommands;
exports.entryProblem = entryProblem;
exports.declaredCommandMatch = declaredCommandMatch;
exports.dataCommandsEvidence = dataCommandsEvidence;
exports.runDataCommands = runDataCommands;
const node_fs_1 = require("node:fs");
const node_crypto_1 = require("node:crypto");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
/**
 * MCP-1b: owner-declared data commands.
 *
 * The owner teaches Marrow, once and in a terminal, that one of their own scripts only handles data (a board tool, a notes tool). The declaration is
 * `~/.marrow/data-commands.json`; a command that is exactly `<argv_prefix> <plain literal words>`, whose script still has the hash the owner saw, is then
 * judged by its effect like a data write (data-write.ts): its remaining words are data, not actions. Everything here fails closed: a file that fails any
 * check is ignored whole, an entry that fails any check never matches, and a segment that is not understood in full is not a match, so the
 * 3.9.109 classification runs byte for byte.
 */
exports.DATA_COMMANDS_VERSION = 1;
exports.DATA_COMMANDS_DIRECTORY = '.marrow';
exports.DATA_COMMANDS_FILENAME = 'data-commands.json';
exports.DATA_COMMANDS_MAX_BYTES = 4096;
exports.DATA_COMMANDS_MAX_ENTRIES = 20;
exports.DATA_COMMANDS_MAX_SCRIPT_BYTES = 1024 * 1024;
const MIN_WORDS = 2;
const MAX_WORDS = 8;
function dataCommandsPath(home = (0, node_os_1.homedir)()) {
    return (0, node_path_1.join)(home, exports.DATA_COMMANDS_DIRECTORY, exports.DATA_COMMANDS_FILENAME);
}
function currentUid() {
    return typeof process.getuid === 'function' ? process.getuid() : undefined;
}
function ownedPrivate(stat, mode, uid) {
    return !stat.isSymbolicLink() && (uid === undefined || stat.uid === uid) && (stat.mode & 0o777) === mode;
}
function ignoredFile(reason) {
    return { present: true, entries: [], ignored: `data-commands.json ignored: ${reason}` };
}
const ABSENT = { present: false, entries: [], ignored: null };
const SHA256 = /^[a-f0-9]{64}$/;
function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/**
 * The declaration file, read with the checks control.json gets (control-state.ts): the folder is a real folder of mode 700 and the file a regular file of
 * mode 600, both owned by this user, no link on either, at most 4 KB, exact schema, at most 20 entries. Any failure ignores the whole file and says why in one line.
 */
function readDataCommands(options = {}) {
    const home = options.home || (0, node_os_1.homedir)();
    const uid = options.uid ?? currentUid();
    const directory = (0, node_path_1.join)(home, exports.DATA_COMMANDS_DIRECTORY);
    const target = dataCommandsPath(home);
    let directoryStat;
    try {
        directoryStat = (0, node_fs_1.lstatSync)(directory);
    }
    catch (error) {
        return error.code === 'ENOENT' ? ABSENT : ignoredFile('the ~/.marrow folder cannot be read');
    }
    if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory())
        return ignoredFile('~/.marrow is a link or not a folder');
    let targetStat;
    try {
        targetStat = (0, node_fs_1.lstatSync)(target);
    }
    catch (error) {
        return error.code === 'ENOENT' ? ABSENT : ignoredFile('the file cannot be read');
    }
    if (!ownedPrivate(directoryStat, 0o700, uid))
        return ignoredFile('the ~/.marrow folder must be mode 700 with you as its owner');
    if (targetStat.isSymbolicLink())
        return ignoredFile('the file is a symbolic link');
    if (!targetStat.isFile())
        return ignoredFile('the file is not a regular file');
    if (!ownedPrivate(targetStat, 0o600, uid))
        return ignoredFile('the file must be mode 600 with you as its owner');
    if (targetStat.size < 2 || targetStat.size > exports.DATA_COMMANDS_MAX_BYTES)
        return ignoredFile(`the file must be 2 to ${exports.DATA_COMMANDS_MAX_BYTES} bytes`);
    let fd = -1;
    try {
        fd = (0, node_fs_1.openSync)(target, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NOFOLLOW || 0));
        const opened = (0, node_fs_1.fstatSync)(fd);
        if (!opened.isFile() || opened.ino !== targetStat.ino || !ownedPrivate(opened, 0o600, uid))
            return ignoredFile('the file changed while it was read');
        const raw = (0, node_fs_1.readFileSync)(fd, 'utf8');
        if (Buffer.byteLength(raw) > exports.DATA_COMMANDS_MAX_BYTES)
            return ignoredFile(`the file must be 2 to ${exports.DATA_COMMANDS_MAX_BYTES} bytes`);
        let value;
        try {
            value = JSON.parse(raw);
        }
        catch {
            return ignoredFile('the file is not valid JSON');
        }
        if (!isPlainObject(value) || Object.keys(value).sort().join(',') !== 'commands,version')
            return ignoredFile('the file does not have exactly the keys version and commands');
        if (value.version !== exports.DATA_COMMANDS_VERSION)
            return ignoredFile('the version is not 1');
        const commands = value.commands;
        if (!Array.isArray(commands))
            return ignoredFile('commands is not a list');
        if (commands.length > exports.DATA_COMMANDS_MAX_ENTRIES)
            return ignoredFile(`more than ${exports.DATA_COMMANDS_MAX_ENTRIES} entries`);
        const entries = [];
        for (const item of commands) {
            if (!isPlainObject(item) || Object.keys(item).sort().join(',') !== 'argv_prefix,sha256')
                return ignoredFile('an entry does not have exactly the keys argv_prefix and sha256');
            const prefix = item.argv_prefix;
            if (!Array.isArray(prefix) || !prefix.every((word) => typeof word === 'string'))
                return ignoredFile('an argv_prefix is not a list of words');
            if (typeof item.sha256 !== 'string' || !SHA256.test(item.sha256))
                return ignoredFile('a sha256 is not 64 lowercase hex characters');
            entries.push({ argv_prefix: [...prefix], sha256: item.sha256 });
        }
        return { present: true, entries, ignored: null };
    }
    catch {
        return ignoredFile('the file cannot be read');
    }
    finally {
        if (fd >= 0)
            (0, node_fs_1.closeSync)(fd);
    }
}
// ─── entry validity ───
// A prefix word is a plain literal: no space, quote, `$`, backtick, glob, brace or `~`, so the one reading of it is the same in every shell.
const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;
const INTERPRETER = /^(?:bash|sh|zsh|dash|fish|node|perl|ruby|deno|bun|python[0-9.]*)$/;
const LAUNCHER = /^(?:env|sudo|doas|xargs|eval|exec|source|\.|npx|nohup|time|command|builtin|nice|ionice|timeout|stdbuf|setsid|su|ssh|watch|busybox|chroot|flock|strace|find|parallel|script|expect|screen|tmux|at|runuser|pkexec|systemd-run|docker|podman|nsenter|unshare)$/;
// Words that hand code (not a file) to an interpreter.
const CODE_FLAG = /^(?:-c|-e|--eval|-m|-p|--print|--command)$/;
const INTERPRETER_FLAGS = {
    python: new Set(['-I', '-B', '-u', '-s', '-S', '-E', '-O', '-OO', '-q', '-b', '-bb']),
};
function flagsFor(interpreter) {
    return interpreter.startsWith('python') ? INTERPRETER_FLAGS.python : new Set();
}
function baseName(word) {
    const cut = word.lastIndexOf('/');
    return cut < 0 ? word : word.slice(cut + 1);
}
/** Why `prefix` can never be an entry (no file is looked at), or null. The one path word is the script; an interpreter may only run that script directly. */
function entryProblem(prefix) {
    if (!Array.isArray(prefix) || !prefix.every((word) => typeof word === 'string'))
        return 'argv_prefix must be a list of words';
    if (prefix.length < MIN_WORDS || prefix.length > MAX_WORDS)
        return `argv_prefix must have ${MIN_WORDS} to ${MAX_WORDS} words`;
    if (!prefix.every((word) => SAFE_WORD.test(word)))
        return 'every word must be plain letters, digits and - _ . / = : , @ % + (no space, quote, $, glob or ~)';
    const paths = prefix.map((word, at) => (word.includes('/') ? at : -1)).filter((at) => at >= 0);
    if (paths.length !== 1)
        return 'argv_prefix must contain exactly one absolute path, the script';
    const at = paths[0];
    const script = prefix[at];
    if (!script.startsWith('/') || script.endsWith('/') || script.split('/').slice(1).some((part) => part === '' || part === '.' || part === '..'))
        return 'the script path must be absolute and written plainly (no ., .. or double slash)';
    for (let index = 0; index < prefix.length; index += 1) {
        const word = prefix[index];
        if (CODE_FLAG.test(word))
            return `${word} hands code to an interpreter; declare a script file instead`;
        if (index === 0 && INTERPRETER.test(word))
            continue;
        if (LAUNCHER.test(baseName(word)) || INTERPRETER.test(baseName(word)))
            return `${word} is a shell, interpreter or launcher; only the first word may be an interpreter, running the script directly`;
    }
    if (at > 0) {
        const interpreter = prefix[0];
        if (!INTERPRETER.test(interpreter))
            return 'the first word must be the script itself or an interpreter (python3, node, bash ...) that runs it';
        const allowed = flagsFor(interpreter);
        for (let index = 1; index < at; index += 1) {
            if (!allowed.has(prefix[index]))
                return `${prefix[index]} may not stand between the interpreter and the script`;
        }
    }
    return null;
}
/** The script's bytes through a descriptor that follows no link: a regular file of at most 1 MB, in a folder chain with no link at all. */
function readScript(path) {
    let fd = -1;
    try {
        const before = (0, node_fs_1.lstatSync)(path);
        if (before.isSymbolicLink() || !before.isFile())
            return { problem: 'the script is not a regular file (a link or a folder does not count)' };
        if ((0, node_fs_1.realpathSync)(path) !== path)
            return { problem: 'the script path goes through a symbolic link' };
        if (before.size > exports.DATA_COMMANDS_MAX_SCRIPT_BYTES)
            return { problem: 'the script is larger than 1 MB' };
        fd = (0, node_fs_1.openSync)(path, node_fs_1.constants.O_RDONLY | (node_fs_1.constants.O_NOFOLLOW || 0));
        const opened = (0, node_fs_1.fstatSync)(fd);
        if (!opened.isFile() || opened.ino !== before.ino || opened.size > exports.DATA_COMMANDS_MAX_SCRIPT_BYTES)
            return { problem: 'the script changed while it was read' };
        const bytes = (0, node_fs_1.readFileSync)(fd);
        if (bytes.length > exports.DATA_COMMANDS_MAX_SCRIPT_BYTES)
            return { problem: 'the script is larger than 1 MB' };
        return { sha256: (0, node_crypto_1.createHash)('sha256').update(bytes).digest('hex') };
    }
    catch {
        return { problem: 'the script cannot be read' };
    }
    finally {
        if (fd >= 0)
            try {
                (0, node_fs_1.closeSync)(fd);
            }
            catch { /* nothing to release */ }
    }
}
function scriptOf(prefix) {
    return prefix.find((word) => word.includes('/'));
}
/** An entry is usable now only if its prefix is valid, its script is a plain regular file of at most 1 MB with no link on the way, and its hash is the entry's. */
function checkEntry(entry) {
    const problem = entryProblem(entry.argv_prefix);
    if (problem)
        return { ok: false, reason: problem };
    const path = scriptOf(entry.argv_prefix);
    const read = readScript(path);
    if ('problem' in read)
        return { ok: false, reason: read.problem };
    if (read.sha256 !== entry.sha256)
        return { ok: false, reason: 'the script changed since it was declared' };
    return { ok: true, path, sha256: read.sha256 };
}
/** The path as the shell would reach it with no link on the way (`..` allowed), or null when any part is a link or missing. */
function linkFreePath(absolute) {
    let current = '';
    for (const part of absolute.split('/')) {
        if (part === '' || part === '.')
            continue;
        if (part === '..') {
            current = current.slice(0, current.lastIndexOf('/'));
            continue;
        }
        const next = `${current}/${part}`;
        try {
            if ((0, node_fs_1.lstatSync)(next).isSymbolicLink())
                return null;
        }
        catch {
            return null;
        }
        current = next;
    }
    return current || '/';
}
const plainWord = (word) => !word.date && !word.expands && !word.dollar && !word.escaped && !word.tilde;
// A remaining word the script may read as a path is never a way into a hidden folder (~/.marrow, ~/.ssh, .git, an rc file) or a system folder: the
// command then keeps the 3.9.109 reading, where those paths are judged. A word with a space is prose (a note) and stays data.
const SYSTEM_ROOT = /^\/(?:etc|var|usr|bin|sbin|lib|lib32|lib64|proc|sys|boot|root|run|srv|dev)(?:\/|$)/;
function unsafePathWord(word) {
    const text = word.text;
    if (/\s/.test(text) || text === '/dev/null')
        return false;
    if (!text.includes('/') && !/^\.[A-Za-z_]/.test(text))
        return false;
    return SYSTEM_ROOT.test(text) || text.split('/').some((part) => part.startsWith('.'));
}
/**
 * Whether the words of one segment (program first) are an owner-declared data command: the first words equal an entry's argv_prefix, the script word
 * names the declared file with no link on the way, the script's hash now is the entry's, and every word after the prefix is a plain literal (no `$`,
 * backtick, glob, brace, `~`, backslash or substitution). Never throws; any doubt is false.
 */
function declaredCommandMatch(words, options = {}) {
    try {
        const file = readDataCommands({ home: options.home });
        if (!file.entries.length)
            return false;
        for (const entry of file.entries) {
            const prefix = entry.argv_prefix;
            if (words.length < prefix.length || entryProblem(prefix))
                continue;
            const scriptAt = prefix.findIndex((word) => word.includes('/'));
            let same = true;
            for (let at = 0; at < prefix.length && same; at += 1) {
                const word = words[at];
                if (at === scriptAt) {
                    if (word.date || word.expands || word.dollar || word.escaped) {
                        same = false;
                        break;
                    }
                    const absolute = word.text.startsWith('/') ? word.text : options.cwd && options.cwd.startsWith('/') && word.text ? `${options.cwd}/${word.text}` : '';
                    same = absolute !== '' && !absolute.includes('\0') && linkFreePath(absolute) === prefix[at];
                }
                else
                    same = plainWord(word) && word.text === prefix[at];
            }
            if (!same)
                continue;
            const rest = words.slice(prefix.length);
            if (!rest.every(plainWord) || rest.some(unsafePathWord))
                continue;
            if (checkEntry(entry).ok)
                return true;
        }
        return false;
    }
    catch {
        return false;
    }
}
/** One line for status and doctor: whether a declaration is in force and, when the file is ignored, why. No hash and no path. */
function dataCommandsEvidence(options = {}) {
    try {
        const file = readDataCommands(options);
        if (!file.present)
            return { state: 'none', entries: 0, usable: 0, reason: null };
        if (file.ignored)
            return { state: 'ignored', entries: 0, usable: 0, reason: file.ignored };
        return { state: 'active', entries: file.entries.length, usable: file.entries.filter((entry) => checkEntry(entry).ok).length, reason: null };
    }
    catch {
        return { state: 'ignored', entries: 0, usable: 0, reason: 'data-commands.json ignored: it could not be checked' };
    }
}
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function randomCode() {
    let code = '';
    for (let at = 0; at < 6; at += 1)
        code += CODE_ALPHABET[(0, node_crypto_1.randomInt)(CODE_ALPHABET.length)];
    return code;
}
function readLineSync() {
    const byte = Buffer.alloc(1);
    let line = '';
    for (let attempts = 0; attempts < 4000; attempts += 1) {
        let count;
        try {
            count = (0, node_fs_1.readSync)(0, byte, 0, 1, null);
        }
        catch (error) {
            if (error.code === 'EAGAIN') {
                Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
                continue;
            }
            return null;
        }
        if (count === 0)
            return line === '' ? null : line;
        if (byte[0] === 10)
            return line;
        if (byte[0] !== 13 && line.length < 64)
            line += String.fromCharCode(byte[0]);
    }
    return null;
}
function processIo() {
    return {
        isTTY: [Boolean(process.stdin.isTTY), Boolean(process.stdout.isTTY), Boolean(process.stderr.isTTY)],
        readLine: readLineSync,
        write: (text) => { process.stdout.write(text); },
        writeErr: (text) => { process.stderr.write(text); },
    };
}
exports.DATA_COMMANDS_USAGE = [
    'Usage: marrow-mcp data-commands list',
    '       marrow-mcp data-commands add -- <argv_prefix...>   (the owner, in a terminal)',
    '       marrow-mcp data-commands remove <n>                (the owner, in a terminal)',
    'Example: marrow-mcp data-commands add -- python3 -I /home/me/tools/board.py set',
    '',
].join('\n');
function whereIsHome(io) {
    return { home: io.home || (0, node_os_1.homedir)(), uid: io.uid ?? currentUid() };
}
function writeDeclaration(home, uid, entries) {
    const directory = (0, node_path_1.join)(home, exports.DATA_COMMANDS_DIRECTORY);
    const target = dataCommandsPath(home);
    const body = `${JSON.stringify({ version: exports.DATA_COMMANDS_VERSION, commands: entries })}\n`;
    if (Buffer.byteLength(body) > exports.DATA_COMMANDS_MAX_BYTES)
        return `the file would be larger than ${exports.DATA_COMMANDS_MAX_BYTES} bytes, which Marrow would ignore; remove an entry first`;
    let temporary = '';
    let fd = -1;
    try {
        let stat = null;
        try {
            stat = (0, node_fs_1.lstatSync)(directory);
        }
        catch (error) {
            if (error.code !== 'ENOENT')
                return 'the ~/.marrow folder cannot be read';
        }
        if (stat === null)
            (0, node_fs_1.mkdirSync)(directory, { mode: 0o700 });
        else if (!stat.isDirectory() || !ownedPrivate(stat, 0o700, uid))
            return 'the ~/.marrow folder must be a real folder of mode 700 owned by you; fix that first';
        temporary = (0, node_path_1.join)(directory, `.data-commands.${process.pid}.${(0, node_crypto_1.randomInt)(2 ** 31)}.tmp`);
        fd = (0, node_fs_1.openSync)(temporary, node_fs_1.constants.O_WRONLY | node_fs_1.constants.O_CREAT | node_fs_1.constants.O_EXCL | (node_fs_1.constants.O_NOFOLLOW || 0), 0o600);
        (0, node_fs_1.writeSync)(fd, body);
        (0, node_fs_1.fsyncSync)(fd);
        (0, node_fs_1.closeSync)(fd);
        fd = -1;
        (0, node_fs_1.renameSync)(temporary, target);
        temporary = '';
        return null;
    }
    catch {
        return 'the file could not be written';
    }
    finally {
        if (fd >= 0)
            try {
                (0, node_fs_1.closeSync)(fd);
            }
            catch { /* nothing to release */ }
        if (temporary)
            try {
                (0, node_fs_1.unlinkSync)(temporary);
            }
            catch { /* already gone */ }
    }
}
function confirmWithCode(io, what) {
    const code = (io.random || randomCode)();
    io.write(`${what}\nTo confirm, type this code and press enter (anything else cancels): ${code}\n`);
    const typed = io.readLine();
    return typeof typed === 'string' && typed.trim() === code;
}
function describe(entry) {
    return entry.argv_prefix.join(' ');
}
/** Runs `marrow-mcp data-commands ...` and returns the exit code: 0 done, 1 failed or cancelled, 2 refused (no terminal), 64 usage. */
function runDataCommands(args, io = processIo()) {
    const subcommand = args[0];
    const { home, uid } = whereIsHome(io);
    if (subcommand === 'list') {
        if (args.length !== 1) {
            io.writeErr(exports.DATA_COMMANDS_USAGE);
            return 64;
        }
        const file = readDataCommands({ home, uid });
        if (!file.present) {
            io.write('No data commands are declared.\n');
            return 0;
        }
        if (file.ignored) {
            io.write(`${file.ignored}\n`);
            return 0;
        }
        if (!file.entries.length) {
            io.write('No data commands are declared.\n');
            return 0;
        }
        file.entries.forEach((entry, at) => {
            const checked = checkEntry(entry);
            io.write(`${at + 1}. ${describe(entry)}  [${checked.ok ? 'active' : `inactive: ${checked.reason}`}]\n`);
        });
        return 0;
    }
    if (subcommand !== 'add' && subcommand !== 'remove') {
        io.writeErr(exports.DATA_COMMANDS_USAGE);
        return 64;
    }
    // Owner only: the declaration loosens a check, so it is never made from a shell without a person at it. This is a guard against the accident, not a
    // proof of the owner: a program that drives a pseudo-terminal can still type the code back (spec friction r3 section 5).
    if (!io.isTTY[0] || !io.isTTY[1] || !io.isTTY[2]) {
        io.writeErr(`data-commands ${subcommand} needs a terminal on stdin, stdout and stderr, and the owner to type back a code. Nothing was written. Run it yourself in your own terminal.\n`);
        return 2;
    }
    const file = readDataCommands({ home, uid });
    if (file.ignored) {
        io.writeErr(`${file.ignored}. Fix or delete ~/.marrow/data-commands.json first; nothing was changed.\n`);
        return 1;
    }
    if (subcommand === 'add') {
        if (args[1] !== '--' || args.length < 3) {
            io.writeErr(exports.DATA_COMMANDS_USAGE);
            return 64;
        }
        const prefix = args.slice(2);
        const problem = entryProblem(prefix);
        if (problem) {
            io.writeErr(`Not declared: ${problem}.\n`);
            return 1;
        }
        if (file.entries.length >= exports.DATA_COMMANDS_MAX_ENTRIES) {
            io.writeErr(`Not declared: ${exports.DATA_COMMANDS_MAX_ENTRIES} entries are already declared (the most Marrow reads).\n`);
            return 1;
        }
        if (file.entries.some((entry) => entry.argv_prefix.join('\0') === prefix.join('\0'))) {
            io.writeErr('Not declared: this prefix is already declared.\n');
            return 1;
        }
        const pinned = readScript(scriptOf(prefix));
        if ('problem' in pinned) {
            io.writeErr(`Not declared: ${pinned.problem}.\n`);
            return 1;
        }
        const confirmed = confirmWithCode(io, `Declare as a data-only command: ${prefix.join(' ')}\nScript sha256: ${pinned.sha256}\nAfter this, Marrow treats the words after that prefix as data, not as actions, while the script stays exactly as it is now.`);
        if (!confirmed) {
            io.writeErr('Cancelled: the code did not match. Nothing was written.\n');
            return 1;
        }
        // The script is read again after the code was typed: the hash written is the one of the bytes on disk now.
        const again = readScript(scriptOf(prefix));
        if ('problem' in again) {
            io.writeErr(`Not declared: ${again.problem}.\n`);
            return 1;
        }
        const failure = writeDeclaration(home, uid, [...file.entries, { argv_prefix: prefix, sha256: again.sha256 }]);
        if (failure) {
            io.writeErr(`Not declared: ${failure}.\n`);
            return 1;
        }
        io.write(`Declared ${file.entries.length + 1} data command(s). Run 'marrow-mcp data-commands list' to check.\n`);
        return 0;
    }
    if (args.length !== 2 || !/^[1-9][0-9]{0,2}$/.test(args[1])) {
        io.writeErr(exports.DATA_COMMANDS_USAGE);
        return 64;
    }
    const number = Number(args[1]);
    if (number > file.entries.length) {
        io.writeErr(`There is no entry ${number}. Run 'marrow-mcp data-commands list'.\n`);
        return 1;
    }
    const confirmed = confirmWithCode(io, `Remove data command ${number}: ${describe(file.entries[number - 1])}`);
    if (!confirmed) {
        io.writeErr('Cancelled: the code did not match. Nothing was changed.\n');
        return 1;
    }
    const failure = writeDeclaration(home, uid, file.entries.filter((_, at) => at !== number - 1));
    if (failure) {
        io.writeErr(`Not removed: ${failure}.\n`);
        return 1;
    }
    io.write(`Removed. ${file.entries.length - 1} data command(s) remain.\n`);
    return 0;
}
//# sourceMappingURL=data-commands.js.map