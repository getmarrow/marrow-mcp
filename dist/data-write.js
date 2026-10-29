"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DATA_FILE_RUN_DENY_TEXT = void 0;
exports.dataWriteOnly = dataWriteOnly;
exports.runsDataFileAsProgram = runsDataFileAsProgram;
const node_fs_1 = require("node:fs");
const data_commands_1 = require("./data-commands");
const hook_tool_policy_1 = require("./hook-tool-policy");
const MAX_COMMAND_LENGTH = 8192;
const REJECT = new Error('not a data write');
function no() { throw REJECT; }
const DATA_EXTENSION = /\.(?:md|txt|log|jsonl|ndjson|csv|tsv)$/i;
const INSTRUCTION_FILE = /^(?:claude\.md|claude\.local\.md|agents\.md|gemini\.md|memory\.md|skill\.md|copilot-instructions\.md)$/i;
// Names a literal assignment may never set: they change how the shell finds programs, expands `~` or runs the next command.
const BLOCKED_ASSIGNMENT = /^(?:PATH|IFS|ENV|BASH_.*|PS[1-4]|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|HOME|PWD|OLDPWD|TMPDIR|SHELL|CDPATH|GLOBIGNORE|POSIXLY_CORRECT|LD_.*|DYLD_.*|MARROW_.*|LC_.*|LANG|LANGUAGE|TZ|TERM|USER|LOGNAME|HISTFILE|MAIL.*)$/i;
const DATE_ARGUMENT = /^(?:-u|--utc|-R|-I[a-z]*|--iso-8601(?:=[a-z]+)?|\+[^$`'"\\;&|<>(){}\s]*)$/;
const DATE_SUBSTITUTION = /^\$\(date((?: [^\s)]+)*)\)/;
const ECHO_FLAGS = new Set(['-n', '-e', '-E', '-ne', '-en', '-nE', '-En']);
const DELIMITER_END = new Set([' ', '\t', '\n', ';', '&', '|', '>']);
// MCP-1b: next to a declared command, a literal assignment may not name a variable an interpreter, a package manager, git or a TLS/proxy client reads.
const DECLARED_BLOCKED_ASSIGNMENT = /^(?:PYTHON.*|NODE.*|NPM_.*|PERL.*|RUBY.*|GEM_.*|BUN_.*|DENO_.*|JAVA.*|_JAVA.*|CLASSPATH|VIRTUAL_ENV|CONDA.*|UV_.*|PIP.*|POETRY.*|XDG_.*|GIT_.*|SSH_.*|SSL_.*|CURL_.*|REQUESTS_.*|.*_PROXY|ALL_PROXY|NO_PROXY|HTTPS?_.*|ZDOTDIR|EDITOR|VISUAL|PAGER|BROWSER|SHELL.*|TMP.*|TEMP.*|DISPLAY|MALLOC.*|GLIBC.*|OPENSSL.*|.*(?:PATH|DIR|DIRS|HOME|OPT|OPTS|OPTIONS|FLAGS|ENV|RC|CONFIG|CONF|PRELOAD|LIB|LIBS|ROOT|PREFIX|STARTUP|SETTINGS|CERT|CERTS|FILE))$/i;
function newSegment(pipeIn = false) {
    return { words: [], redirects: [], heredoc: false, pipeIn, pipeOut: false };
}
/** Reads the command into simple segments, or throws REJECT for any syntax outside the narrow grammar DW admits. */
function scan(command, home) {
    const segments = [];
    const variables = new Map();
    let cur = newSegment();
    let text = '';
    let inWord = false;
    let head = '';
    let headOpen = true;
    let date = false;
    let expands = false;
    let dollar = false;
    let escaped = false;
    let tilde = false;
    let pending = null;
    let heredoc = null;
    let heredocSeen = false;
    let previousSeparator = '';
    let onlyAssignments = true;
    const literal = (value, special) => {
        text += value;
        inWord = true;
        if (special)
            headOpen = false;
        else if (headOpen)
            head += value;
    };
    const endWord = () => {
        if (!inWord)
            return;
        const assign = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(head);
        const word = { text, date, expands, dollar, escaped, tilde, assignName: assign ? assign[1] : null };
        if (pending) {
            if (date)
                no();
            cur.redirects.push({ target: word, append: pending.append });
            pending = null;
        }
        else
            cur.words.push(word);
        text = '';
        inWord = false;
        head = '';
        headOpen = true;
        date = false;
        expands = false;
        dollar = false;
        escaped = false;
        tilde = false;
    };
    const endSegment = (separator) => {
        endWord();
        if (pending)
            no();
        if (!cur.words.length && !cur.redirects.length && !cur.heredoc) {
            if (cur.pipeIn)
                no();
            if (separator === '\n' || separator === '')
                return;
            no();
        }
        const assignments = cur.words.length > 0 && cur.words[0].assignName !== null;
        if (assignments) {
            if (cur.words.some((word) => word.assignName === null) || cur.redirects.length || cur.heredoc || cur.pipeIn)
                no();
            if (!['', ';', '\n', '&&', '||'].includes(separator))
                no();
            if (segments.length > 0 && !onlyAssignments && previousSeparator !== ';' && previousSeparator !== '\n')
                no();
            for (const word of cur.words) {
                const name = word.assignName;
                if (word.expands || word.date || BLOCKED_ASSIGNMENT.test(name) || variables.has(name))
                    no();
                variables.set(name, word.text.slice(name.length + 1));
            }
        }
        else
            onlyAssignments = false;
        if (separator === '|')
            cur.pipeOut = true;
        segments.push(cur);
        previousSeparator = separator;
        cur = newSegment(separator === '|');
    };
    const expand = (name, quoted) => {
        if (!variables.has(name))
            no();
        const value = variables.get(name);
        if (!quoted && (value === '' || /[\s*?[]/.test(value)))
            no();
        text += value;
        inWord = true;
        headOpen = false;
        expands = true;
    };
    const dollarAt = (index, quoted) => {
        dollar = true;
        const rest = command.slice(index);
        const substitution = DATE_SUBSTITUTION.exec(rest);
        if (substitution) {
            const args = substitution[1].split(' ').filter(Boolean);
            if (!args.every((arg) => DATE_ARGUMENT.test(arg)))
                no();
            literal('DATE', true);
            date = true;
            return substitution[0].length;
        }
        const braced = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}/.exec(rest);
        if (braced) {
            expand(braced[1], quoted);
            return braced[0].length;
        }
        const named = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(rest);
        if (named) {
            expand(named[1], quoted);
            return named[0].length;
        }
        const next = rest[1];
        if (next === undefined || next === ' ' || next === '\t' || next === '\n' || next === '"' || next === '/') {
            literal('$', true);
            return 1;
        }
        return no();
    };
    let index = 0;
    while (index < command.length) {
        const char = command[index];
        const next = command[index + 1];
        if (char === "'") {
            const end = command.indexOf("'", index + 1);
            if (end < 0)
                no();
            literal(command.slice(index + 1, end), true);
            inWord = true;
            index = end + 1;
            continue;
        }
        if (char === '"') {
            inWord = true;
            headOpen = false;
            index += 1;
            let closed = false;
            while (index < command.length) {
                const inner = command[index];
                if (inner === '"') {
                    closed = true;
                    index += 1;
                    break;
                }
                if (inner === '`')
                    no();
                if (inner === '\\') {
                    escaped = true;
                    const escapedChar = command[index + 1];
                    if (escapedChar === undefined || escapedChar === '\n')
                        no();
                    if ('$`"\\'.includes(escapedChar)) {
                        text += escapedChar;
                        index += 2;
                    }
                    else {
                        text += '\\';
                        index += 1;
                    }
                    continue;
                }
                if (inner === '$') {
                    index += dollarAt(index, true);
                    continue;
                }
                text += inner;
                index += 1;
            }
            if (!closed)
                no();
            continue;
        }
        if (char === '\\') {
            if (next === undefined || next === '\n')
                no();
            escaped = true;
            literal(next, true);
            index += 2;
            continue;
        }
        if (char === '`' || char === '(' || char === ')' || char === '{' || char === '}' || char === '*' || char === '?' || char === '[')
            no();
        if (char === '$') {
            index += dollarAt(index, false);
            continue;
        }
        if (char === '~' && (!inWord || (headOpen && /^[A-Za-z_][A-Za-z0-9_]*=$/.test(head) && text === head))) {
            if (next !== undefined && !' \t\n;&|<>/'.includes(next))
                no();
            tilde = true;
            literal(home, true);
            index += 1;
            continue;
        }
        if (char === ' ' || char === '\t') {
            endWord();
            index += 1;
            continue;
        }
        if (char === '\n') {
            endSegment('\n');
            if (heredoc) {
                const lines = [];
                let position = index + 1;
                let matched = false;
                while (position <= command.length) {
                    const stop = command.indexOf('\n', position);
                    const line = command.slice(position, stop < 0 ? command.length : stop);
                    const candidate = heredoc.strip ? line.replace(/^\t+/, '') : line;
                    if (candidate === heredoc.delimiter) {
                        matched = true;
                        position = stop < 0 ? command.length : stop + 1;
                        break;
                    }
                    lines.push(line);
                    if (stop < 0)
                        break;
                    position = stop + 1;
                }
                if (!matched)
                    no();
                if (!heredoc.quoted && /[$`\\]/.test(lines.join('\n')))
                    no();
                heredoc = null;
                index = position;
                continue;
            }
            index += 1;
            continue;
        }
        if (char === ';') {
            if (next === ';' || next === '&')
                no();
            endSegment(';');
            index += 1;
            continue;
        }
        if (char === '|') {
            if (next === '&')
                no();
            if (next === '|') {
                endSegment('||');
                index += 2;
            }
            else {
                endSegment('|');
                index += 1;
            }
            continue;
        }
        if (char === '&') {
            if (next === '&') {
                endSegment('&&');
                index += 2;
                continue;
            }
            if (next === '>') {
                endWord();
                if (pending)
                    no();
                const append = command[index + 2] === '>';
                pending = { append };
                index += append ? 3 : 2;
                continue;
            }
            endSegment('&');
            index += 1;
            continue;
        }
        if (char === '>') {
            if (inWord && /^\d+$/.test(text) && head === text) {
                if (text !== '1' && text !== '2')
                    no();
                text = '';
                inWord = false;
                head = '';
                headOpen = true;
            }
            else
                endWord();
            if (pending)
                no();
            if (next === '|' || next === '(')
                no();
            if (next === '&') {
                const dup = /^&(?:1|2)(?![A-Za-z0-9_./-])/.exec(command.slice(index + 1));
                if (!dup)
                    no();
                index += 1 + dup[0].length;
                continue;
            }
            const append = next === '>';
            pending = { append };
            index += append ? 2 : 1;
            continue;
        }
        if (char === '<') {
            endWord();
            if (pending || next !== '<' || command[index + 2] === '<' || command[index + 2] === '(' || heredocSeen)
                no();
            let cursor = index + 2;
            const strip = command[cursor] === '-';
            if (strip)
                cursor += 1;
            while (command[cursor] === ' ' || command[cursor] === '\t')
                cursor += 1;
            let delimiter;
            let quoted = true;
            const quote = command[cursor];
            if (quote === "'" || quote === '"') {
                const end = command.indexOf(quote, cursor + 1);
                if (end < 0)
                    no();
                delimiter = command.slice(cursor + 1, end);
                if (!delimiter || /[\n$`\\]/.test(delimiter))
                    no();
                cursor = end + 1;
            }
            else {
                const bare = /^[A-Za-z0-9_]+/.exec(command.slice(cursor));
                if (!bare)
                    no();
                delimiter = bare[0];
                quoted = false;
                cursor += delimiter.length;
            }
            if (cursor < command.length && !DELIMITER_END.has(command[cursor]))
                no();
            heredoc = { delimiter, strip, quoted };
            heredocSeen = true;
            cur.heredoc = true;
            index = cursor;
            continue;
        }
        if (char === '#' && !inWord) {
            while (index < command.length && command[index] !== '\n')
                index += 1;
            continue;
        }
        literal(char, false);
        index += 1;
    }
    if (heredoc)
        no();
    endSegment('');
    if (!segments.length)
        no();
    return segments;
}
/** Rule 6: one write target (after substitution) is a null/std device or a plain notes file. */
function writableTarget(raw, truncate, context, roots) {
    if (raw === '/dev/null' || raw === '/dev/stdout' || raw === '/dev/stderr')
        return true;
    if (!raw || raw.includes('\0') || /[*?[]/.test(raw) || raw.endsWith('/'))
        return false;
    let path = raw;
    if (!path.startsWith('/')) {
        if (!context.cwd || !context.cwd.startsWith('/'))
            return false;
        path = `${context.cwd}/${path}`;
    }
    const parts = path.split('/').filter((part) => part !== '' && part !== '.');
    if (!parts.length || parts.some((part) => part === '..' || part.startsWith('.')))
        return false;
    const full = `/${parts.join('/')}`;
    const name = parts[parts.length - 1];
    if (!DATA_EXTENSION.test(name) || INSTRUCTION_FILE.test(name))
        return false;
    const underRoot = ['/tmp', '/mnt', roots.home].some((root) => root && root.length > 1 && full.startsWith(`${root}/`));
    if (!underRoot)
        return false;
    let current = '';
    for (let at = 0; at < parts.length; at += 1) {
        current += `/${parts[at]}`;
        const last = at === parts.length - 1;
        let stat;
        try {
            stat = (0, node_fs_1.lstatSync)(current);
        }
        catch (error) {
            return last && error.code === 'ENOENT';
        }
        if (stat.isSymbolicLink())
            return false;
        if (!last) {
            if (!stat.isDirectory())
                return false;
            continue;
        }
        if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o111) !== 0)
            return false;
        if (truncate && context.postTool !== true)
            return false;
    }
    return true;
}
/** Whether `command` writes notes/log files only, using nothing but echo, printf, cat, tee and literal assignments. */
function dataWriteOnly(command, context = {}) {
    try {
        if (process.platform === 'win32' || typeof command !== 'string')
            return false;
        if (command.length > MAX_COMMAND_LENGTH || hook_tool_policy_1.UNMODELED_SHELL_CHARACTER.test(command))
            return false;
        const home = typeof context.home === 'string' && context.home.startsWith('/') && context.home.length > 1 ? context.home : null;
        const segments = scan(command, home ?? no());
        const roots = { home };
        let writes = 0;
        let declared = false;
        for (const segment of segments) {
            const [program, ...args] = segment.words;
            if (program.assignName !== null)
                continue;
            if (program.expands || program.date)
                no();
            let payload = args;
            let truncate = true;
            const operands = [];
            switch (program.text) {
                case 'echo': {
                    let at = 0;
                    while (at < args.length && args[at].text.startsWith('-')) {
                        if (args[at].date || !ECHO_FLAGS.has(args[at].text))
                            no();
                        at += 1;
                    }
                    payload = args.slice(at);
                    if (segment.heredoc)
                        no();
                    break;
                }
                case 'printf': {
                    let at = 0;
                    if (args[0] && args[0].text === '--')
                        at = 1;
                    else if (args[0] && args[0].text.startsWith('-'))
                        no();
                    payload = args.slice(at);
                    if (segment.heredoc)
                        no();
                    break;
                }
                case 'cat':
                    if (args.length || (!segment.heredoc && !segment.pipeIn))
                        no();
                    payload = [];
                    break;
                case 'tee': {
                    let at = 0;
                    let append = false;
                    while (at < args.length && args[at].text.startsWith('-')) {
                        if (args[at].date || (args[at].text !== '-a' && args[at].text !== '--append'))
                            no();
                        append = true;
                        at += 1;
                    }
                    if (!segment.heredoc && !segment.pipeIn)
                        no();
                    operands.push(...args.slice(at));
                    truncate = !append;
                    payload = [];
                    break;
                }
                default:
                    // MCP-1b: a segment that is not echo/printf/cat/tee is still data-only when it is exactly an owner-declared command (data-commands.ts):
                    // its words are then data, its redirects are judged below like any other, and it counts as the write it is declared to be.
                    if (segment.heredoc || !(0, data_commands_1.declaredCommandMatch)(segment.words, { cwd: context.cwd, home: context.dataCommandsHome }))
                        return false;
                    declared = true;
                    writes += 1;
                    payload = [];
            }
            if (program.text !== 'echo' && program.text !== 'printf' && payload.some((word) => word.date))
                no();
            if (operands.some((word) => word.date))
                no();
            for (const operand of operands) {
                if (!writableTarget(operand.text, truncate, context, roots))
                    return false;
                writes += 1;
            }
            for (const redirect of segment.redirects) {
                if (redirect.target.date)
                    no();
                const device = ['/dev/null', '/dev/stdout', '/dev/stderr'].includes(redirect.target.text);
                if (!writableTarget(redirect.target.text, !redirect.append, context, roots))
                    return false;
                if (!device)
                    writes += 1;
            }
        }
        if (declared) {
            for (const segment of segments) {
                if (segment.words[0].assignName !== null && segment.words.some((word) => DECLARED_BLOCKED_ASSIGNMENT.test(word.assignName)))
                    return false;
            }
        }
        return writes > 0;
    }
    catch {
        return false;
    }
}
/** T1: the deny text for a data file run as a program. */
exports.DATA_FILE_RUN_DENY_TEXT = 'Marrow does not run a notes or log file as a program. Put scripts in a file with a script extension.';
const INTERPRETER = /^(?:sh|bash|zsh|dash|ksh|fish|source|\.|python[0-9.]*|node|perl|ruby|php)$/;
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|xargs|stdbuf|timeout)$/;
// Options of the interpreters that take the next word as a value (code, module, warning or require argument), never as the program file.
const VALUE_OPTION = /^-(?:c|e|m|W|X|r)$/;
function baseName(program) {
    const cut = program.lastIndexOf('/');
    return cut < 0 ? program : program.slice(cut + 1);
}
function runsDataFile(words, depth) {
    let at = 0;
    while (at < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[at]))
        at += 1;
    while (at < words.length && WRAPPER.test(baseName(words[at]))) {
        at += 1;
        while (at < words.length && (words[at].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[at]) || /^\d+$/.test(words[at])))
            at += 1;
    }
    if (at >= words.length)
        return false;
    const program = words[at];
    if (program.includes('/') && DATA_EXTENSION.test(program))
        return true;
    if (!INTERPRETER.test(baseName(program)))
        return false;
    const args = words.slice(at + 1);
    for (let arg = 0; arg < args.length; arg += 1) {
        const word = args[arg];
        if (word === '-c' && baseName(program) !== 'node' && !baseName(program).startsWith('python') && depth < 3) {
            const inner = args[arg + 1] === undefined ? null : (0, hook_tool_policy_1.parseShellSegments)(args[arg + 1]);
            return Boolean(inner && inner.some((segment) => runsDataFile(segment.words, depth + 1)));
        }
        if (word.startsWith('-')) {
            if (VALUE_OPTION.test(word))
                arg += 1;
            continue;
        }
        return DATA_EXTENSION.test(word);
    }
    return false;
}
/** T1: true when a plain shell command hands a notes/log file to an interpreter, or names one as its program. */
function runsDataFileAsProgram(command) {
    try {
        const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
        return Boolean(segments && segments.some((segment) => runsDataFile(segment.words, 0)));
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=data-write.js.map