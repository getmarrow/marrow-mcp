"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONTROL_ROUTE_DENY_TEXT = void 0;
exports.provenDataText = provenDataText;
exports.controlRoute = controlRoute;
exports.approvalReportUrl = approvalReportUrl;
exports.selfApproveRoute = selfApproveRoute;
const hook_tool_policy_1 = require("./hook-tool-policy");
/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 * CL-5: only a command in a position that runs counts (the program word, a runner's package or file argument, the code of `-c`, `eval`,
 * `$( )` or backticks); the installer's name in a data operand, a folder name or a message is not a route.
 */
exports.CONTROL_ROUTE_DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';
const INSTALLER_PACKAGE = /(?:^|=)@getmarrow\/install(?:@[^\s/]*)?$/i;
const INSTALLER_BIN = /(?:^|\/)marrow-install(?:\.[cm]?js)?$/i;
const INSTALLER_PATH = /@getmarrow\/install\//i;
const INSTALLER_TEXT = /@getmarrow\/install|marrow-install/i;
const INSTALLER_TEXT_ALL = /@getmarrow\/install|marrow-install/gi;
const L1_PROGRAM = /^(?:printf|echo|grep|git|cat|cd|ls)$/; // CL-5 L1: the owner-decided data programs
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const KEYWORD = /^(?:do|then|else|elif|if|while|until|!)$/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh|su)$/;
const STDIN_SHELL = /^(?:sh|bash|zsh|dash|ksh|su|eval|source|\.)$/; // reads its code from stdin, a here-doc or a file
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
const RUNNER_SUBCOMMAND = /^(?:exec|x|dlx|run)$/;
const DYNAMIC = /[$`*?[]/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);
const INTERPRETER = /^(?:python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php)$/i; // M-SELF-APPROVE (g): runs code that can send a request
const HTTP_CLIENT = /^(?:curl|wget|http|https|httpie|xh|aria2c|nc)$/i;
const REPORT_SCRIPT = /^(?:host[_-]?report|approval[_-]link|host[_-]approval)(?:\.[^/]*)?$/i;
const REPORT_TEXT = /host[_-]?report|approval[_-]link|host[_-]approval/i;
const MAX_DEPTH = 3;
// Past this size a text keeps the 3.9.113 answer (the whole-text word check), so the reading stays inside the hook's budget.
const MAX_READ = 32_768;
function baseName(word) {
    const cut = word.lastIndexOf('/');
    return cut < 0 ? word : word.slice(cut + 1);
}
function installerArguments(words) {
    const marker = words.findIndex((word) => INSTALLER_PACKAGE.test(word) || INSTALLER_BIN.test(word) || INSTALLER_PATH.test(word));
    return marker < 0 ? null : words.slice(marker + 1);
}
function routeArguments(args, dynamic) {
    if (dynamic || args.some((arg) => /[$`*?[~]/.test(arg)))
        return true;
    if (args.some((arg) => /^-{0,2}(?:disable|uninstall)$/i.test(arg)))
        return true;
    const control = args.findIndex((arg) => arg.toLowerCase() === 'control');
    if (control < 0)
        return false;
    const subcommands = args.slice(control + 1).filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
    return !(subcommands.length > 0 && subcommands.every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
}
/** The words from the program on: leading assignments, shell keywords and wrappers (with their options) skipped. */
function programWords(words) {
    let at = 0;
    for (;;) {
        const start = at;
        while (at < words.length && (ASSIGNMENT.test(words[at]) || KEYWORD.test(words[at])))
            at += 1;
        while (at < words.length && WRAPPER.test(baseName(words[at]))) {
            at += 1;
            while (at < words.length && (words[at].startsWith('-') || ASSIGNMENT.test(words[at]) || /^\d+$/.test(words[at])))
                at += 1;
        }
        if (at === start)
            return words.slice(at);
    }
}
/** The code a shell `-c`, `su -c` or `eval` runs, or null. */
function innerCode(words) {
    if (words[0] === 'eval')
        return words.length > 1 ? words.slice(1).join(' ') : null;
    if (!SHELL_PROGRAM.test(baseName(words[0])))
        return null;
    const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
    return flag > 0 && words[flag + 1] !== undefined ? words[flag + 1] : null;
}
/** A runner's package or file argument that is not a literal (`npx $x`, `npm exec "$P"`, `node ${F}`). */
function dynamicRunnerArgument(words) {
    let subcommand = !/^(?:npx|pnpx|bunx|node|nodejs)$/.test(baseName(words[0]));
    for (let at = 1; at < words.length; at += 1) {
        const word = words[at];
        if (/^(?:-p|--package)$/.test(word)) {
            if (DYNAMIC.test(words[at + 1] ?? ''))
                return true;
            at += 1;
            continue;
        }
        if (word.startsWith('-')) {
            if (/^--package=/.test(word) && DYNAMIC.test(word))
                return true;
            continue;
        }
        if (DYNAMIC.test(word))
            return true;
        if (subcommand && RUNNER_SUBCOMMAND.test(word)) {
            subcommand = false;
            continue;
        }
        return false;
    }
    return false;
}
/**
 * The commands of a text the shell parser cannot read, split at `; & | ( ) { }` and newlines; `$( )` and backtick bodies go
 * to `nested` (read as commands one level down). A quoted string is one data word (eval and `-c` read it as code); an
 * unbalanced quote reads the rest of the text as commands. One pass over the text.
 */
function lexicalCommands(text, nested) {
    const commands = [];
    let words = [];
    let word = '';
    let inWord = false;
    let dynamic = false;
    const endWord = () => { if (inWord)
        words.push(word); word = ''; inWord = false; };
    const endCommand = () => { endWord(); if (words.length)
        commands.push({ words, dynamic }); words = []; dynamic = false; };
    // The end of the `$(` body that opens at `open` (matching parenthesis, or the end of the text).
    const closing = (open) => {
        let level = 1;
        for (let at = open + 2; at < text.length; at += 1) {
            if (text[at] === '(')
                level += 1;
            else if (text[at] === ')' && --level === 0)
                return at;
        }
        return text.length;
    };
    const substitution = (at) => {
        dynamic = true;
        inWord = true;
        const tick = text[at] === '`';
        const end = tick ? text.indexOf('`', at + 1) : closing(at);
        const stop = end < 0 ? text.length : end;
        nested.push(text.slice(at + (tick ? 1 : 2), stop));
        word += tick ? '`' : '$(';
        return stop;
    };
    for (let at = 0; at < text.length; at += 1) {
        const char = text[at];
        if (char === '\\') {
            word += text[at + 1] ?? '';
            inWord = true;
            at += 1;
            continue;
        }
        if (char === "'") {
            const end = text.indexOf("'", at + 1);
            if (end < 0) {
                endCommand();
                continue;
            }
            word += text.slice(at + 1, end);
            inWord = true;
            at = end;
            continue;
        }
        if (char === '"') {
            let end = at + 1;
            let quoted = '';
            while (end < text.length && text[end] !== '"') {
                if (text[end] === '\\') {
                    quoted += text[end + 1] ?? '';
                    end += 2;
                    continue;
                }
                if (text[end] === '`' || (text[end] === '$' && text[end + 1] === '(')) {
                    const before = word;
                    word = '';
                    end = substitution(end) + 1;
                    quoted += word;
                    word = before;
                    continue;
                }
                if (text[end] === '$')
                    dynamic = true;
                quoted += text[end];
                end += 1;
            }
            if (end >= text.length) {
                endCommand();
                continue;
            }
            word += quoted;
            inWord = true;
            at = end;
            continue;
        }
        if (char === '`' || (char === '$' && text[at + 1] === '(')) {
            at = substitution(at);
            continue;
        }
        if (char === '$')
            dynamic = true;
        if (char === ' ' || char === '\t') {
            endWord();
            continue;
        }
        if (';&|(){}\n'.includes(char)) {
            endCommand();
            continue;
        }
        word += char;
        inWord = true;
    }
    endCommand();
    return commands;
}
/** Whether `rule` holds for any command of the text, read by the shell parser or, where it cannot, lexically. */
function anyCommand(text, depth, rule) {
    if (depth > MAX_DEPTH)
        return true;
    const segments = (0, hook_tool_policy_1.parseShellSegments)(text);
    if (segments)
        return segments.some((segment) => rule(segment.words, segment.expansions.length > 0, depth));
    const nested = [];
    const commands = lexicalCommands(text, nested);
    // A non-ASCII text, or a STDIN_SHELL that may run a quoted string of it: master's word check.
    if (rule === installerRule && (/[^\x00-\x7f]/.test(text) || commands.some(({ words }) => STDIN_SHELL.test(baseName(programWords(words)[0] ?? '')) && innerCode(programWords(words)) === null)))
        return /control|disable|uninstall|[$`]/i.test(text);
    if (commands.some((command) => rule(command.words, command.dynamic, depth)))
        return true;
    return nested.some((inner) => anyCommand(inner, depth + 1, rule));
}
const installerRule = (all, dynamic, depth) => {
    const words = programWords(all);
    const code = words.length ? innerCode(words) : null;
    if (!words.length || code !== null)
        return code !== null && (/[$`]/.test(code) || anyCommand(code, depth + 1, installerRule));
    const program = words[0];
    const runner = RUNNER.test(baseName(program));
    // CX-A2: a runner whose package or file is a variable or a substitution, in a text that names the installer.
    if (runner && dynamicRunnerArgument(words))
        return true;
    const runs = runner || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
    const args = runs ? installerArguments(words) : null;
    return args !== null && routeArguments(args, dynamic);
};
/** 3.9.113's reading of one parsed command (master's rule, unchanged). */
function masterSegmentIsRoute(segment, depth) {
    let at = 0;
    while (at < segment.words.length && ASSIGNMENT.test(segment.words[at]))
        at += 1;
    while (at < segment.words.length && WRAPPER.test(baseName(segment.words[at]))) {
        at += 1;
        while (at < segment.words.length && (segment.words[at].startsWith('-') || ASSIGNMENT.test(segment.words[at]) || /^\d+$/.test(segment.words[at])))
            at += 1;
    }
    const words = segment.words.slice(at);
    if (!words.length)
        return false;
    if (/^(?:sh|bash|zsh|dash|ksh)$/.test(baseName(words[0]))) {
        const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
        if (flag > 0 && words[flag + 1] !== undefined)
            return masterControlRoute(words[flag + 1], depth + 1);
    }
    const program = words[0];
    const runs = RUNNER.test(baseName(program)) || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
    const args = runs ? installerArguments(words) : null;
    return args !== null && routeArguments(args, segment.expansions.length > 0);
}
/** 3.9.113's text-wide rule (master's answer, unchanged). */
function masterControlRoute(command, depth = 0) {
    try {
        if (typeof command !== 'string' || !INSTALLER_TEXT.test(command))
            return false;
        if (depth > 3)
            return true;
        const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
        // A command the parser cannot read that names the installer next to a control word is held, never guessed at.
        if (!segments)
            return /control|disable|uninstall|[$`]/i.test(command);
        return segments.some((segment) => masterSegmentIsRoute(segment, depth));
    }
    catch {
        return true;
    }
}
/**
 * Ruling R4: the clean L1 shape, the only text where the reader may answer "no route" against master. The text parses, holds no
 * here-doc and no `#`, and every installer mention is a data operand of printf, echo, grep, git, cat, cd or ls (none in a redirect,
 * a substitution or a word the parser joined).
 */
function cleanL1Text(command) {
    if (/<<|#/.test(command))
        return false;
    const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
    if (!segments)
        return false;
    let operands = 0;
    for (const segment of segments) {
        const at = segment.words.findIndex((word) => INSTALLER_TEXT.test(word));
        if (at < 0)
            continue;
        const words = programWords(segment.words);
        const program = segment.words.length - words.length;
        if (!L1_PROGRAM.test(words[0] ?? '') || at <= program || segment.expansions.length > 0)
            return false;
        operands += segment.words.reduce((n, word) => n + (word.match(INSTALLER_TEXT_ALL) ?? []).length, 0);
    }
    return operands >= (command.match(INSTALLER_TEXT_ALL) ?? []).length;
}
// S4 (client round 4): the strict reader. Programs that never run a program, a package or code named in their arguments, stdin or environment.
const DATA_PROGRAMS = new Set(['printf', 'echo', 'cat', 'ls', 'cd', 'pwd', 'wc', 'sort', 'uniq', 'head', 'tail', 'cut', 'tr', 'date', 'basename', 'dirname',
    'true', 'false', 'test', '[', 'realpath', 'readlink', 'stat', 'comm', 'seq', 'sleep', 'grep', 'egrep', 'fgrep', 'jq', 'diff', 'tee', 'git', 'gh', 'find',
    'sed', 'mkdir', 'touch', 'nl', 'du', 'df']);
// Programs with an option that can run a program: an expansion or a glob may never start a word of theirs.
const EXEC_OPTION_PROGRAMS = new Set(['git', 'gh', 'sort', 'find', 'sed']);
const MAX_PROVEN = 8192;
const FIND_BANNED = /^-(?:exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/;
const SED_PRINT = /^(?:\d+|\$)(?:,(?:\d+|\$))?p$/;
const DATA_KEYWORDS = new Set(['do', 'done', 'then', 'fi', 'else', 'elif', 'if', 'while', 'until', '!']);
const GIT_GLOBAL_FLAG = /^(?:--git-dir=.+|--work-tree=.+|--no-pager|-P|--no-replace-objects|--literal-pathspecs|--bare)$/;
const GIT_SUB = new Set(['grep', 'log', 'show', 'ls-tree', 'ls-files', 'rev-parse', 'status', 'diff', 'rev-list', 'describe', 'cat-file', 'shortlog',
    'blame', 'merge-base', 'for-each-ref', 'commit', 'remote']);
const GIT_BANNED_ARG = /^(?:-O|--open-files-in-pager|--ext-diff|--textconv|--filters|--output|--exec|--upload-pack|--receive-pack|--template)/;
// git takes unambiguous long-option prefixes (`--open=`, `--ext`) and short clusters (`-iO...`): either form of a banned option is refused.
const GIT_BANNED_LONG = ['open-files-in-pager', 'ext-diff', 'textconv', 'filters', 'output', 'exec', 'upload-pack', 'receive-pack', 'template'];
const GH_PAIRS = new Set(['api', 'pr view', 'pr list', 'pr checks', 'pr diff', 'pr status', 'run list', 'run view', 'repo view', 'release list',
    'release view', 'issue view', 'issue list']);
const GH_WRITE_ARG = /^(?:-f|-F|--field|--raw-field|--input)(?:=|$)|^-[fF].|^-[^-]*[fF]/;
const BAD_ASSIGN = /^(?:PATH|IFS|BASH_ENV|ENV|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|CDPATH|HOME|LD_\w+|DYLD_\w+|NODE_\w+|NPM_\w+|npm_\w+|GIT_\w+|\w*PAGER|LESS\w*|EDITOR|VISUAL|SHELL|\w*_COMMAND|GH_\w+|BROWSER|TERMINFO|TZDIR|LOCPATH|GCONV_PATH|XDG_\w+|BASH_\w+|PS4|POSIXLY_CORRECT|\w*INIT|VIM\w*|MYVIMRC|EMACS\w*)$/i;
const PLAIN = /^[A-Za-z0-9._/~@+:,=-]+$/;
const DATA_TARGET_RE = /(?:^\/dev\/(?:null|stdout|stderr)$)|^(?![^]*(?:^|\/)\.[^./])[^]*\.(?:md|txt|log|json|jsonl|csv|tsv|out|ya?ml|toml|tsx?|[cm]?js|py|html|css|sql)$/i;
// Never a data target: a file a package manager, the installer or a host runs later.
const RUN_LATER_TARGET = /(?:^|\/)(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|marrow-install(?:\.[cm]?js)?)$|(?:^|\/)node_modules\/|@getmarrow\/install\//i;
const HEREDOC = /<<(-?)[ \t]*(?:'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)"|([A-Za-z0-9_]+))(?=$|[ \t\n;|&><])/y;
/** S4 strict reader: the commands of the text at every depth (into `all`), or null when any byte is outside the modelled grammar. */
function readCommands(text, start, depth, nested, all) {
    if (depth > MAX_DEPTH)
        return null;
    let i = start;
    let cmd = { words: [], redirects: [] };
    let w = null;
    let redirect = null;
    let parens = 0;
    let heredoc = null;
    const word = () => (w ??= { text: '', exps: [], startsDyn: false, optDyn: false, glob: false, quoted: false, lead: '', leadDone: false });
    const exp = (name, quoted) => {
        const cur = word();
        if (cur.text === '' && cur.exps.length === 0)
            cur.startsDyn = true;
        else if (cur.text.startsWith('-') && !cur.text.includes('='))
            cur.optDyn = true;
        cur.leadDone = true;
        cur.exps.push({ name, quoted });
    };
    const endWord = () => {
        if (w && redirect?.needs) {
            redirect.target = w;
            redirect.needs = false;
            cmd.redirects.push(redirect);
            redirect = null;
        }
        else if (w)
            cmd.words.push(w);
        w = null;
    };
    const endCmd = () => {
        endWord();
        if (redirect)
            return false;
        if (cmd.words.length || cmd.redirects.length)
            all.push(cmd);
        cmd = { words: [], redirects: [] };
        return true;
    };
    // `$( )` or backticks, read one level down. While a here-doc waits for its body no substitution (nor a quote across a line) is read.
    const sub = (quoted) => {
        const tick = text[i] === '`';
        const end = tick ? text.indexOf('`', i + 1) : -1;
        if (heredoc || (tick && (end < 0 || text.slice(i + 1, end).includes('\\'))))
            return false;
        const inner = tick ? readCommands(text.slice(i + 1, end), 0, depth + 1, false, all) : readCommands(text, i + 2, depth + 1, true, all);
        if (!inner || (tick && inner.end !== end - i - 1))
            return false;
        exp(tick ? '`' : '$(', quoted);
        i = tick ? end + 1 : inner.end + 1;
        return true;
    };
    const dollar = (quoted) => {
        const rest = text.slice(i);
        if (rest.startsWith('$('))
            return sub(quoted);
        const m = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}/.exec(rest) || /^\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*?$!#-])/.exec(rest);
        if (m) {
            exp(m[1], quoted);
            i += m[0].length;
            return true;
        }
        if (rest.startsWith('${'))
            return false;
        word().text += '$';
        i += 1;
        return true;
    };
    while (i < text.length) {
        const c = text[i];
        const next = text[i + 1];
        if (c === "'") {
            const end = text.indexOf("'", i + 1);
            if (end < 0 || (heredoc && text.slice(i, end).includes('\n')))
                return null;
            const cur = word();
            cur.text += text.slice(i + 1, end);
            cur.quoted = cur.leadDone = true;
            i = end + 1;
        }
        else if (c === '"') {
            const cur = word();
            cur.quoted = cur.leadDone = true;
            for (i += 1; text[i] !== '"';) {
                const d = text[i];
                if (d === undefined || (d === '\n' && heredoc))
                    return null;
                if (d === '\\') {
                    const e = text[i + 1];
                    if (e === undefined || e === '\n')
                        return null;
                    cur.text += '$`"\\'.includes(e) ? e : `\\${e}`;
                    i += 2;
                }
                else if (d === '$' || d === '`') {
                    if (!(d === '$' ? dollar(true) : sub(true)))
                        return null;
                }
                else {
                    cur.text += d;
                    i += 1;
                }
            }
            i += 1;
        }
        else if (c === '\\' || c === '{' || c === '}')
            return null;
        // W2: a comment starts only at the start of a word outside quotes and runs to the newline (bash's rule).
        else if (c === '#' && !w) {
            while (i < text.length && text[i] !== '\n')
                i += 1;
        }
        else if (c === '$' || c === '`') {
            if (!(c === '$' ? dollar(false) : sub(false)))
                return null;
        }
        else if (c === '(') {
            // A subshell opens only where a command starts (after nothing or after keywords such as `do`).
            if (w || redirect || cmd.words.some((x) => !(literal(x) && !x.quoted && DATA_KEYWORDS.has(x.text))))
                return null;
            parens += 1;
            i += 1;
        }
        else if (c === ')') {
            if (!endCmd())
                return null;
            if (parens === 0)
                return nested ? { end: i } : null;
            parens -= 1;
            i += 1;
        }
        else if (c === ' ' || c === '\t') {
            endWord();
            i += 1;
        }
        else if (c === '\n' && heredoc) {
            // W1: the body runs to the first line that equals the delimiter exactly (leading tabs dropped for <<-); none = unread.
            const doc = heredoc;
            const lines = text.slice(i + 1).split('\n');
            const at = lines.findIndex((line) => (doc.strip ? line.replace(/^\t+/, '') : line) === doc.delim);
            if (!endCmd() || at < 0 || (!doc.quoted && /[$`\\]/.test(lines.slice(0, at).join('\n'))))
                return null;
            i = Math.min(text.length, i + 2 + lines.slice(0, at + 1).join('\n').length);
            heredoc = null;
        }
        else if (c === '\n' || c === ';') {
            if (!endCmd())
                return null;
            i += 1;
        }
        else if (c === '|' || (c === '&' && next !== '>')) {
            if (!endCmd())
                return null;
            i += next === '|' || next === '&' ? 2 : 1;
        }
        else if (c === '>' || c === '<' || c === '&') {
            const fd = w;
            if (fd && literal(fd) && !fd.quoted && /^\d+$/.test(fd.text))
                w = null;
            else
                endWord();
            if (redirect)
                return null;
            if (c === '<' && next === '<' && text[i + 2] === '<') {
                redirect = { out: false, needs: true, target: null };
                i += 3;
                continue;
            }
            if (c === '<' && next === '<') {
                HEREDOC.lastIndex = i;
                const m = HEREDOC.exec(text);
                if (nested || depth > 0 || heredoc || !m)
                    return null;
                heredoc = { delim: m[2] ?? m[3] ?? m[4], quoted: m[4] === undefined, strip: m[1] === '-' };
                i += m[0].length;
                continue;
            }
            let j = i + 1;
            let out = c !== '<';
            if (c === '&')
                j = text[i + 2] === '>' ? i + 3 : i + 2;
            else if (c === '>' && (text[j] === '>' || text[j] === '|'))
                j += 1;
            else if (c === '<' && text[j] === '>') {
                out = true;
                j += 1;
            }
            const dup = c !== '&' && text[j] === '&' ? /^(\d+|-)/.exec(text.slice(j + 1)) : undefined;
            if (dup === null)
                return null;
            if (dup)
                i = j + 1 + dup[0].length;
            else {
                redirect = { out, needs: true, target: null };
                i = j;
            }
        }
        else {
            const cur = word();
            if (c === '*' || c === '?' || c === '[')
                cur.glob = true;
            cur.text += c;
            if (!cur.leadDone)
                cur.lead += c;
            i += 1;
        }
    }
    return nested || parens !== 0 || heredoc || !endCmd() ? null : { end: i };
}
function literal(w) { return w.exps.length === 0; }
/**
 * S4 PROVEN-DATA (LOWER-SHAPES r4, C0-C6, C8): whether the strict reader proves every command of the whole text, at every depth, is a
 * data program with data arguments and data-only write targets. Any doubt, any unread byte or any throw is false (the c5af0d83 answer).
 */
function provenDataText(text) {
    try {
        if (typeof text !== 'string' || !INSTALLER_TEXT.test(text) || text.length > MAX_PROVEN)
            return false;
        if (/[^\x20-\x7e\n\t]/.test(text) || /<\(|>\(|\(\(|\$\[|\$'|\$"|;;|\$\{#/.test(text))
            return false;
        const commands = [];
        if (readCommands(text, 0, 0, false, commands)?.end !== text.length)
            return false;
        const bare = (x, word) => !!x && literal(x) && !x.quoted && (word === undefined || x.text === word);
        const forVars = new Map();
        // First pass: for-loop variables and their lists (a variable reaches an exec-option program only from a list of plain words).
        for (const c of commands.filter((x) => bare(x.words[0], 'for'))) {
            const [, name, inWord, ...list] = c.words;
            if (!bare(name) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name.text) || BAD_ASSIGN.test(name.text) || !bare(inWord, 'in'))
                return false;
            const plain = list.every((x) => literal(x) && !x.glob && PLAIN.test(x.text) && !x.text.startsWith('-'));
            forVars.set(name.text, plain && forVars.get(name.text) !== false);
        }
        // A `cd` moves every relative write target: with one in the text, only /dev/null, stdout and stderr stay data targets.
        const moved = commands.some((c) => c.words.some((x) => bare(x, 'cd')));
        const target = (x) => !!x && literal(x) && !x.glob && DATA_TARGET_RE.test(x.text) && !RUN_LATER_TARGET.test(x.text) && (!moved || x.text.startsWith('/dev/'));
        for (const c of commands) {
            if (c.redirects.some((r) => r.out && !target(r.target)))
                return false;
            if (bare(c.words[0], 'for'))
                continue;
            let at = 0;
            for (let begin = -1; begin !== at;) {
                begin = at;
                while (at < c.words.length && bare(c.words[at]) && DATA_KEYWORDS.has(c.words[at].text))
                    at += 1;
                for (; at < c.words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(c.words[at].lead); at += 1) {
                    if (BAD_ASSIGN.test(c.words[at].text.split('=')[0]) || INSTALLER_TEXT.test(c.words[at].text))
                        return false;
                }
            }
            const [prog, ...args] = c.words.slice(at);
            if (!prog)
                continue;
            if (!bare(prog) || (prog.glob && prog.text !== '[') || !DATA_PROGRAMS.has(prog.text))
                return false;
            const [p, argText] = [prog.text, args.map((x) => x.text)];
            const has = (re) => argText.some((t) => re.test(t));
            if (p === 'printf' && has(/^-v/))
                return false;
            // bash's test -v / -R expand an array subscript (and so a substitution in it).
            if ((p === 'test' || p === '[') && has(/^-[vR]$/))
                return false;
            // sort -o, also in a short cluster (`-uo`), and its long-option prefixes (`--out=`, `--co`) write a file or run a program.
            if (p === 'sort' && has(/^(?:--compress|--output|-o)|^--(?:o|co)|^-[^-]*o/))
                return false;
            // uniq's second operand is an output file.
            if (p === 'uniq' && argText.filter((t) => !t.startsWith('-')).length > 1)
                return false;
            if (p === 'tee' && args.some((x) => !x.text.startsWith('-') && !target(x)))
                return false;
            if (p === 'find' && has(FIND_BANNED))
                return false;
            if (p === 'sed' && (!args.every(literal) || has(/^-(?!(?:n|E|r|s|-quiet|-silent)$)/) || !has(/^(?:-n|--quiet|--silent)$/)
                || !SED_PRINT.test(argText.find((t) => !t.startsWith('-')) ?? '')))
                return false;
            if (EXEC_OPTION_PROGRAMS.has(p) && args.some((x) => x.startsDyn || x.optDyn || (x.glob && !x.quoted) || x.exps.some((e) => !e.quoted && forVars.get(e.name) !== true)))
                return false;
            if (p === 'git') {
                let k = 0;
                for (; k < args.length && args[k].text.startsWith('-'); k += 1) {
                    if (args[k].text === '-C' && literal(args[k]))
                        k += 1;
                    else if (!GIT_GLOBAL_FLAG.test(args[k].text))
                        return false;
                }
                const rest = argText.slice(k + 1);
                if (!args[k] || !literal(args[k]) || !GIT_SUB.has(args[k].text))
                    return false;
                if (rest.some((t) => GIT_BANNED_ARG.test(t) || /^-[^-]*O/.test(t) || (/^--[^=]/.test(t) && GIT_BANNED_LONG.some((name) => name.startsWith(t.slice(2).split('=')[0])))))
                    return false;
                if (args[k].text === 'remote' && !(rest.length === 1 && rest[0] === '-v') && rest[0] !== 'get-url')
                    return false;
            }
            if (p === 'gh' && (!GH_PAIRS.has(argText[0] === 'api' ? 'api' : `${argText[0]} ${argText[1]}`) || has(GH_WRITE_ARG) || has(/^-[^-X]+X/)
                || argText.some((t, k) => ((t === '-X' || t === '--method') && argText[k + 1] !== 'GET') || (/^(?:-X|--method=)./.test(t) && !/^(?:-XGET|--method=GET)$/.test(t)))))
                return false;
        }
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command.
 * `proven` (round 4, S4): a route stands unless it proves the whole text is data; a throw in it keeps the route (the c5af0d83 answer).
 */
function controlRoute(command, depth = 0, proven = provenDataText) {
    try {
        if (typeof command !== 'string' || !INSTALLER_TEXT.test(command))
            return false;
        if (command.length > MAX_READ)
            return /control|disable|uninstall|[$`]/i.test(command);
        // R4: outside the clean L1 shape, master's route stands (a route if either reading says route).
        if (!anyCommand(command, depth, installerRule) && (cleanL1Text(command) || !masterControlRoute(command, depth)))
            return false;
        try {
            return proven(command) !== true;
        }
        catch {
            return true;
        }
    }
    catch {
        return true;
    }
}
/** Whether a text holds a gate receipt's host-approval or approval-link path (any case, `%2F`, doubled slashes). */
function approvalReportUrl(text) {
    const path = text.toLowerCase().replace(/%2f/g, '/').replace(/\/{2,}/g, '/');
    const at = path.indexOf('/gate-receipts/');
    return at >= 0 && (path.includes('/host-approval', at) || path.includes('/approval-link', at));
}
/**
 * M-SELF-APPROVE (g): a shell text that reports an approval for a gate receipt: a request client or an interpreter (its code,
 * a here-doc or piped stdin) in a text that holds the approval path, or a run of a host-report or approval-link script as the
 * program or an interpreter's script. A grep, a printf, a cat or a commit message that only names it is not one.
 */
function selfApproveRoute(command) {
    try {
        if (typeof command !== 'string')
            return false;
        const url = approvalReportUrl(command);
        if (!url && !REPORT_TEXT.test(command))
            return false;
        if (command.length > MAX_READ)
            return true;
        const rule = (all, _dynamic, depth) => {
            const words = programWords(all);
            if (!words.length || (innerCode(words) !== null && anyCommand(innerCode(words), depth + 1, rule)))
                return words.length > 0;
            const program = baseName(words[0]);
            if (REPORT_SCRIPT.test(program))
                return true;
            if (url && (INTERPRETER.test(program) || HTTP_CLIENT.test(program) || SHELL_PROGRAM.test(program)))
                return true;
            if (!INTERPRETER.test(program))
                return false;
            const script = words.slice(1).find((word) => !word.startsWith('-'));
            return script !== undefined && REPORT_SCRIPT.test(baseName(script));
        };
        return anyCommand(command, 0, rule);
    }
    catch {
        return true;
    }
}
//# sourceMappingURL=control-routes.js.map