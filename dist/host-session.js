"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.localInteractiveSession = localInteractiveSession;
exports.parseCodexSettings = parseCodexSettings;
exports.codexApprovalPromptOff = codexApprovalPromptOff;
exports.hostApprovalPromptOff = hostApprovalPromptOff;
const node_child_process_1 = require("node:child_process");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const MAX_DEPTH = 8;
const CODEX_NON_INTERACTIVE = new Set([
    'exec', 'e', 'app-server', 'mcp', 'mcp-server', 'proto', 'cloud', 'apply', 'a', 'review',
    'login', 'logout', 'completion', 'debug', 'sandbox', 'features', '--json',
]);
function linuxProcess(pid) {
    try {
        const stat = (0, node_fs_1.readFileSync)(`/proc/${pid}/stat`, 'utf8');
        const close = stat.lastIndexOf(')');
        const fields = stat.slice(close + 2).split(' ');
        const ppid = Number(fields[1]);
        const args = (0, node_fs_1.readFileSync)(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean).slice(0, 64);
        let terminal = false;
        try {
            const stdin = (0, node_fs_1.readlinkSync)(`/proc/${pid}/fd/0`);
            terminal = /^\/dev\/(?:pts\/\d+|tty\w*)$/.test(stdin);
        }
        catch {
            terminal = false;
        }
        return Number.isSafeInteger(ppid) ? { pid, ppid, args, terminal } : null;
    }
    catch {
        return null;
    }
}
function psProcess(pid) {
    try {
        const line = (0, node_child_process_1.execFileSync)('ps', ['-o', 'ppid=,tty=,command=', '-p', String(pid)], {
            encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'],
        }).trim();
        const match = line.match(/^(\d+)\s+(\S+)\s+(.*)$/s);
        if (!match)
            return null;
        return { pid, ppid: Number(match[1]), args: match[3].split(/\s+/).slice(0, 64), terminal: !/^(?:\?\??|-)$/.test(match[2]) };
    }
    catch {
        return null;
    }
}
const TEST_PROCESS_TABLE = Symbol.for('marrow.test.processTable');
function defaultReader() {
    // Test seam: a preloaded test module may supply a synthetic process table.
    const table = globalThis[TEST_PROCESS_TABLE];
    if (table && typeof table === 'object') {
        return (pid) => (table[String(pid)] ?? null);
    }
    if (process.platform === 'linux')
        return linuxProcess;
    if (process.platform === 'darwin' || process.platform === 'freebsd')
        return psProcess;
    return () => null;
}
function programNames(args) {
    return args.slice(0, 2).map((arg) => (0, node_path_1.basename)(arg).toLowerCase());
}
function isCodex(args) {
    return programNames(args).some((name) => /^codex(?:-[a-z0-9_.-]+)?(?:\.exe|\.js|\.mjs)?$/.test(name));
}
function isGemini(args) {
    return programNames(args).some((name) => /^gemini(?:\.exe|\.js|\.mjs)?$/.test(name));
}
/** The editor app (VS Code and its forks) or its extension host, where Cline and Windsurf's Cascade run for a person. */
function isEditorApp(args) {
    const names = programNames(args);
    if (names.some((name) => /^(?:code|code-insiders|codium|vscodium|windsurf|windsurf-next|code helper(?: \(plugin\))?)(?:\.exe)?$/.test(name)))
        return true;
    return args.slice(0, 8).some((arg) => /^--type=extensionHost$/.test(arg) || /[/\\](?:Visual Studio Code|VSCodium|Windsurf)(?:\.app)?[/\\]/i.test(arg));
}
function isGrokCli(args) {
    return programNames(args).some((name) => /^grok(?:\.exe|\.js|\.mjs)?$/.test(name));
}
function isClineCli(args) {
    return programNames(args).some((name) => /^cline(?:\.exe|\.js|\.mjs)?$/.test(name));
}
function findHostProcess(match, reader, startPid) {
    let pid = startPid;
    for (let depth = 0; depth < MAX_DEPTH && pid > 1; depth += 1) {
        const info = reader(pid);
        if (!info)
            return null;
        if (match(info.args))
            return info;
        pid = info.ppid;
    }
    return null;
}
/** true only with positive evidence; false or null means no typed approval is offered. */
function localInteractiveSession(host, reader = defaultReader(), startPid = process.ppid) {
    if (host === 'codex') {
        const codex = findHostProcess(isCodex, reader, startPid);
        if (!codex)
            return null;
        const tokens = codex.args.slice(1).map((arg) => arg.toLowerCase());
        return codex.terminal && !tokens.some((token) => CODEX_NON_INTERACTIVE.has(token));
    }
    if (host === 'grok') {
        const grok = findHostProcess(isGrokCli, reader, startPid);
        if (!grok)
            return null;
        const tokens = grok.args.slice(1).map((arg) => arg.toLowerCase());
        return grok.terminal && !tokens.some((token) => ['-p', '--prompt', '--print', '--headless', '--json'].includes(token) || token.startsWith('--prompt='));
    }
    if (host === 'cline' || host === 'windsurf') {
        // In the editor a person is at the session; the Cline CLI counts only with a terminal and no scripted mode.
        const editor = findHostProcess(isEditorApp, reader, startPid);
        if (editor)
            return true;
        if (host === 'cline') {
            const cli = findHostProcess(isClineCli, reader, startPid);
            if (!cli)
                return null;
            const tokens = cli.args.slice(1).map((arg) => arg.toLowerCase());
            return cli.terminal && !tokens.some((token) => ['-p', '--prompt', '--yolo', '--json', '--headless', '--oneshot', 'task'].includes(token));
        }
        return null;
    }
    if (host === 'gemini') {
        const gemini = findHostProcess(isGemini, reader, startPid);
        if (!gemini)
            return null;
        const tokens = gemini.args.slice(1);
        const scripted = tokens.some((token) => token === '-p' || token === '--prompt' || token.startsWith('--prompt=')
            || token === '--experimental-acp' || token === '--acp');
        return gemini.terminal && !scripted;
    }
    return null;
}
// ---------------------------------------------------------------------------
// The host's own approval prompt
// ---------------------------------------------------------------------------
const CODEX_KEYS = ['approval_policy', 'approvals_reviewer', 'sandbox_mode'];
/** Codex flags that turn its approval prompt off for the session. */
const CODEX_NO_PROMPT_FLAGS = new Set([
    '--dangerously-bypass-approvals-and-sandbox', '--yolo', '--full-auto', '--approve-for-me', '--not-so-yolo',
]);
const MAX_CONFIG_BYTES = 256 * 1024;
const RELEVANT_KEY_NAME = /(?:^|[^A-Za-z0-9_])(?:approval_policy|approvals_reviewer|sandbox_mode|profiles?)(?:$|[^A-Za-z0-9_])/;
/** Reads a config file into memory (never logged); null when missing, unreadable or too large. */
function readConfigFile(path) {
    try {
        if ((0, node_fs_1.statSync)(path).size > MAX_CONFIG_BYTES)
            return null;
        return (0, node_fs_1.readFileSync)(path, 'utf8');
    }
    catch {
        return null;
    }
}
class TomlError extends Error {
}
/**
 * A small TOML reader for the keys above only: tables and array tables,
 * dotted and quoted keys, basic, literal and multi-line strings, inline
 * tables and arrays. Values of every other key are skipped and never kept.
 */
function parseCodexSettings(input) {
    const text = input.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    const result = { top: {}, profiles: {}, unreadable: false };
    const n = text.length;
    let i = 0;
    let table = [];
    const fail = () => { throw new TomlError(); };
    const skipSpaces = () => { while (i < n && (text[i] === ' ' || text[i] === '\t'))
        i += 1; };
    const skipComment = () => { if (text[i] === '#')
        while (i < n && text[i] !== '\n')
            i += 1; };
    const skipBlank = () => {
        for (;;) {
            skipSpaces();
            skipComment();
            if (text[i] !== '\n')
                return;
            i += 1;
        }
    };
    const record = (path, value) => {
        if (path.length === 1 && (CODEX_KEYS.includes(path[0]) || path[0] === 'profile')) {
            result.top[path[0]] = value;
        }
        else if (path.length === 3 && path[0] === 'profiles' && CODEX_KEYS.includes(path[2])) {
            (result.profiles[path[1]] ??= {})[path[2]] = value;
        }
    };
    const multiline = (quote) => {
        i += 3;
        if (text[i] === '\n')
            i += 1;
        const close = text.indexOf(quote.repeat(3), i);
        if (close < 0)
            fail();
        let end = close;
        while (text[end + 3] === quote && end - close < 2)
            end += 1;
        const value = text.slice(i, end);
        i = end + 3;
        return value;
    };
    const basicString = () => {
        if (text.startsWith('"""', i))
            return multiline('"').replace(/\\\n[ \t\n]*/g, '').replace(/\\(["\\])/g, '$1');
        i += 1;
        let out = '';
        while (i < n && text[i] !== '"') {
            if (text[i] === '\n')
                fail();
            if (text[i] === '\\') {
                const next = text[i + 1];
                const simple = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '"': '"', '\\': '\\' };
                if (next in simple) {
                    out += simple[next];
                    i += 2;
                    continue;
                }
                const width = next === 'u' ? 4 : next === 'U' ? 8 : 0;
                const hex = text.slice(i + 2, i + 2 + width);
                if (!width || hex.length !== width || !/^[0-9A-Fa-f]+$/.test(hex))
                    fail();
                out += String.fromCodePoint(parseInt(hex, 16));
                i += 2 + width;
                continue;
            }
            out += text[i];
            i += 1;
        }
        if (text[i] !== '"')
            fail();
        i += 1;
        return out;
    };
    const literalString = () => {
        if (text.startsWith("'''", i))
            return multiline("'");
        const close = text.indexOf("'", i + 1);
        const newline = text.indexOf('\n', i + 1);
        if (close < 0 || (newline >= 0 && newline < close))
            fail();
        const value = text.slice(i + 1, close);
        i = close + 1;
        return value;
    };
    const keyPart = () => {
        skipSpaces();
        if (text[i] === '"')
            return basicString();
        if (text[i] === "'")
            return literalString();
        const bare = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 256));
        if (!bare)
            return fail();
        i += bare[0].length;
        return bare[0];
    };
    const key = () => {
        const parts = [keyPart()];
        for (;;) {
            skipSpaces();
            if (text[i] !== '.')
                return parts;
            i += 1;
            parts.push(keyPart());
        }
    };
    const value = (path, depth) => {
        if (depth > 16)
            fail();
        skipSpaces();
        const c = text[i];
        if (c === '"') {
            record(path, basicString());
            return;
        }
        if (c === "'") {
            record(path, literalString());
            return;
        }
        if (c === '{' || c === '[') {
            const close = c === '{' ? '}' : ']';
            i += 1;
            skipBlank();
            if (text[i] === close) {
                i += 1;
                return;
            }
            for (;;) {
                if (c === '{') {
                    const inner = key();
                    skipSpaces();
                    if (text[i] !== '=')
                        fail();
                    i += 1;
                    value([...path, ...inner], depth + 1);
                }
                else {
                    value([...path, '[]'], depth + 1);
                }
                skipBlank();
                if (text[i] === ',') {
                    i += 1;
                    skipBlank();
                    if (text[i] === close) {
                        i += 1;
                        return;
                    }
                    continue;
                }
                if (text[i] === close) {
                    i += 1;
                    return;
                }
                fail();
            }
        }
        const bare = /^[A-Za-z0-9_+.:-]+/.exec(text.slice(i, i + 128));
        if (!bare)
            return fail();
        i += bare[0].length;
        record(path, bare[0]);
    };
    while (i < n) {
        const lineStart = i;
        try {
            skipBlank();
            if (i >= n)
                break;
            if (text[i] === '[') {
                const arrayTable = text[i + 1] === '[';
                i += arrayTable ? 2 : 1;
                const header = key();
                skipSpaces();
                if (arrayTable ? !text.startsWith(']]', i) : text[i] !== ']')
                    fail();
                i += arrayTable ? 2 : 1;
                table = arrayTable ? [...header, '[]'] : header;
            }
            else {
                const name = key();
                skipSpaces();
                if (text[i] !== '=')
                    fail();
                i += 1;
                value([...table, ...name], 0);
            }
            skipSpaces();
            skipComment();
            if (i < n && text[i] !== '\n')
                fail();
        }
        catch (error) {
            if (!(error instanceof TomlError))
                throw error;
            // This line could not be read. If it names a key that decides the prompt, treat the prompt as off.
            const lineEnd = text.indexOf('\n', Math.max(i, lineStart));
            const stop = lineEnd < 0 ? n : lineEnd;
            if (RELEVANT_KEY_NAME.test(text.slice(lineStart, stop)))
                result.unreadable = true;
            i = stop + 1;
        }
    }
    return result;
}
function emptySettings() {
    return { top: {}, profiles: {}, unreadable: false };
}
/** A `-c key=value` override: the value is TOML, or a plain string when it is not (as Codex reads it). */
function parseCodexOverride(text) {
    const equals = text.indexOf('=');
    if (equals < 0) {
        const settings = emptySettings();
        settings.unreadable = RELEVANT_KEY_NAME.test(text);
        return settings;
    }
    const keyText = text.slice(0, equals).trim();
    const valueText = text.slice(equals + 1).trim();
    const parsed = parseCodexSettings(`${keyText} = ${valueText}\n`);
    if (!parsed.unreadable)
        return parsed;
    return parseCodexSettings(`${keyText} = ${JSON.stringify(valueText)}\n`);
}
function mergeSettings(into, from) {
    Object.assign(into.top, from.top);
    for (const [name, values] of Object.entries(from.profiles))
        Object.assign((into.profiles[name] ??= {}), values);
    into.unreadable = into.unreadable || from.unreadable;
}
/**
 * Whether Codex, as started, shows no approval prompt for a held action:
 * approval bypass (`--dangerously-bypass-approvals-and-sandbox`, `--yolo`),
 * never-ask (`-a never`), automatic review (`--approve-for-me`, or an
 * `approvals_reviewer` other than `user`), `--full-auto`, or full access
 * (`-s danger-full-access`), on the command line, in `-c` overrides
 * (including `profiles.NAME.key`), or in its config: `$CODEX_HOME/config.toml`
 * with its active profile, and a `-p NAME` profile file. A flag decides its
 * own setting; otherwise any of those sources that turns the prompt off
 * counts, since their order cannot be known for certain from outside Codex.
 * A line naming one of these keys that cannot be read also counts as off.
 */
function codexApprovalPromptOff(args, readConfig = readConfigFile, env = process.env) {
    const tokens = args.slice(1);
    const cli = {};
    const overrides = emptySettings();
    const take = (i, long, short) => {
        const token = tokens[i];
        if (token === long || (short && token === short))
            return i + 1 < tokens.length ? { value: tokens[i + 1], next: i + 1 } : null;
        if (token.startsWith(`${long}=`))
            return { value: token.slice(long.length + 1), next: i };
        if (short && token.startsWith(short) && !token.startsWith('--') && token.length > short.length)
            return { value: token.slice(short.length).replace(/^=/, ''), next: i };
        return null;
    };
    for (let i = 0; i < tokens.length; i += 1) {
        const token = tokens[i];
        if (CODEX_NO_PROMPT_FLAGS.has(token))
            return true;
        const approval = take(i, '--ask-for-approval', '-a');
        if (approval) {
            cli.approval = approval.value;
            i = approval.next;
            continue;
        }
        const sandbox = take(i, '--sandbox', '-s');
        if (sandbox) {
            cli.sandbox = sandbox.value;
            i = sandbox.next;
            continue;
        }
        const profile = take(i, '--profile', '-p');
        if (profile) {
            cli.profile = profile.value;
            i = profile.next;
            continue;
        }
        const config = take(i, '--config', '-c');
        if (config) {
            mergeSettings(overrides, parseCodexOverride(config.value));
            i = config.next;
        }
    }
    if (overrides.unreadable)
        return true;
    const home = env.CODEX_HOME && env.CODEX_HOME.trim() ? env.CODEX_HOME : (0, node_path_1.join)((0, node_os_1.homedir)(), '.codex');
    const baseText = readConfig((0, node_path_1.join)(home, 'config.toml'));
    const base = baseText === null ? emptySettings() : parseCodexSettings(baseText);
    if (base.unreadable)
        return true;
    const profileName = cli.profile ?? overrides.top.profile ?? base.top.profile;
    const validName = typeof profileName === 'string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/.test(profileName) ? profileName : null;
    const fileText = validName ? readConfig((0, node_path_1.join)(home, `${validName}.config.toml`)) : null;
    const file = fileText === null ? emptySettings() : parseCodexSettings(fileText);
    if (file.unreadable)
        return true;
    const sources = [base.top, file.top, overrides.top];
    if (validName)
        sources.push(base.profiles[validName] ?? {}, file.profiles[validName] ?? {}, overrides.profiles[validName] ?? {});
    const anyOff = (key, off) => sources.some((source) => source[key] !== undefined && off(source[key].trim().toLowerCase()));
    const approvalOff = cli.approval !== undefined ? cli.approval.trim().toLowerCase() === 'never' : anyOff('approval_policy', (value) => value === 'never');
    const sandboxOff = cli.sandbox !== undefined ? cli.sandbox.trim().toLowerCase() === 'danger-full-access' : anyOff('sandbox_mode', (value) => value === 'danger-full-access');
    const reviewerOff = anyOff('approvals_reviewer', (value) => value !== 'user');
    return approvalOff || sandboxOff || reviewerOff;
}
/**
 * Whether the host's own approval prompt is off in this session, so leaving a
 * held action to it would let it run with no one asked. Codex is read from
 * its process and config (see codexApprovalPromptOff). Cline's auto-approve
 * and Windsurf's Turbo mode live in editor state with no reliable signal, so
 * they are not detected (false).
 */
function hostApprovalPromptOff(host, reader = defaultReader(), startPid = process.ppid, readConfig = readConfigFile) {
    if (host !== 'codex')
        return false;
    const codex = findHostProcess(isCodex, reader, startPid);
    if (!codex)
        return false;
    return codexApprovalPromptOff(codex.args, readConfig);
}
//# sourceMappingURL=host-session.js.map