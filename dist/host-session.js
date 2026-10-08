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
const CODEX_SETTING_KEYS = new Set(['approval_policy', 'approvals_reviewer', 'sandbox_mode', 'profile']);
/** Codex flags that turn its approval prompt off for the session. */
const CODEX_NO_PROMPT_FLAGS = new Set([
    '--dangerously-bypass-approvals-and-sandbox', '--yolo', '--full-auto', '--approve-for-me', '--not-so-yolo',
]);
const MAX_CONFIG_BYTES = 256 * 1024;
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
/**
 * Only approval_policy, approvals_reviewer, sandbox_mode and profile are
 * kept, at the top level and per profile; every other line is skipped.
 */
function parseCodexSettings(text) {
    const top = {};
    const profiles = {};
    let table = null;
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#'))
            continue;
        const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
        if (header) {
            table = header[1];
            continue;
        }
        const pair = /^([A-Za-z0-9_."-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([A-Za-z0-9_.-]+))\s*(?:#.*)?$/.exec(line);
        if (!pair)
            continue;
        const key = pair[1].replace(/"/g, '');
        const value = pair[2] ?? pair[3] ?? pair[4];
        let target = null;
        let name = key;
        if (table === null) {
            const dotted = /^profiles\.([^.]+)\.([a-z_]+)$/.exec(key);
            if (dotted) {
                target = (profiles[dotted[1]] ??= {});
                name = dotted[2];
            }
            else {
                target = top;
            }
        }
        else {
            const profile = /^profiles\.(?:"([^"]+)"|([^."]+))$/.exec(table);
            if (profile)
                target = (profiles[profile[1] ?? profile[2]] ??= {});
        }
        if (target && CODEX_SETTING_KEYS.has(name))
            target[name] = value;
    }
    return { top, profiles };
}
function stripTomlQuotes(value) {
    return value.trim().replace(/^"([^"]*)"$|^'([^']*)'$/, (_match, double, single) => double ?? single ?? '');
}
/**
 * Whether Codex, as started, shows no approval prompt for a held action:
 * approval bypass (`--dangerously-bypass-approvals-and-sandbox`, `--yolo`),
 * never-ask (`-a never`), automatic review (`--approve-for-me`,
 * `approvals_reviewer`), `--full-auto`, or full access (`-s
 * danger-full-access`), on the command line, in `-c` overrides, or in its
 * config (`$CODEX_HOME/config.toml`, a `-p` profile file and the active
 * profile table). Later sources override earlier ones as Codex applies them:
 * config, profile, `-c`, flags.
 */
function codexApprovalPromptOff(args, readConfig = readConfigFile, env = process.env) {
    const tokens = args.slice(1);
    const cli = {};
    const overrides = {};
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
            cli.approval_policy = approval.value;
            i = approval.next;
            continue;
        }
        const sandbox = take(i, '--sandbox', '-s');
        if (sandbox) {
            cli.sandbox_mode = sandbox.value;
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
            const pair = /^([A-Za-z_.]+)\s*=(.*)$/s.exec(config.value);
            if (pair && CODEX_SETTING_KEYS.has(pair[1]))
                overrides[pair[1]] = stripTomlQuotes(pair[2]);
            i = config.next;
        }
    }
    const home = env.CODEX_HOME && env.CODEX_HOME.trim() ? env.CODEX_HOME : (0, node_path_1.join)((0, node_os_1.homedir)(), '.codex');
    const base = (() => { const text = readConfig((0, node_path_1.join)(home, 'config.toml')); return text === null ? { top: {}, profiles: {} } : parseCodexSettings(text); })();
    const profileName = cli.profile ?? overrides.profile ?? base.top.profile;
    const validName = typeof profileName === 'string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/.test(profileName) ? profileName : null;
    const profileFile = validName ? readConfig((0, node_path_1.join)(home, `${validName}.config.toml`)) : null;
    const layers = [
        base.top,
        validName ? base.profiles[validName] ?? {} : {},
        profileFile === null ? {} : parseCodexSettings(profileFile).top,
        overrides,
        cli,
    ];
    const effective = (key) => {
        let value;
        for (const layer of layers)
            if (layer[key] !== undefined)
                value = layer[key];
        return value?.toLowerCase();
    };
    if (effective('approval_policy') === 'never')
        return true;
    const reviewer = effective('approvals_reviewer');
    if (reviewer !== undefined && reviewer !== 'user')
        return true;
    return effective('sandbox_mode') === 'danger-full-access';
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