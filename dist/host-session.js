"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.localInteractiveSession = localInteractiveSession;
const node_child_process_1 = require("node:child_process");
const node_fs_1 = require("node:fs");
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
//# sourceMappingURL=host-session.js.map