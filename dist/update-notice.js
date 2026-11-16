"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateNoticeOff = updateNoticeOff;
exports.updateNoticeLine = updateNoticeLine;
exports.hookUpdateNotice = hookUpdateNotice;
exports.withPreActionNotice = withPreActionNotice;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
const hook_context_1 = require("./hook-context");
const hook_contract_1 = require("./hook-contract");
const request_reliability_1 = require("./request-reliability");
// The update notice (FIXVER N1-N5): one fixed line built here from two strict versions and the client's own update
// command, never a server string. It changes no decision, hold, key, body or event; it is only printed.
const STATE_NAME = 'update-notice.json';
const STATE_LIMIT = 1024;
/** N5: MARROW_UPDATE_NOTICE=off (also 0, false, no): no line on any surface and no state read or write. */
function updateNoticeOff() {
    return ['off', '0', 'false', 'no'].includes(process.env.MARROW_UPDATE_NOTICE);
}
// A plain release: three dot-separated runs of ASCII digits, nothing else.
function plainRelease(value) {
    return typeof value === 'string' && value.length <= 32 && /^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$/.test(value);
}
function notice(answer) {
    const strict = updateNoticeOff() ? null : (0, hook_context_1.strictClientUpdate)(answer);
    if (!strict || (strict.priority !== 'recommended' && strict.priority !== 'security_required'))
        return null;
    // N1: the raw fields exactly: this client's own version and a plain newer release.
    const installed = strict.update.installed_version;
    const latest = strict.update.latest_version;
    if (installed !== hook_contract_1.MCP_ADAPTER_VERSION || !plainRelease(latest) || strict.currentVersion !== installed || strict.latestVersion !== latest)
        return null;
    const head = strict.priority === 'security_required' ? 'Marrow security update' : 'Marrow update';
    const line = `${head}: this agent runs @getmarrow/mcp ${installed}; ${latest} is out. Tell the user to run: ${(0, request_reliability_1.localClientUpdate)().auto_update_command} (then restart the host).`;
    return line.length <= 200 ? { line, installed, latest } : null;
}
/** The status tool's line: shown on every call while N1 holds (no state). */
function updateNoticeLine(...answers) {
    return answers.map(notice).find(Boolean)?.line ?? null;
}
// N4: the owner-private Marrow state folder, checked like the lifecycle spool parent (no symlinked component, no
// group- or world-writable non-sticky ancestor, owned by this user, owner-only). Null = unsafe.
function stateFolder() {
    if (process.platform === 'win32' || typeof process.getuid !== 'function')
        return null;
    const folder = (0, path_1.join)((0, path_1.resolve)((0, os_1.homedir)()), '.marrow');
    try {
        (0, fs_1.mkdirSync)(folder, { mode: 0o700 });
    }
    catch (error) {
        if (error.code !== 'EEXIST')
            return null;
    }
    let current = (0, path_1.parse)(folder).root;
    for (const segment of folder.slice(current.length).split(path_1.sep).filter(Boolean)) {
        current = (0, path_1.join)(current, segment);
        const stat = (0, fs_1.lstatSync)(current);
        if (stat.isSymbolicLink() || !stat.isDirectory() || ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0))
            return null;
    }
    const stat = (0, fs_1.lstatSync)(folder);
    return stat.uid === process.getuid() && (stat.mode & 0o077) === 0 ? folder : null;
}
// 'shown' only for an owner-only regular file holding exactly today's record for this pair; links and FIFOs are unsafe.
function readState(path, record) {
    let descriptor;
    try {
        descriptor = (0, fs_1.openSync)(path, fs_1.constants.O_RDONLY | fs_1.constants.O_NOFOLLOW | fs_1.constants.O_NONBLOCK);
    }
    catch (error) {
        return error.code === 'ENOENT' ? 'not_shown' : 'unsafe';
    }
    try {
        const stat = (0, fs_1.fstatSync)(descriptor);
        if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)
            return 'unsafe';
        const buffer = Buffer.alloc(STATE_LIMIT + 1);
        const length = stat.size > STATE_LIMIT ? 0 : (0, fs_1.readSync)(descriptor, buffer, 0, buffer.length, 0);
        return length > 0 && length <= STATE_LIMIT && buffer.subarray(0, length).toString('utf8') === record ? 'shown' : 'not_shown';
    }
    catch {
        return 'not_shown';
    }
    finally {
        (0, fs_1.closeSync)(descriptor);
    }
}
// A new temporary file in the same folder, then a rename over the state name (never written through a link).
function writeState(folder, record) {
    const temporary = (0, path_1.join)(folder, `.update-notice.${process.pid}.${(0, crypto_1.randomBytes)(6).toString('hex')}.tmp`);
    try {
        const descriptor = (0, fs_1.openSync)(temporary, fs_1.constants.O_CREAT | fs_1.constants.O_EXCL | fs_1.constants.O_WRONLY | fs_1.constants.O_NOFOLLOW, 0o600);
        try {
            (0, fs_1.writeSync)(descriptor, record);
        }
        finally {
            (0, fs_1.closeSync)(descriptor);
        }
        (0, fs_1.renameSync)(temporary, (0, path_1.join)(folder, STATE_NAME));
        return true;
    }
    catch {
        try {
            (0, fs_1.unlinkSync)(temporary);
        }
        catch { /* never created */ }
        return false;
    }
}
/** The hooks' line: at most once per UTC day per (installed, latest) pair; an unsafe or unwritable state shows none. Never throws. */
function hookUpdateNotice(answer) {
    try {
        const found = notice(answer);
        const folder = found ? stateFolder() : null;
        if (!found || !folder)
            return null;
        const record = JSON.stringify({ v: 1, installed: found.installed, latest: found.latest, day: new Date().toISOString().slice(0, 10) });
        return readState((0, path_1.join)(folder, STATE_NAME), record) === 'not_shown' && writeState(folder, record) ? found.line : null;
    }
    catch {
        return null;
    }
}
/** N3, pre-action: only into the separate additionalContext of a Claude Code or Codex answer that neither denies nor asks. */
function withPreActionNotice(output, harness, result) {
    if ((harness !== 'claude-code' && harness !== 'codex') || result.outage || result.timedOut || !result.runtime)
        return output;
    const specific = output.hookSpecificOutput;
    if (Object.keys(output).length !== 1 || !specific || typeof specific !== 'object' || Array.isArray(specific))
        return output;
    if ('permissionDecision' in specific || 'permissionDecisionReason' in specific || specific.hookEventName !== 'PreToolUse')
        return output;
    const line = hookUpdateNotice(result.runtime);
    if (!line)
        return output;
    const context = typeof specific.additionalContext === 'string' && specific.additionalContext ? `${specific.additionalContext}\n${line}` : line;
    return { hookSpecificOutput: { ...specific, additionalContext: context } };
}
//# sourceMappingURL=update-notice.js.map