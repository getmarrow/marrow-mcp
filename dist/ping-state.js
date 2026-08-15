"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolvePingTimeoutMs = resolvePingTimeoutMs;
exports.updatePingState = updatePingState;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const os_1 = require("os");
const path_1 = require("path");
function resolvePingTimeoutMs(value) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0)
        return 2_500;
    return Math.min(5_000, Math.max(500, Math.floor(parsed)));
}
function statePath(apiKey, baseUrl, agentId, home = (0, os_1.homedir)()) {
    const namespace = (0, crypto_1.createHash)('sha256').update(`${baseUrl}|${apiKey}|${agentId || 'account'}`).digest('hex').slice(0, 24);
    const directory = (0, path_1.join)(home, '.marrow', 'health');
    if (!(0, fs_1.existsSync)(directory))
        (0, fs_1.mkdirSync)(directory, { recursive: true, mode: 0o700 });
    const stat = (0, fs_1.lstatSync)(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
        throw new Error('Marrow health directory must be owner-only and cannot be a symlink');
    }
    return (0, path_1.join)(directory, `ping-${namespace}.json`);
}
function read(path) {
    if (!(0, fs_1.existsSync)(path))
        return { version: 1, last_success_at: null, samples_ms: [] };
    const stat = (0, fs_1.lstatSync)(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
        throw new Error('Marrow health file is not private');
    try {
        const parsed = JSON.parse((0, fs_1.readFileSync)(path, 'utf8'));
        const samples = Array.isArray(parsed.samples_ms)
            ? parsed.samples_ms.filter((value) => Number.isFinite(value) && value >= 0 && value <= 60_000).slice(-100)
            : [];
        return { version: 1, last_success_at: typeof parsed.last_success_at === 'string' ? parsed.last_success_at : null, samples_ms: samples };
    }
    catch {
        return { version: 1, last_success_at: null, samples_ms: [] };
    }
}
function percentile(values, fraction) {
    if (!values.length)
        return null;
    const sorted = [...values].sort((left, right) => left - right);
    return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? null;
}
function updatePingState(input) {
    const path = statePath(input.apiKey, input.baseUrl, input.agentId, input.home);
    const state = read(path);
    if (input.success && Number.isFinite(input.latencyMs))
        state.samples_ms.push(Math.max(0, Math.round(input.latencyMs)));
    state.samples_ms = state.samples_ms.slice(-100);
    if (input.success)
        state.last_success_at = new Date().toISOString();
    const temporary = `${path}.tmp-${process.pid}`;
    (0, fs_1.writeFileSync)(temporary, JSON.stringify(state), { encoding: 'utf8', mode: 0o600, flag: 'w' });
    (0, fs_1.chmodSync)(temporary, 0o600);
    (0, fs_1.renameSync)(temporary, path);
    return {
        last_success_at: state.last_success_at,
        sample_count: state.samples_ms.length,
        p50_ms: percentile(state.samples_ms, 0.50),
        p99_ms: percentile(state.samples_ms, 0.99),
    };
}
//# sourceMappingURL=ping-state.js.map