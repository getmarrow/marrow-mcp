"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CODEX_USAGE_LIMITS = void 0;
exports.observeCodexNativeUsage = observeCodexNativeUsage;
exports.captureCodexNativeUsage = captureCodexNativeUsage;
const node_fs_1 = require("node:fs");
const node_crypto_1 = require("node:crypto");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const node_perf_hooks_1 = require("node:perf_hooks");
const index_1 = require("./index");
const habit_loop_copy_1 = require("./habit-loop-copy");
const model_usage_1 = require("./model-usage");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const MODEL = /^[a-zA-Z0-9_.:-]{1,120}$/;
exports.CODEX_USAGE_LIMITS = { fileBytes: 32 * 1024 * 1024, tailBytes: 256 * 1024, lineBytes: 64 * 1024, lines: 2048, readMs: 50 };
const TRANSCRIPT_VERSIONS = new Set(['0.157.1']);
const record = (v) => v && typeof v === 'object' && !Array.isArray(v) ? v : null;
const hash = (v) => (0, node_crypto_1.createHash)('sha256').update(JSON.stringify(v)).digest('hex');
const count = (v) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
function counters(value, camel = false) {
    const v = record(value);
    if (!v)
        return null;
    const names = camel ? ['inputTokens', 'cachedInputTokens', 'outputTokens', 'reasoningOutputTokens', 'totalTokens', 'cacheWriteInputTokens']
        : ['input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_output_tokens', 'total_tokens', 'cache_write_input_tokens'];
    if (Object.keys(v).some(k => !names.includes(k)))
        return null;
    const values = names.map(k => v[k]);
    if (!values.slice(0, 5).every(count) || (values[5] !== undefined && !count(values[5])))
        return null;
    const result = [...values.slice(0, 5), values[5] ?? null];
    if (result[1] + (result[5] || 0) > result[0] || result[3] > result[2] || result[4] !== result[0] + result[2])
        return null;
    return result;
}
function ownedPath(path, directory) {
    try {
        const s = (0, node_fs_1.lstatSync)(path);
        return !s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile())
            && (typeof process.getuid !== 'function' || s.uid === process.getuid()) && !(s.mode & 0o022);
    }
    catch {
        return false;
    }
}
function safeTranscript(path, root) {
    if (!(0, node_path_1.isAbsolute)(path) || !(0, node_path_1.isAbsolute)(root))
        return false;
    const rel = (0, node_path_1.relative)(root, path);
    if (!rel || rel.startsWith('..') || (0, node_path_1.isAbsolute)(rel) || !path.endsWith('.jsonl'))
        return false;
    // Validate every ancestor, not just the final path: no symlink traversal.
    let current = (0, node_path_1.resolve)(path);
    while (current !== (0, node_path_1.dirname)(current)) {
        if (current === root || (0, node_path_1.relative)(root, current).startsWith('..') === false) {
            if (!ownedPath(current, current !== (0, node_path_1.resolve)(path)))
                return false;
        }
        else {
            const stat = (0, node_fs_1.lstatSync)(current);
            if (stat.isSymbolicLink() || !stat.isDirectory())
                return false;
        }
        current = (0, node_path_1.dirname)(current);
    }
    return true;
}
function delta(total, last, previous) {
    return !!previous && total.every((value, i) => {
        const prior = previous[i], current = last[i];
        return value === null ? prior === null && current === null
            : prior !== null && current !== null && value >= prior && value - prior === current;
    }) && last[4] > 0;
}
function observation(thread, turn, model, provider, total, last, previous, occurredAt) {
    const checkpoint = { version: 1, thread, turn, model, total };
    if (!delta(total, last, previous))
        return { reason: 'delta_not_proven', checkpoint };
    const context = (0, habit_loop_copy_1.modelUsageCaptureContextFromEnv)();
    let billingHost;
    try {
        const endpoint = new URL(context.endpoint || '');
        if (provider === 'openai' && endpoint.protocol === 'https:' && endpoint.hostname === 'api.openai.com'
            && !endpoint.port && !endpoint.username && !endpoint.password)
            billingHost = 'first_party';
    }
    catch { /* Billing evidence remains unknown. */ }
    const usage = (0, model_usage_1.normalizeModelUsage)({ provider, model, session_id: thread,
        usage_event_id: `codex-native:${hash([thread, turn, model, total])}`,
        input_tokens: last[0], cached_tokens: last[1], output_tokens: last[2], total_tokens: last[4],
        ...(last[5] === null ? {} : { cache_write_tokens: last[5] }),
        // Codex counters already include cached input and reasoning output.
        token_semantics: 'input_includes_cache', usage_kind: 'delta', source: 'codex_native_usage', action_type: 'model',
        billing_host: billingHost, billing_mode: context.billing_mode, pricing_dimensions: context.pricing_dimensions,
        occurred_at: occurredAt,
    });
    return { reason: 'observed_delta', checkpoint, usage };
}
/** Reads one supported event or bounded current transcript. Never returns transcript text. */
function observeCodexNativeUsage(input, previous, options = {}) {
    try {
        const hook = record(input);
        if (!hook)
            return { reason: 'unsupported_shape' };
        // Native subagent session_id can name its parent. Without a proven Marrow
        // binding for that child, abstain rather than upload parent-attributed usage.
        if (hook.subagent_transcript_path !== undefined || hook.agent_id !== undefined)
            return { reason: 'subagent_binding_unproven' };
        if (typeof hook.model !== 'string' || !MODEL.test(hook.model))
            return { reason: 'model_missing' };
        if (hook.method === 'thread/tokenUsage/updated') {
            const params = record(hook.params), usage = record(params?.tokenUsage);
            const thread = params?.threadId, turn = params?.turnId;
            if (typeof thread !== 'string' || !UUID.test(thread) || typeof turn !== 'string' || !UUID.test(turn)
                || hook.session_id !== thread || hook.turn_id !== turn || !usage)
                return { reason: 'event_identity_unproven' };
            if (Object.keys(usage).some(k => !['total', 'last', 'modelContextWindow'].includes(k)))
                return { reason: 'unsupported_shape' };
            const total = counters(usage.total, true), last = counters(usage.last, true);
            if (!total || !last)
                return { reason: 'invalid_counters' };
            const prior = previous?.thread === thread && previous.turn === turn && previous.model === hook.model ? previous.total : undefined;
            return observation(thread, turn, hook.model, undefined, total, last, prior);
        }
        if (typeof hook.session_id !== 'string' || !UUID.test(hook.session_id) || typeof hook.transcript_path !== 'string')
            return { reason: 'transcript_identity_unproven' };
        const root = (0, node_path_1.resolve)(options.sessionsRoot || (0, node_path_1.join)(process.env.CODEX_HOME || (0, node_path_1.join)((0, node_os_1.homedir)(), '.codex'), 'sessions'));
        const file = hook.transcript_path;
        if (!safeTranscript(file, root))
            return { reason: 'transcript_path_rejected' };
        const started = node_perf_hooks_1.performance.now();
        const fd = (0, node_fs_1.openSync)(file, node_fs_1.constants.O_RDONLY | node_fs_1.constants.O_NOFOLLOW);
        let head, tail, offset;
        try {
            const stat = (0, node_fs_1.fstatSync)(fd);
            if (!stat.isFile() || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || (stat.mode & 0o022) || stat.size > exports.CODEX_USAGE_LIMITS.fileBytes)
                return { reason: 'transcript_size_limit' };
            const read = (start, size) => { const b = Buffer.alloc(size); return b.subarray(0, (0, node_fs_1.readSync)(fd, b, 0, size, start)).toString('utf8'); };
            head = read(0, Math.min(stat.size, exports.CODEX_USAGE_LIMITS.lineBytes));
            offset = Math.max(0, stat.size - exports.CODEX_USAGE_LIMITS.tailBytes);
            tail = read(offset, stat.size - offset);
            if ((0, node_fs_1.fstatSync)(fd).size !== stat.size)
                return { reason: 'transcript_changed_during_read' };
        }
        finally {
            (0, node_fs_1.closeSync)(fd);
        }
        if (node_perf_hooks_1.performance.now() - started > exports.CODEX_USAGE_LIMITS.readMs)
            return { reason: 'transcript_time_limit' };
        const firstLineEnd = head.indexOf('\n');
        if (firstLineEnd < 0)
            return { reason: 'transcript_metadata_limit' };
        const header = record(JSON.parse(head.slice(0, firstLineEnd))), meta = record(header?.payload);
        if (header?.type !== 'session_meta' || meta?.id !== hook.session_id || !TRANSCRIPT_VERSIONS.has(String(meta?.cli_version)))
            return { reason: 'transcript_version_or_identity_unproven' };
        if (meta?.parent_thread_id || record(meta?.source)?.subagent)
            return { reason: 'subagent_binding_unproven' };
        const lines = tail.split('\n');
        if (offset)
            lines.shift();
        if (lines.length > exports.CODEX_USAGE_LIMITS.lines)
            return { reason: 'transcript_line_limit' };
        let turn, model, prior;
        let found = { reason: 'current_turn_delta_unavailable' };
        for (const line of lines) {
            if (node_perf_hooks_1.performance.now() - started > exports.CODEX_USAGE_LIMITS.readMs)
                return { reason: 'transcript_time_limit' };
            if (Buffer.byteLength(line) > exports.CODEX_USAGE_LIMITS.lineBytes)
                return { reason: 'transcript_line_limit' };
            if (!line || (!line.includes('"turn_context"') && !line.includes('"token_count"')))
                continue;
            const event = record(JSON.parse(line)), p = record(event?.payload);
            if (event?.type === 'turn_context') {
                turn = typeof p?.turn_id === 'string' && UUID.test(p.turn_id) ? p.turn_id : undefined;
                model = typeof p?.model === 'string' && MODEL.test(p.model) ? p.model : undefined;
                prior = undefined;
                found = { reason: 'current_turn_delta_unavailable' };
            }
            else if (event?.type === 'event_msg' && p?.type === 'token_count') {
                const info = record(p.info), total = counters(info?.total_token_usage), last = counters(info?.last_token_usage);
                if (!turn || !model || !total || !last) {
                    prior = undefined;
                    found = { reason: 'unsupported_shape' };
                    continue;
                }
                if (prior && total.every((n, i) => n === prior[i]))
                    continue;
                if (model !== hook.model || (hook.turn_id !== undefined && hook.turn_id !== turn)) {
                    prior = total;
                    found = { reason: 'turn_model_mismatch' };
                    continue;
                }
                const time = event?.timestamp;
                if (typeof time !== 'string' || !Number.isFinite(Date.parse(time)))
                    return { reason: 'timestamp_missing' };
                found = observation(hook.session_id, turn, model, meta?.model_provider === 'openai' ? 'openai' : undefined, total, last, prior, new Date(time).toISOString());
                prior = total;
            }
        }
        return found;
    }
    catch {
        return { reason: 'native_usage_unavailable' };
    }
}
function checkpointPath(thread, agentId) {
    const home = (0, node_os_1.homedir)(), parent = (0, node_path_1.join)(home, '.marrow'), root = (0, node_path_1.join)(parent, 'codex-native-usage');
    try {
        if (!ownedPath(home, true))
            return null;
        for (const dir of [parent, root]) {
            try {
                (0, node_fs_1.mkdirSync)(dir, { mode: 0o700 });
            }
            catch { /* Validate existing directory below. */ }
            if (!ownedPath(dir, true))
                return null;
        }
        return (0, node_path_1.join)(root, `${hash([agentId, thread])}.json`);
    }
    catch {
        return null;
    }
}
/** Compact private checkpoint avoids duplicate uploads across native hook processes. */
async function captureCodexNativeUsage(input, apiKey, baseUrl, agentId) {
    const hook = record(input), params = record(hook?.params);
    const thread = hook?.method === 'thread/tokenUsage/updated' ? params?.threadId : hook?.session_id;
    if (hook?.subagent_transcript_path !== undefined || hook?.agent_id !== undefined)
        return;
    if (!apiKey || !agentId || typeof thread !== 'string' || !UUID.test(thread))
        return;
    const file = checkpointPath(thread, agentId);
    if (!file)
        return;
    let previous;
    try {
        if (ownedPath(file, false) && (0, node_fs_1.lstatSync)(file).size <= 2048) {
            const fd = (0, node_fs_1.openSync)(file, node_fs_1.constants.O_RDONLY | node_fs_1.constants.O_NOFOLLOW);
            let saved;
            try {
                if ((0, node_fs_1.fstatSync)(fd).size > 2048)
                    return;
                saved = JSON.parse((0, node_fs_1.readFileSync)(fd, 'utf8'));
            }
            finally {
                (0, node_fs_1.closeSync)(fd);
            }
            if (saved.version === 1 && saved.thread === thread && typeof saved.turn === 'string' && UUID.test(saved.turn)
                && typeof saved.model === 'string' && MODEL.test(saved.model) && Array.isArray(saved.total)
                && saved.total.length === 6 && saved.total.slice(0, 5).every(count) && (saved.total[5] === null || count(saved.total[5])))
                previous = saved;
        }
    }
    catch { /* An invalid checkpoint proves no delta. */ }
    const result = observeCodexNativeUsage(input, previous);
    if (!result.checkpoint)
        return;
    if (result.usage) {
        if (previous?.submitted === result.usage.usage_event_id)
            return;
        try {
            await (0, index_1.marrowModelUsage)(apiKey, baseUrl, result.usage, result.checkpoint.thread, agentId);
        }
        catch {
            return;
        } // Keep the prior checkpoint so the same observation can retry unchanged.
        result.checkpoint.submitted = result.usage.usage_event_id;
    }
    else
        result.checkpoint.submitted = previous?.submitted;
    const temporary = `${file}.${process.pid}.${hash(Date.now()).slice(0, 8)}.tmp`;
    try {
        (0, node_fs_1.writeFileSync)(temporary, JSON.stringify(result.checkpoint), { mode: 0o600, flag: 'wx' });
        (0, node_fs_1.renameSync)(temporary, file);
    }
    catch {
        try {
            (0, node_fs_1.unlinkSync)(temporary);
        }
        catch { /* Best effort checkpoint only. */ }
    }
}
//# sourceMappingURL=codex-native-usage.js.map