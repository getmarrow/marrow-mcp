"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordLifecycleEvent = recordLifecycleEvent;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const redact_1 = require("./redact");
const MAX_EVENTS = 100;
function safeId(value, fallback) {
    const normalized = typeof value === 'string' ? value.trim().slice(0, 128) : '';
    return normalized && /^[A-Za-z0-9._:-]+$/.test(normalized) ? normalized : fallback;
}
function spoolPath(apiKey, agentId) {
    if (process.env.MARROW_EVENT_SPOOL_PATH)
        return process.env.MARROW_EVENT_SPOOL_PATH;
    const namespace = (0, node_crypto_1.createHash)('sha256').update(`${apiKey}:${agentId || 'account'}`).digest('hex').slice(0, 20);
    return (0, node_path_1.join)((0, node_os_1.homedir)(), '.marrow', 'spool', `mcp-${namespace}.json`);
}
function read(path) {
    if (!(0, node_fs_1.existsSync)(path))
        return [];
    try {
        const parsed = JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'));
        return Array.isArray(parsed) ? parsed.slice(-MAX_EVENTS) : [];
    }
    catch {
        return [];
    }
}
function write(path, events) {
    (0, node_fs_1.mkdirSync)((0, node_path_1.dirname)(path), { recursive: true, mode: 0o700 });
    (0, node_fs_1.chmodSync)((0, node_path_1.dirname)(path), 0o700);
    const temporary = `${path}.tmp`;
    (0, node_fs_1.writeFileSync)(temporary, JSON.stringify(events.slice(-MAX_EVENTS)), { encoding: 'utf8', mode: 0o600 });
    (0, node_fs_1.chmodSync)(temporary, 0o600);
    (0, node_fs_1.renameSync)(temporary, path);
    (0, node_fs_1.chmodSync)(path, 0o600);
}
function compact(input) {
    return {
        event_id: safeId(input.event_id) || (0, node_crypto_1.randomUUID)(),
        event_type: safeId(input.event_type, 'unknown') || 'unknown',
        harness: safeId(input.harness, 'custom') || 'custom',
        agent_id: safeId(input.agent_id, 'unknown') || 'unknown',
        action: (0, redact_1.redactSensitiveText)(String(input.action || input.event_type)).replace(/\s+/g, ' ').trim().slice(0, 240),
        ...(safeId(input.workflow_id) ? { workflow_id: safeId(input.workflow_id) } : {}),
        ...(safeId(input.session_id) ? { session_id: safeId(input.session_id) } : {}),
        ...(safeId(input.decision_id) ? { decision_id: safeId(input.decision_id) } : {}),
        ...(input.risk_level ? { risk_level: input.risk_level } : {}),
        ...(input.outcome_state ? { outcome_state: input.outcome_state } : {}),
        ...(typeof input.success === 'boolean' ? { success: input.success } : {}),
        occurred_at: input.occurred_at || new Date().toISOString(),
        attempts: 0,
    };
}
function retryable(status) {
    return [408, 425, 429, 500, 502, 503, 504].includes(status);
}
async function recordLifecycleEvent(input) {
    const path = spoolPath(input.apiKey, input.event.agent_id);
    const event = compact(input.event);
    const initial = read(path).filter((row) => row.event_id !== event.event_id);
    write(path, [...initial, event]);
    const remaining = read(path);
    for (const queued of remaining.slice(0, 10)) {
        try {
            const response = await fetch(`${input.baseUrl}/v1/agent/integrations/events`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${input.apiKey}`,
                    'Content-Type': 'application/json',
                    'X-Marrow-Client': 'mcp',
                    ...(queued.session_id ? { 'X-Marrow-Session-Id': queued.session_id } : {}),
                    ...(queued.agent_id !== 'unknown' ? { 'X-Marrow-Agent-Id': queued.agent_id } : {}),
                },
                body: JSON.stringify(queued),
            });
            if (response.ok) {
                write(path, read(path).filter((row) => row.event_id !== queued.event_id));
                continue;
            }
            if (retryable(response.status) && queued.attempts < 3) {
                write(path, read(path).map((row) => row.event_id === queued.event_id ? { ...row, attempts: row.attempts + 1 } : row));
                break;
            }
            write(path, read(path).filter((row) => row.event_id !== queued.event_id));
        }
        catch {
            write(path, read(path).map((row) => row.event_id === queued.event_id ? { ...row, attempts: row.attempts + 1 } : row));
            break;
        }
    }
    const pending = read(path).length;
    return { event_id: event.event_id, queued: pending > 0, pending };
}
//# sourceMappingURL=lifecycle-spool.js.map