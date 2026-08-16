"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LIFECYCLE_EVENT_TYPES = void 0;
exports.lifecycleSpoolStatus = lifecycleSpoolStatus;
exports.drainLifecycleSpool = drainLifecycleSpool;
exports.recordLifecycleEvent = recordLifecycleEvent;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
const redact_1 = require("./redact");
exports.LIFECYCLE_EVENT_TYPES = [
    'activation_profile_registered',
    'prompt_submitted',
    'goal_started',
    'pre_action_checked',
    'risk_gate_requested',
    'tool_completed',
    'tool_failed',
    'command_completed',
    'command_failed',
    'verification_evidence_added',
    'workflow_completed',
    'session_completed',
    'learned_workflow_created',
    'journey_update',
    'subagent_completed',
    'handoff_started',
    'handoff_completed',
    'proof_pack_closed',
    'outcome_committed',
];
const EVENT_TYPES = new Set(exports.LIFECYCLE_EVENT_TYPES);
const RISK_LEVELS = new Set(['low', 'medium', 'high']);
const OUTCOME_STATES = new Set(['pending', 'closed', 'unknown', 'timed_out']);
const CAPABILITY_LEVELS = new Set(['native_hooks', 'mcp', 'sdk_passive_runtime', 'governed_wrapper', 'event_contract']);
const INTERVENTION_DISPOSITIONS = new Set(['followed', 'ignored', 'overridden']);
const MAX_EVENTS = 1000;
const MAX_RECORD_BYTES = 4096;
const MAX_SPOOL_BYTES = 2 * 1024 * 1024;
const MAX_NAMESPACE_FILES = 128;
const MAX_ATTEMPTS = 3;
const PASSIVE_DELIVERY_REQUEST_TIMEOUT_MS = 750;
const DRAIN_REQUEST_TIMEOUT_MS = 4_000;
const DELIVERY_DRAIN_BUDGET_MS = 8_000;
const LOCK_WAIT_MS = 20;
const LOCK_ATTEMPTS = 250;
const LOCK_STALE_MS = 30_000;
function safeId(value, fallback) {
    const normalized = typeof value === 'string' ? value.trim().slice(0, 128) : '';
    return normalized && /^[A-Za-z0-9._:-]+$/.test(normalized) ? normalized : fallback;
}
function optionalId(value, field) {
    if (value == null || value === '')
        return undefined;
    const id = safeId(value);
    if (!id)
        throw new Error(`invalid lifecycle ${field}`);
    return id;
}
function compactAction(value) {
    const safe = (0, redact_1.redactSensitiveText)(String(value || 'agent lifecycle event'))
        .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[redacted-email]')
        .replace(/\bhttps?:\/\/\S+/gi, '[redacted-url]')
        .replace(/(?:^|\s)(?:\/[A-Za-z0-9._-]+){2,}/g, ' [redacted-path]')
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 180);
    if (!safe)
        throw new Error('invalid lifecycle action');
    return safe;
}
function hookList(value) {
    if (value == null)
        return undefined;
    if (!Array.isArray(value) || value.length > 12)
        throw new Error('invalid lifecycle expected_hooks');
    const hooks = value.map((hook) => optionalId(hook, 'expected_hooks'));
    if (hooks.some((hook) => !hook))
        throw new Error('invalid lifecycle expected_hooks');
    return [...new Set(hooks)];
}
function surfaceList(value) {
    if (value == null)
        return undefined;
    if (!Array.isArray(value) || value.length > 16)
        throw new Error('invalid lifecycle surfaces');
    const surfaces = value.map((surface) => optionalId(surface, 'surfaces')?.toLowerCase());
    if (surfaces.some((surface) => !surface) || new Set(surfaces).size !== surfaces.length) {
        throw new Error('invalid lifecycle surfaces');
    }
    return [...surfaces].sort();
}
function canonicalTimestamp(value) {
    const timestamp = value == null ? new Date().toISOString() : String(value).trim();
    const parsed = Date.parse(timestamp);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) {
        throw new Error('invalid lifecycle occurred_at');
    }
    return timestamp;
}
function spoolPath(apiKey, agentId) {
    if (process.env.MARROW_EVENT_SPOOL_PATH) {
        return { path: process.env.MARROW_EVENT_SPOOL_PATH, ownsParent: false };
    }
    const namespace = (0, node_crypto_1.createHash)('sha256').update(`${apiKey}:${agentId || 'account'}`).digest('hex').slice(0, 20);
    return { path: (0, node_path_1.join)((0, node_os_1.homedir)(), '.marrow', 'spool', `mcp-${namespace}.json`), ownsParent: true };
}
function currentUid() {
    return typeof process.getuid === 'function' ? process.getuid() : null;
}
function assertSafeFile(path, label) {
    if (!(0, node_fs_1.existsSync)(path))
        return;
    const stat = (0, node_fs_1.lstatSync)(path);
    const uid = currentUid();
    if (stat.isSymbolicLink() || !stat.isFile())
        throw new Error(`lifecycle ${label} must be a regular file`);
    if (uid !== null && stat.uid !== uid)
        throw new Error(`lifecycle ${label} must be owned by the current user`);
    if ((stat.mode & 0o077) !== 0)
        throw new Error(`lifecycle ${label} permissions must be 0600 or stricter`);
}
function ensureParent(path, ownsParent) {
    const parent = (0, node_path_1.resolve)((0, node_path_1.dirname)(path));
    const parsed = (0, node_path_1.parse)(parent);
    let current = parsed.root;
    for (const segment of parent.slice(parsed.root.length).split(node_path_1.sep).filter(Boolean)) {
        current = (0, node_path_1.join)(current, segment);
        try {
            (0, node_fs_1.mkdirSync)(current, { mode: 0o700 });
        }
        catch (error) {
            const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
            if (code !== 'EEXIST')
                throw error;
        }
        const stat = (0, node_fs_1.lstatSync)(current);
        if (stat.isSymbolicLink() || !stat.isDirectory() || (0, node_fs_1.realpathSync)(current) !== current) {
            throw new Error('lifecycle spool path cannot contain symlinked components');
        }
        if ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0) {
            throw new Error('lifecycle spool path cannot be nested under a non-sticky writable ancestor');
        }
    }
    const stat = (0, node_fs_1.lstatSync)(parent);
    const uid = currentUid();
    if (ownsParent) {
        if (uid !== null && stat.uid !== uid)
            throw new Error('lifecycle spool directory must be owned by the current user');
        (0, node_fs_1.chmodSync)(parent, 0o700);
    }
    else if ((stat.mode & 0o022) !== 0) {
        throw new Error('custom lifecycle spool directory cannot be group or world writable');
    }
}
function sleep(milliseconds) {
    const lock = new Int32Array(new SharedArrayBuffer(4));
    Atomics.wait(lock, 0, 0, milliseconds);
}
function withLock(path, ownsParent, operation) {
    ensureParent(path, ownsParent);
    const lockPath = `${path}.lock`;
    let descriptor = null;
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
        try {
            descriptor = (0, node_fs_1.openSync)(lockPath, 'wx', 0o600);
            break;
        }
        catch (error) {
            const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
            if (code !== 'EEXIST')
                throw error;
            try {
                assertSafeFile(lockPath, 'spool lock');
                if (Date.now() - (0, node_fs_1.statSync)(lockPath).mtimeMs > LOCK_STALE_MS)
                    (0, node_fs_1.unlinkSync)(lockPath);
            }
            catch (inspectionError) {
                const inspectionCode = inspectionError && typeof inspectionError === 'object' && 'code' in inspectionError
                    ? String(inspectionError.code)
                    : '';
                if (inspectionCode !== 'ENOENT')
                    throw inspectionError;
            }
            sleep(LOCK_WAIT_MS);
        }
    }
    if (descriptor == null)
        throw new Error('lifecycle spool lock timeout');
    try {
        return operation();
    }
    finally {
        (0, node_fs_1.closeSync)(descriptor);
        try {
            (0, node_fs_1.unlinkSync)(lockPath);
        }
        catch { /* lock already removed */ }
    }
}
function validateStoredEvent(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('invalid lifecycle spool record');
    const event = value;
    if (!EVENT_TYPES.has(String(event.event_type)))
        throw new Error('invalid lifecycle event_type');
    if (event.risk_level != null && !RISK_LEVELS.has(String(event.risk_level)))
        throw new Error('invalid lifecycle risk_level');
    if (event.outcome_state != null && !OUTCOME_STATES.has(String(event.outcome_state)))
        throw new Error('invalid lifecycle outcome_state');
    if (event.capability_level != null && !CAPABILITY_LEVELS.has(String(event.capability_level)))
        throw new Error('invalid lifecycle capability_level');
    if (event.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(String(event.intervention_disposition)))
        throw new Error('invalid lifecycle intervention_disposition');
    if (event.action_changed != null && typeof event.action_changed !== 'boolean')
        throw new Error('invalid lifecycle action_changed');
    const expectedHooks = hookList(event.expected_hooks);
    const surfaces = surfaceList(event.surfaces);
    const stored = {
        event_id: safeId(event.event_id) || (() => { throw new Error('invalid lifecycle event_id'); })(),
        event_type: String(event.event_type),
        harness: safeId(event.harness, 'custom') || 'custom',
        agent_id: safeId(event.agent_id, 'unknown') || 'unknown',
        action: compactAction(event.action),
        ...(event.target ? { target: compactAction(event.target) } : {}),
        ...(surfaces ? { surfaces } : {}),
        ...(safeId(event.workflow_id) ? { workflow_id: safeId(event.workflow_id) } : {}),
        ...(safeId(event.session_id) ? { session_id: safeId(event.session_id) } : {}),
        ...(safeId(event.decision_id) ? { decision_id: safeId(event.decision_id) } : {}),
        ...(safeId(event.correlation_id) ? { correlation_id: safeId(event.correlation_id) } : {}),
        ...(safeId(event.adapter_version) ? { adapter_version: safeId(event.adapter_version) } : {}),
        ...(event.capability_level ? { capability_level: String(event.capability_level) } : {}),
        ...(safeId(event.config_fingerprint) ? { config_fingerprint: safeId(event.config_fingerprint) } : {}),
        ...(expectedHooks ? { expected_hooks: expectedHooks } : {}),
        ...(safeId(event.observed_hook) ? { observed_hook: safeId(event.observed_hook) } : {}),
        ...(event.intervention_disposition ? { intervention_disposition: String(event.intervention_disposition) } : {}),
        ...(typeof event.action_changed === 'boolean' ? { action_changed: event.action_changed } : {}),
        ...(event.risk_level ? { risk_level: String(event.risk_level) } : {}),
        ...(event.outcome_state ? { outcome_state: String(event.outcome_state) } : {}),
        ...(typeof event.success === 'boolean' ? { success: event.success } : {}),
        occurred_at: canonicalTimestamp(event.occurred_at),
        attempts: Number.isInteger(event.attempts) && Number(event.attempts) >= 0 ? Math.min(Number(event.attempts), MAX_ATTEMPTS) : 0,
        delivery_state: event.delivery_state === 'dead_letter' ? 'dead_letter' : 'queued',
        ...(Number.isInteger(event.last_status) ? { last_status: Number(event.last_status) } : {}),
    };
    if (Buffer.byteLength(JSON.stringify(stored), 'utf8') > MAX_RECORD_BYTES) {
        throw new Error('lifecycle spool record exceeds byte limit');
    }
    return stored;
}
function compact(input) {
    if (!input || typeof input !== 'object')
        throw new Error('invalid lifecycle event');
    if (!EVENT_TYPES.has(String(input.event_type)))
        throw new Error('invalid lifecycle event_type');
    if (input.risk_level != null && !RISK_LEVELS.has(input.risk_level))
        throw new Error('invalid lifecycle risk_level');
    if (input.outcome_state != null && !OUTCOME_STATES.has(input.outcome_state))
        throw new Error('invalid lifecycle outcome_state');
    if (input.capability_level != null && !CAPABILITY_LEVELS.has(input.capability_level))
        throw new Error('invalid lifecycle capability_level');
    if (input.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(input.intervention_disposition))
        throw new Error('invalid lifecycle intervention_disposition');
    if (input.action_changed != null && typeof input.action_changed !== 'boolean')
        throw new Error('invalid lifecycle action_changed');
    const eventId = optionalId(input.event_id, 'event_id') || (0, node_crypto_1.randomUUID)();
    const harness = optionalId(input.harness, 'harness') || 'custom';
    const agentId = optionalId(input.agent_id, 'agent_id') || 'unknown';
    const workflowId = optionalId(input.workflow_id, 'workflow_id');
    const sessionId = optionalId(input.session_id, 'session_id');
    const decisionId = optionalId(input.decision_id, 'decision_id');
    const correlationId = optionalId(input.correlation_id, 'correlation_id')
        || decisionId
        || workflowId
        || sessionId
        || eventId;
    const expectedHooks = hookList(input.expected_hooks);
    const surfaces = surfaceList(input.surfaces);
    return validateStoredEvent({
        event_id: eventId,
        event_type: input.event_type,
        harness,
        agent_id: agentId,
        action: compactAction(input.action),
        ...(input.target ? { target: compactAction(input.target) } : {}),
        ...(surfaces ? { surfaces } : {}),
        ...(workflowId ? { workflow_id: workflowId } : {}),
        ...(sessionId ? { session_id: sessionId } : {}),
        ...(decisionId ? { decision_id: decisionId } : {}),
        correlation_id: correlationId,
        ...(optionalId(input.adapter_version, 'adapter_version') ? { adapter_version: optionalId(input.adapter_version, 'adapter_version') } : {}),
        ...(input.capability_level ? { capability_level: input.capability_level } : {}),
        ...(optionalId(input.config_fingerprint, 'config_fingerprint') ? { config_fingerprint: optionalId(input.config_fingerprint, 'config_fingerprint') } : {}),
        ...(expectedHooks ? { expected_hooks: expectedHooks } : {}),
        ...(optionalId(input.observed_hook, 'observed_hook') ? { observed_hook: optionalId(input.observed_hook, 'observed_hook') } : {}),
        ...(input.intervention_disposition ? { intervention_disposition: input.intervention_disposition } : {}),
        ...(typeof input.action_changed === 'boolean' ? { action_changed: input.action_changed } : {}),
        ...(input.risk_level ? { risk_level: input.risk_level } : {}),
        ...(input.outcome_state ? { outcome_state: input.outcome_state } : {}),
        ...(typeof input.success === 'boolean' ? { success: input.success } : {}),
        occurred_at: canonicalTimestamp(input.occurred_at),
        attempts: 0,
        delivery_state: 'queued',
    });
}
function readUnlocked(path) {
    if (!(0, node_fs_1.existsSync)(path))
        return { events: [], recoveredCorruption: false };
    assertSafeFile(path, 'spool file');
    try {
        const parsed = JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'));
        if (!Array.isArray(parsed))
            throw new Error('invalid lifecycle spool');
        if (parsed.length > MAX_EVENTS)
            throw new Error('lifecycle spool exceeds event capacity');
        return { events: parsed.map(validateStoredEvent), recoveredCorruption: false };
    }
    catch {
        const quarantine = `${path}.corrupt-${Date.now()}-${(0, node_crypto_1.randomUUID)()}`;
        (0, node_fs_1.renameSync)(path, quarantine);
        return { events: [], recoveredCorruption: true };
    }
}
function writeUnlocked(path, events) {
    if (events.length > MAX_EVENTS) {
        throw new Error('lifecycle spool capacity exceeded; receipt was not accepted');
    }
    const serialized = JSON.stringify(events);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_SPOOL_BYTES) {
        throw new Error('lifecycle spool byte capacity exceeded; receipt was not accepted');
    }
    assertSafeFile(path, 'spool file');
    const temporary = `${path}.${process.pid}.${(0, node_crypto_1.randomUUID)()}.tmp`;
    try {
        (0, node_fs_1.writeFileSync)(temporary, serialized, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        (0, node_fs_1.chmodSync)(temporary, 0o600);
        assertSafeFile(path, 'spool file');
        (0, node_fs_1.renameSync)(temporary, path);
        (0, node_fs_1.chmodSync)(path, 0o600);
    }
    finally {
        try {
            (0, node_fs_1.rmSync)(temporary, { force: true });
        }
        catch { }
    }
}
function mutate(path, ownsParent, operation) {
    return withLock(path, ownsParent, () => {
        const current = readUnlocked(path);
        const result = operation(current.events);
        writeUnlocked(path, current.events);
        return { result, recoveredCorruption: current.recoveredCorruption };
    });
}
function snapshot(path, ownsParent) {
    return withLock(path, ownsParent, () => readUnlocked(path));
}
function retryable(status) {
    return status === 0 || [408, 425, 429, 500, 502, 503, 504].includes(status);
}
async function deliver(baseUrl, apiKey, queued, timeoutMs) {
    const controller = new AbortController();
    let timeout;
    try {
        const response = await Promise.race([
            fetch(`${baseUrl}/v1/agent/integrations/events`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                    'X-Marrow-Client': 'mcp',
                    ...(queued.session_id ? { 'X-Marrow-Session-Id': queued.session_id } : {}),
                    ...(queued.agent_id !== 'unknown' ? { 'X-Marrow-Agent-Id': queued.agent_id } : {}),
                },
                body: JSON.stringify(queued),
                signal: controller.signal,
            }),
            new Promise((_resolve, reject) => {
                timeout = setTimeout(() => {
                    controller.abort();
                    reject(new Error('lifecycle delivery timeout'));
                }, timeoutMs);
            }),
        ]);
        return response.status;
    }
    finally {
        if (timeout)
            clearTimeout(timeout);
    }
}
function otherNamespaceStatus(currentPath, ownsParent) {
    if (!ownsParent) {
        return { state: 'clear', count: 0, pending: 0, failed: 0, unreadable: 0, truncated: false, exact_fix: null };
    }
    const parent = (0, node_path_1.dirname)(currentPath);
    if (!(0, node_fs_1.existsSync)(parent)) {
        return { state: 'clear', count: 0, pending: 0, failed: 0, unreadable: 0, truncated: false, exact_fix: null };
    }
    const names = (0, node_fs_1.readdirSync)(parent)
        .filter((name) => /^mcp-[a-f0-9]{20}\.json$/.test(name))
        .filter((name) => (0, node_path_1.join)(parent, name) !== currentPath)
        .sort();
    const truncated = names.length > MAX_NAMESPACE_FILES;
    let pending = 0;
    let failed = 0;
    let unreadable = 0;
    for (const name of names.slice(0, MAX_NAMESPACE_FILES)) {
        const path = (0, node_path_1.join)(parent, name);
        try {
            assertSafeFile(path, 'spool file');
            if ((0, node_fs_1.statSync)(path).size > MAX_SPOOL_BYTES)
                throw new Error('lifecycle spool is too large');
            const parsed = JSON.parse((0, node_fs_1.readFileSync)(path, 'utf8'));
            if (!Array.isArray(parsed) || parsed.length > MAX_EVENTS)
                throw new Error('invalid lifecycle spool');
            for (const event of parsed.map(validateStoredEvent)) {
                if (event.delivery_state === 'dead_letter')
                    failed += 1;
                else
                    pending += 1;
            }
        }
        catch {
            unreadable += 1;
        }
    }
    const attention = pending > 0 || failed > 0 || unreadable > 0 || truncated;
    return {
        state: attention ? 'attention_required' : 'clear',
        count: names.length,
        pending,
        failed,
        unreadable,
        truncated,
        exact_fix: attention
            ? truncated
                ? 'More than 128 older spool namespaces exist. Inspect owner-only spool inventory before restoring each original credential and agent identity; Marrow will not replay unverified namespaces under the current key.'
                : 'Older credential or agent spool namespaces exist. Restore each namespace\'s original credential and agent identity to drain it; Marrow will not replay it under the current key because same-tenant ownership cannot be proven.'
            : null,
    };
}
function lifecycleSpoolStatus(input) {
    const location = spoolPath(input.apiKey, input.agentId);
    const current = snapshot(location.path, location.ownsParent);
    const queued = current.events.filter((event) => event.delivery_state === 'queued');
    const failed = current.events.filter((event) => event.delivery_state === 'dead_letter');
    const otherNamespaces = otherNamespaceStatus(location.path, location.ownsParent);
    const failureStatuses = failed.map((event) => event.last_status).filter((status) => status != null);
    const authFailure = failureStatuses.some((status) => status === 401 || status === 403);
    const transportFailure = failureStatuses.some((status) => status === 0 || status === 408 || status >= 500);
    return {
        state: failed.length > 0 ? 'attention_required' : queued.length > 0 ? 'pending' : 'clear',
        pending: queued.length,
        failed: failed.length,
        oldest_pending_at: queued.map((event) => event.occurred_at).sort()[0] || null,
        oldest_failed_at: failed.map((event) => event.occurred_at).sort()[0] || null,
        capacity: MAX_EVENTS,
        available: Math.max(0, MAX_EVENTS - current.events.length),
        recovered_corruption: current.recoveredCorruption,
        exact_fix: failed.length > 0
            ? authFailure
                ? 'The server rejected delivery authentication or authorization. Restore the credential and agent binding, then run npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool.'
                : transportFailure
                    ? 'Lifecycle delivery timed out or the service was unavailable. Keep the credential unchanged, verify reachability, then run npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool.'
                    : 'Inspect the lifecycle event compatibility error, then run npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool.'
            : queued.length > 0
                ? 'Keep MCP activity running so a later event can retry, or run npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool.'
                : null,
        other_namespaces: otherNamespaces,
    };
}
async function attemptQueuedDelivery(input) {
    let status = 0;
    try {
        status = await deliver(input.baseUrl, input.apiKey, input.event, input.timeoutMs);
    }
    catch {
        status = 0;
    }
    mutate(input.path, input.ownsParent, (events) => {
        const current = events.find((row) => row.event_id === input.event.event_id);
        if (!current || current.delivery_state !== 'queued')
            return;
        if (status >= 200 && status < 300) {
            events.splice(events.indexOf(current), 1);
            return;
        }
        current.attempts += 1;
        current.last_status = status;
        if (!retryable(status) || current.attempts >= MAX_ATTEMPTS) {
            current.delivery_state = 'dead_letter';
        }
    });
    return status;
}
async function drainLifecycleSpool(input) {
    const location = spoolPath(input.apiKey, input.agentId);
    const deliveryDeadline = Date.now() + DELIVERY_DRAIN_BUDGET_MS;
    for (let delivered = 0; delivered < 10; delivered += 1) {
        let queued = snapshot(location.path, location.ownsParent).events.find((row) => row.delivery_state === 'queued');
        if (!queued) {
            queued = mutate(location.path, location.ownsParent, (events) => {
                const failed = events.find((row) => row.delivery_state === 'dead_letter');
                if (!failed)
                    return undefined;
                failed.delivery_state = 'queued';
                failed.attempts = 0;
                delete failed.last_status;
                return { ...failed };
            }).result;
        }
        if (!queued)
            break;
        const remainingMs = Math.min(DRAIN_REQUEST_TIMEOUT_MS, deliveryDeadline - Date.now());
        if (remainingMs <= 0)
            break;
        const status = await attemptQueuedDelivery({
            path: location.path,
            ownsParent: location.ownsParent,
            apiKey: input.apiKey,
            baseUrl: input.baseUrl,
            event: queued,
            timeoutMs: remainingMs,
        });
        if (!(status >= 200 && status < 300))
            break;
    }
    return lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.agentId });
}
async function recordLifecycleEvent(input) {
    const location = spoolPath(input.apiKey, input.event.agent_id);
    const event = compact(input.event);
    const queued = mutate(location.path, location.ownsParent, (events) => {
        const index = events.findIndex((row) => row.event_id === event.event_id);
        if (index < 0) {
            events.push(event);
            return event;
        }
        return events[index];
    });
    let recoveredCorruption = queued.recoveredCorruption;
    let deliveryStatus = 0;
    if (!input.deferDelivery && queued.result.delivery_state === 'queued')
        deliveryStatus = await attemptQueuedDelivery({
            path: location.path,
            ownsParent: location.ownsParent,
            apiKey: input.apiKey,
            baseUrl: input.baseUrl,
            event: queued.result,
            timeoutMs: PASSIVE_DELIVERY_REQUEST_TIMEOUT_MS,
        });
    if (deliveryStatus >= 200 && deliveryStatus < 300) {
        const previous = snapshot(location.path, location.ownsParent).events.find((row) => (row.delivery_state === 'queued' && row.event_id !== event.event_id));
        if (previous) {
            try {
                await attemptQueuedDelivery({
                    path: location.path,
                    ownsParent: location.ownsParent,
                    apiKey: input.apiKey,
                    baseUrl: input.baseUrl,
                    event: previous,
                    timeoutMs: PASSIVE_DELIVERY_REQUEST_TIMEOUT_MS,
                });
            }
            catch {
                // An older receipt retry must not turn a successfully accepted current receipt into a failure.
            }
        }
    }
    const final = snapshot(location.path, location.ownsParent);
    recoveredCorruption ||= final.recoveredCorruption;
    const current = final.events.find((row) => row.event_id === event.event_id);
    return {
        event_id: event.event_id,
        accepted: !current,
        queued: current?.delivery_state === 'queued',
        failed: current?.delivery_state === 'dead_letter',
        pending: final.events.filter((row) => row.delivery_state === 'queued').length,
        recovered_corruption: recoveredCorruption,
    };
}
//# sourceMappingURL=lifecycle-spool.js.map