"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LIFECYCLE_EVENT_TYPES = void 0;
exports.lifecycleSpoolStatus = lifecycleSpoolStatus;
exports.quarantineLegacyNamespaces = quarantineLegacyNamespaces;
exports.nudgeLifecycleSpool = nudgeLifecycleSpool;
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
const INTERVENTION_DISPOSITIONS = new Set(['followed', 'ignored', 'overridden']);
const LIFECYCLE_SOURCES = new Set(['client_self_reported']);
const MAX_EVENTS = 1000;
const MAX_RECORD_BYTES = 4096;
const MAX_SPOOL_BYTES = 2 * 1024 * 1024;
const MAX_NAMESPACE_FILES = 128;
const MAX_NAMESPACE_DIRECTORY_ENTRIES = 1024;
const MAX_ATTEMPTS = 3;
const PASSIVE_DELIVERY_REQUEST_TIMEOUT_MS = 750;
const DRAIN_REQUEST_TIMEOUT_MS = 4_000;
const DELIVERY_DRAIN_BUDGET_MS = 30_000;
const NUDGE_DRAIN_BUDGET_MS = 20_000;
const NUDGE_MAX_EVENTS = 40;
const NAMESPACE_JSON_RE = /^mcp-[a-f0-9]{20}\.json$/;
const NAMESPACE_LOCK_RE = /^mcp-[a-f0-9]{20}\.json\.lock$/;
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
function unlinkQuiet(path) {
    try {
        (0, node_fs_1.unlinkSync)(path);
    }
    catch { /* already gone */ }
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
    if (event.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(String(event.intervention_disposition)))
        throw new Error('invalid lifecycle intervention_disposition');
    if (event.source != null && !LIFECYCLE_SOURCES.has(String(event.source)))
        throw new Error('invalid lifecycle source');
    if (event.action_changed != null && typeof event.action_changed !== 'boolean')
        throw new Error('invalid lifecycle action_changed');
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
        source: 'client_self_reported',
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
    if (input.intervention_disposition != null && !INTERVENTION_DISPOSITIONS.has(input.intervention_disposition))
        throw new Error('invalid lifecycle intervention_disposition');
    if (input.source != null && !LIFECYCLE_SOURCES.has(input.source))
        throw new Error('invalid lifecycle source');
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
        source: 'client_self_reported',
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
    const wireEvent = { ...queued };
    if (queued.agent_id === 'unknown')
        delete wireEvent.agent_id;
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
                body: JSON.stringify(wireEvent),
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
function clearOtherNamespaceStatus() {
    return {
        state: 'clear',
        count: 0,
        count_exact: true,
        scanned: 0,
        scan_limit: MAX_NAMESPACE_FILES,
        directory_entries_scanned: 0,
        directory_entry_limit: MAX_NAMESPACE_DIRECTORY_ENTRIES,
        pending: 0,
        failed: 0,
        event_counts_exact: true,
        unreadable: 0,
        truncated: false,
        blocks_current_namespace: false,
        exact_fix: null,
        safe_recovery_action: null,
        safe_quarantine_action: null,
    };
}
function readInventoryEvents(path) {
    assertSafeFile(path, 'spool file');
    const before = (0, node_fs_1.lstatSync)(path);
    if (before.size > MAX_SPOOL_BYTES)
        throw new Error('lifecycle spool is too large');
    const descriptor = (0, node_fs_1.openSync)(path, node_fs_1.constants.O_RDONLY | node_fs_1.constants.O_NOFOLLOW | node_fs_1.constants.O_NONBLOCK);
    try {
        const opened = (0, node_fs_1.fstatSync)(descriptor);
        const uid = currentUid();
        if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) {
            throw new Error('lifecycle spool changed during inventory');
        }
        if (uid !== null && opened.uid !== uid)
            throw new Error('lifecycle spool file must be owned by the current user');
        if ((opened.mode & 0o077) !== 0)
            throw new Error('lifecycle spool file permissions must be 0600 or stricter');
        if (opened.size > MAX_SPOOL_BYTES)
            throw new Error('lifecycle spool is too large');
        const parsed = JSON.parse((0, node_fs_1.readFileSync)(descriptor, 'utf8'));
        if (!Array.isArray(parsed) || parsed.length > MAX_EVENTS)
            throw new Error('invalid lifecycle spool');
        return parsed.map(validateStoredEvent);
    }
    finally {
        (0, node_fs_1.closeSync)(descriptor);
    }
}
function otherNamespaceStatus(currentPath, ownsParent) {
    if (!ownsParent)
        return clearOtherNamespaceStatus();
    const parent = (0, node_path_1.dirname)(currentPath);
    if (!(0, node_fs_1.existsSync)(parent))
        return clearOtherNamespaceStatus();
    const currentName = (0, node_path_1.basename)(currentPath);
    const names = [];
    let directoryEntriesScanned = 0;
    let directoryEntriesTruncated = false;
    const directory = (0, node_fs_1.opendirSync)(parent);
    try {
        let entry = directory.readSync();
        while (entry) {
            if (directoryEntriesScanned >= MAX_NAMESPACE_DIRECTORY_ENTRIES) {
                directoryEntriesTruncated = true;
                break;
            }
            directoryEntriesScanned += 1;
            if (entry.name !== currentName && NAMESPACE_JSON_RE.test(entry.name)) {
                names.push(entry.name);
                if (names.length > MAX_NAMESPACE_FILES)
                    break;
            }
            entry = directory.readSync();
        }
    }
    finally {
        directory.closeSync();
    }
    const truncated = names.length > MAX_NAMESPACE_FILES || directoryEntriesTruncated;
    const inspectedNames = names.slice(0, MAX_NAMESPACE_FILES).sort();
    let pending = 0;
    let failed = 0;
    let unreadable = 0;
    for (const name of inspectedNames) {
        const path = (0, node_path_1.join)(parent, name);
        try {
            for (const event of readInventoryEvents(path)) {
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
        count_exact: !truncated,
        scanned: inspectedNames.length,
        scan_limit: MAX_NAMESPACE_FILES,
        directory_entries_scanned: directoryEntriesScanned,
        directory_entry_limit: MAX_NAMESPACE_DIRECTORY_ENTRIES,
        pending,
        failed,
        event_counts_exact: !truncated && unreadable === 0,
        unreadable,
        truncated,
        blocks_current_namespace: false,
        exact_fix: attention
            ? truncated
                ? 'The older spool inventory exceeded a bounded scan limit: at most 128 legacy namespace files and 1024 directory entries are inspected per check. Review the owner-only inventory in bounded batches. Legacy debt never blocks or changes the active credential namespace, and Marrow will not replay unverified namespaces under the current key.'
                : 'Older credential or agent spool namespaces exist. Legacy debt never blocks or changes the active credential namespace, and Marrow will not replay it under the current key because same-tenant ownership cannot be proven.'
            : null,
        safe_recovery_action: attention
            ? 'For each selected legacy file, restore its original credential from trusted secret storage and its exact original agent identity, then run npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool. Never put the credential on the command line and never drain the file under another key or agent identity.'
            : null,
        safe_quarantine_action: attention
            ? 'If the original identity cannot be restored, move only the selected legacy mcp-<20-hex>.json file from the active owner-only spool directory into a separate owner-only quarantine directory. Preserve it unchanged for later authenticated recovery; do not copy, merge, replay, edit, or delete it, and do not move the active namespace file.'
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
function quarantineLegacyNamespaces(input) {
    const location = spoolPath(input.apiKey, input.agentId);
    if (!location.ownsParent)
        return { moved: 0, destination: null };
    const parent = (0, node_path_1.dirname)(location.path);
    if (!(0, node_fs_1.existsSync)(parent))
        return { moved: 0, destination: null };
    const currentName = (0, node_path_1.basename)(location.path);
    const names = [];
    const leftoverLocks = [];
    const directory = (0, node_fs_1.opendirSync)(parent);
    try {
        let entry = directory.readSync();
        while (entry) {
            if (names.length >= MAX_NAMESPACE_FILES && leftoverLocks.length >= MAX_NAMESPACE_FILES)
                break;
            if (entry.name !== currentName && NAMESPACE_JSON_RE.test(entry.name)) {
                names.push(entry.name);
            }
            else if (entry.name !== `${currentName}.lock` && NAMESPACE_LOCK_RE.test(entry.name)) {
                leftoverLocks.push(entry.name);
            }
            entry = directory.readSync();
        }
    }
    finally {
        directory.closeSync();
    }
    if (names.length === 0 && leftoverLocks.length === 0)
        return { moved: 0, destination: null };
    const quarantineDir = (0, node_path_1.join)(parent, 'quarantine');
    ensureParent((0, node_path_1.join)(quarantineDir, 'mcp-placeholder.json'), true);
    let moved = 0;
    for (const name of names) {
        const source = (0, node_path_1.join)(parent, name);
        const destination = (0, node_path_1.join)(quarantineDir, name);
        try {
            assertSafeFile(source, 'legacy spool');
            if ((0, node_fs_1.existsSync)(destination))
                continue;
            withLock(source, true, () => {
                assertSafeFile(source, 'legacy spool');
                (0, node_fs_1.renameSync)(source, destination);
                (0, node_fs_1.chmodSync)(destination, 0o600);
            });
            unlinkQuiet(`${source}.lock`);
            unlinkQuiet(`${destination}.lock`);
            moved += 1;
        }
        catch {
            // Leave unsafe or contested files in place; never replay them under the current key.
            unlinkQuiet(`${source}.lock`);
        }
    }
    for (const name of leftoverLocks) {
        const source = (0, node_path_1.join)(parent, name);
        const jsonName = name.slice(0, -'.lock'.length);
        if (jsonName === currentName || (0, node_fs_1.existsSync)((0, node_path_1.join)(parent, jsonName)))
            continue;
        unlinkQuiet(source);
    }
    return { moved, destination: moved > 0 ? quarantineDir : null };
}
let nudgeInFlight = false;
function nudgeLifecycleSpool(input) {
    if (nudgeInFlight)
        return Promise.resolve();
    nudgeInFlight = true;
    return drainLifecycleSpool({
        ...input,
        maxEvents: NUDGE_MAX_EVENTS,
        budgetMs: NUDGE_DRAIN_BUDGET_MS,
        requestTimeoutMs: PASSIVE_DELIVERY_REQUEST_TIMEOUT_MS,
        retryDeadLetters: false,
    })
        .then(() => undefined)
        .catch(() => undefined)
        .finally(() => {
        nudgeInFlight = false;
    });
}
async function drainLifecycleSpool(input) {
    const location = spoolPath(input.apiKey, input.agentId);
    const retryDeadLetters = input.retryDeadLetters !== false;
    const maxEvents = Number.isInteger(input.maxEvents)
        ? Math.max(1, Math.min(MAX_EVENTS, Number(input.maxEvents)))
        : retryDeadLetters ? MAX_EVENTS : NUDGE_MAX_EVENTS;
    const budgetMs = Number.isInteger(input.budgetMs)
        ? Math.max(1, Number(input.budgetMs))
        : retryDeadLetters ? DELIVERY_DRAIN_BUDGET_MS : NUDGE_DRAIN_BUDGET_MS;
    const requestTimeoutMs = Number.isInteger(input.requestTimeoutMs)
        ? Math.max(1, Number(input.requestTimeoutMs))
        : DRAIN_REQUEST_TIMEOUT_MS;
    const deliveryDeadline = Date.now() + budgetMs;
    const attempted = new Set();
    for (let delivered = 0; delivered < maxEvents; delivered += 1) {
        let queued = snapshot(location.path, location.ownsParent).events.find((row) => (row.delivery_state === 'queued' && !attempted.has(row.event_id)));
        if (!queued && retryDeadLetters) {
            queued = mutate(location.path, location.ownsParent, (events) => {
                const failed = events.find((row) => row.delivery_state === 'dead_letter' && !attempted.has(row.event_id));
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
        attempted.add(queued.event_id);
        const remainingMs = Math.min(requestTimeoutMs, deliveryDeadline - Date.now());
        if (remainingMs <= 0)
            break;
        await attemptQueuedDelivery({
            path: location.path,
            ownsParent: location.ownsParent,
            apiKey: input.apiKey,
            baseUrl: input.baseUrl,
            event: queued,
            timeoutMs: remainingMs,
        });
    }
    if (retryDeadLetters) {
        mutate(location.path, location.ownsParent, (events) => {
            for (const event of events) {
                if (event.delivery_state === 'queued') {
                    event.delivery_state = 'dead_letter';
                    event.last_status = event.last_status ?? 0;
                }
            }
        });
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