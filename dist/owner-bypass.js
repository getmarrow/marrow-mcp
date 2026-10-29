"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordSessionBypass = recordSessionBypass;
const node_crypto_1 = require("node:crypto");
const index_1 = require("./index");
const control_state_1 = require("./control-state");
const hook_contract_1 = require("./hook-contract");
const lifecycle_spool_1 = require("./lifecycle-spool");
const session_marker_1 = require("./session-marker");
const BYPASS_TARGET = {
    hooks_switched_off: 'marrow:hooks-switched-off',
    control_state_unsafe: 'marrow:control-state-unsafe',
};
const MAX_INPUT_BYTES = 1024 * 1024;
const INPUT_WAIT_MS = 1_500;
function readHookInput() {
    return new Promise((resolve) => {
        if (process.stdin.isTTY) {
            resolve(undefined);
            return;
        }
        const chunks = [];
        let size = 0;
        const finish = () => {
            clearTimeout(timer);
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            }
            catch {
                resolve(undefined);
            }
        };
        const timer = setTimeout(finish, INPUT_WAIT_MS);
        process.stdin.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_INPUT_BYTES) {
                chunks.length = 0;
                finish();
                return;
            }
            chunks.push(chunk);
        });
        process.stdin.on('end', finish);
        process.stdin.on('error', finish);
    });
}
async function recordSessionBypass(reason, identity, input) {
    try {
        const resolved = identity.environment;
        if (!resolved.apiKey)
            return;
        const event = (0, hook_contract_1.normalizeHookEventPayload)(input === undefined ? await readHookInput() : input);
        const named = [event.session_id, event.conversation_id, event.task_id].find((value) => typeof value === 'string' && value.length > 0);
        const sessionId = resolved.sessionId || (typeof named === 'string' ? named : '');
        if (!sessionId || !(0, session_marker_1.claimSessionMarker)(`bypass-${reason.replace(/_/g, '-')}`, sessionId))
            return;
        const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
        const correlation = (0, node_crypto_1.createHash)('sha256').update(`${reason}\n${sessionId}`).digest('hex').slice(0, 24);
        await (0, lifecycle_spool_1.recordLifecycleEvent)({ apiKey: resolved.apiKey, baseUrl, event: (0, lifecycle_spool_1.payloadBoundEvent)(`owner-bypass-${correlation}`, {
                event_type: 'pre_action_checked',
                ...(0, hook_contract_1.clientReportedHookLifecycleIdentity)(identity),
                session_id: sessionId,
                workflow_id: (0, hook_contract_1.stableSessionWorkflowId)(sessionId),
                correlation_id: correlation,
                action: control_state_1.CONTROL_BYPASS_ACTION,
                target: BYPASS_TARGET[reason],
                surfaces: ['workspace'],
                risk_level: 'low',
                outcome_state: 'pending',
                intervention_disposition: 'overridden',
                action_changed: false,
            }) }).catch(() => null);
    }
    catch { /* telemetry never changes what a hook allows */ }
}
//# sourceMappingURL=owner-bypass.js.map