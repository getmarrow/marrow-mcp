import { createHash } from 'node:crypto';
import { validateBaseUrl } from './index';
import { CONTROL_BYPASS_ACTION } from './control-state';
import { clientReportedHookLifecycleIdentity, normalizeHookEventPayload, stableSessionWorkflowId, type resolveNativeHookIdentity } from './hook-contract';
import { payloadBoundEvent, recordLifecycleEvent } from './lifecycle-spool';
import { claimSessionMarker } from './session-marker';

/**
 * MCP-10: a hook that goes quiet on purpose (MARROW_AUTO_HOOK=false, or a control file that cannot be trusted) tells the backend once per
 * host session, when a key resolves, so the owner can see it. The event is the owner-bypass event 3.9.108 already sends while the owner has
 * local control off; only its target differs. Nothing here changes what the hook allows, and no value of any variable is recorded.
 */
export type BypassReason = 'hooks_switched_off' | 'control_state_unsafe';
const BYPASS_TARGET: Record<BypassReason, string> = {
  hooks_switched_off: 'marrow:hooks-switched-off',
  control_state_unsafe: 'marrow:control-state-unsafe',
};
const MAX_INPUT_BYTES = 1024 * 1024;
const INPUT_WAIT_MS = 1_500;

function readHookInput(): Promise<unknown> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) { resolve(undefined); return; }
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (): void => {
      clearTimeout(timer);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { resolve(undefined); }
    };
    const timer = setTimeout(finish, INPUT_WAIT_MS);
    process.stdin.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_INPUT_BYTES) { chunks.length = 0; finish(); return; }
      chunks.push(chunk);
    });
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
  });
}

export async function recordSessionBypass(
  reason: BypassReason,
  identity: ReturnType<typeof resolveNativeHookIdentity>,
  input?: unknown,
): Promise<void> {
  try {
    const resolved = identity.environment;
    if (!resolved.apiKey) return;
    const event = normalizeHookEventPayload(input === undefined ? await readHookInput() : input);
    const named = [event.session_id, event.conversation_id, event.task_id].find((value) => typeof value === 'string' && value.length > 0);
    const sessionId = resolved.sessionId || (typeof named === 'string' ? named : '');
    if (!sessionId || !claimSessionMarker(`bypass-${reason.replace(/_/g, '-')}`, sessionId)) return;
    const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
    const correlation = createHash('sha256').update(`${reason}\n${sessionId}`).digest('hex').slice(0, 24);
    await recordLifecycleEvent({ apiKey: resolved.apiKey, baseUrl, event: payloadBoundEvent(`owner-bypass-${correlation}`, {
      event_type: 'pre_action_checked',
      ...clientReportedHookLifecycleIdentity(identity),
      session_id: sessionId,
      workflow_id: stableSessionWorkflowId(sessionId),
      correlation_id: correlation,
      action: CONTROL_BYPASS_ACTION,
      target: BYPASS_TARGET[reason],
      surfaces: ['workspace'],
      risk_level: 'low',
      outcome_state: 'pending',
      intervention_disposition: 'overridden',
      action_changed: false,
    }) }).catch(() => null);
  } catch { /* telemetry never changes what a hook allows */ }
}
