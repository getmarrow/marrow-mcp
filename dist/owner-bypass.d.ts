import { type resolveNativeHookIdentity } from './hook-contract';
/**
 * MCP-10: a hook that goes quiet on purpose (MARROW_AUTO_HOOK=false, or a control file that cannot be trusted) tells the backend once per
 * host session, when a key resolves, so the owner can see it. The event is the owner-bypass event 3.9.108 already sends while the owner has
 * local control off; only its target differs. Nothing here changes what the hook allows, and no value of any variable is recorded.
 */
export type BypassReason = 'hooks_switched_off' | 'control_state_unsafe';
export declare function recordSessionBypass(reason: BypassReason, identity: ReturnType<typeof resolveNativeHookIdentity>, input?: unknown): Promise<void>;
//# sourceMappingURL=owner-bypass.d.ts.map