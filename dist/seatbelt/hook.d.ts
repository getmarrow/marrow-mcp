import type { SeatbeltDecision, SeatbeltFs as MapperFs, SeatbeltGit } from './mapper';
import type { SeatbeltFs } from '../seatbelt-fs';
/**
 * Compiled-in rollout table. Not env, not a file: changing a value is a one-line, reviewed code
 * change. `keyless: 'off'` makes every keyless machine `claimed_no_key` (3.9.103 holds plus the
 * floor). `account_floor: 'on'` enforces the S0-S5 floor before the server flow.
 */
export declare const SEATBELT_ROLLOUT: {
    readonly keyless: 'on' | 'off';
    readonly account_floor: 'watch' | 'on';
};
/** One wall-clock budget for the whole seatbelt path (mode resolution and mapper). Over it: stop. */
export declare const HOOK_BUDGET_MS = 300;
export declare const CLAIMED_NO_KEY_TEXT = "Marrow is linked to an account but has no working key; owner: run `npx -y @getmarrow/install@latest doctor`.";
/**
 * `claimed_no_key` with no account evidence and no rejected key: a fallback because the machine's
 * setup could not be confirmed (an evidence dir others can write, an unreadable probe, a home
 * mismatch, strict mode). Same holds as CLAIMED_NO_KEY_TEXT, but it never claims an account exists.
 */
export declare const SETUP_UNCONFIRMED_TEXT = "Marrow has no working key on this machine and its keyless mode is off here (strict mode, or a home folder it cannot trust); owner: run `npx -y @getmarrow/install@latest doctor`.";
export declare function seatbeltStopText(category: string, rule: string, reason: string, mode: 'seatbelt' | 'claimed_no_key' | 'account', accountLinked?: boolean): string;
/** §4.2: an S0-S5 floor stop is lifted only by an enforced server allow (a verified permit); an advisory allow never lifts it. */
export declare function accountFloorStops(rollout: 'watch' | 'on', floor: Pick<SeatbeltDecision, 'decision'> | null, server: 'enforced_allow' | 'advisory_allow' | 'deny' | 'none'): boolean;
/** The mapper's file view over the host. Missing: null. A failure the mapper must not guess about throws (it stops on fs_error). */
export declare function hostMapperFs(fs3: SeatbeltFs): MapperFs;
/**
 * The git view the mapper gets (r4 contract). `currentBranch` is read at every call, never cached;
 * anything unclear is null. `getAll` throws when the config cannot be read in full.
 */
export declare function hostSeatbeltGit(fs3: SeatbeltFs, home: string, env: NodeJS.ProcessEnv): SeatbeltGit;
export interface SeatbeltHookEvent {
    tool_name: unknown;
    tool_input: unknown;
    /** The event's cwd as the harness sent it; anything but an absolute path means the workspace is unknown. */
    cwd: unknown;
    /** The harness adapter cut the input: the action is not known in full. */
    truncated: boolean;
    /** The harness session id; used only for the receipt's keyed session_key. */
    session?: unknown;
}
export interface KeylessOutcome {
    mode: 'seatbelt' | 'claimed_no_key';
    /** The agent text of a stop; null when the seatbelt passes the action. */
    stopText: string | null;
    /** True only with account evidence or a rejected key: then the text may say the machine is linked to an account. */
    accountLinked: boolean;
    /**
     * The mapper recognised the tool (audit H1). False: the seatbelt passed nothing it can vouch for, so
     * the hook gives master's answer for that host instead of the seatbelt pass.
     */
    recognized: boolean;
}
/** The keyless branch of the hook: mode (U4), then the mapper (U2) with the U3 resolvers. Never throws. */
export declare function keylessSeatbelt(harness: string, event: SeatbeltHookEvent): KeylessOutcome;
/**
 * The account floor. `watch`: computed after the answer, for the record only; it never throws and
 * never writes output. `on` (not active): run before the server flow; a returned text is a stop.
 */
export declare function accountFloor(harness: string, event: SeatbeltHookEvent, deadlineAt: number): string | null;
/**
 * I3: how the mapper reads an action for the outage hold (Marrow unreachable). `high`: an S0-S5/S-x hit
 * or a program on the outage list (git push, publish, deploy, remote delete), a dynamic subcommand of a
 * listed program included. `not_high`: the mapper read all of it and found neither. `unknown`: it could
 * not (budget, error, unparsed or dynamic text, truncated input, a tool it does not recognise); the hook
 * then keeps the client classifier's answer. `shell`: the event ran a shell command. Never throws;
 * writes no receipt or output.
 */
export declare function outageRisk(event: SeatbeltHookEvent, deadlineAt: number): {
    shell: boolean;
    risk: 'high' | 'not_high' | 'unknown';
};
//# sourceMappingURL=hook.d.ts.map