import type { LifecycleSpoolStatus } from './lifecycle-spool';
export type LifecycleSpoolCommandOutcome = {
    output: {
        ok: boolean;
        scope: 'current_credential_namespace';
        legacy_namespace_debt: boolean;
        lifecycle_spool: LifecycleSpoolStatus;
    };
    exitCode: 0 | 1 | 2;
};
/**
 * Maps spool state to the public CLI contract without conflating the active
 * credential namespace with isolated legacy files that this identity cannot
 * safely authenticate, replay, or claim.
 */
export declare function lifecycleSpoolCommandOutcome(status: LifecycleSpoolStatus, drain: boolean): LifecycleSpoolCommandOutcome;
//# sourceMappingURL=spool-command.d.ts.map