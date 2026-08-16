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
export function lifecycleSpoolCommandOutcome(
  status: LifecycleSpoolStatus,
  drain: boolean,
): LifecycleSpoolCommandOutcome {
  const currentNamespaceOk = drain ? status.state === 'clear' : status.state !== 'attention_required';
  const exitCode = status.state === 'attention_required'
    ? 2
    : drain && status.state !== 'clear'
      ? 1
      : 0;
  return {
    output: {
      ok: currentNamespaceOk,
      scope: 'current_credential_namespace',
      legacy_namespace_debt: status.other_namespaces.state === 'attention_required',
      lifecycle_spool: status,
    },
    exitCode,
  };
}
