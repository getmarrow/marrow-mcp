"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.lifecycleSpoolCommandOutcome = lifecycleSpoolCommandOutcome;
/**
 * Maps spool state to the public CLI contract without conflating the active
 * credential namespace with isolated legacy files that this identity cannot
 * safely authenticate, replay, or claim.
 */
function lifecycleSpoolCommandOutcome(status, drain) {
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
//# sourceMappingURL=spool-command.js.map