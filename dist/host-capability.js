"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NATIVE_HOOK_RECEIPTS = void 0;
exports.resolveHostCapability = resolveHostCapability;
exports.hostCapabilityInstructions = hostCapabilityInstructions;
exports.NATIVE_HOOK_RECEIPTS = [
    'native_hooks:prompt',
    'native_hooks:pre_action',
    'native_hooks:action_result',
    'native_hooks:session_end',
];
const KNOWN_HOST_LABELS = new Set([
    'grok',
    'claude-code',
    'codex',
    'cursor',
    'windsurf',
    'gemini',
    'kimi',
    'qwen',
    'deepseek',
]);
const SDK_ACTIVE_RECEIPT = 'sdk_passive_runtime:active';
const GOVERNED_RUNNER_RECEIPT = 'governed_runner:wrapped_command';
const EVENT_ADAPTER_RECEIPT = 'event_adapter:lifecycle';
const KNOWN_CAPABILITY_RECEIPTS = new Set([
    ...exports.NATIVE_HOOK_RECEIPTS,
    SDK_ACTIVE_RECEIPT,
    GOVERNED_RUNNER_RECEIPT,
    EVENT_ADAPTER_RECEIPT,
]);
function normalizeHostLabel(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return KNOWN_HOST_LABELS.has(normalized)
        ? { host: normalized, source: 'adapter_hint' }
        : { host: 'mcp-client', source: 'generic_fallback' };
}
function resolveHostCapability(input = {}) {
    const identity = normalizeHostLabel(input.hostLabel);
    const observed = [...new Set(input.observedReceipts || [])]
        .filter((receipt) => typeof receipt === 'string' && KNOWN_CAPABILITY_RECEIPTS.has(receipt));
    const has = (receipt) => observed.includes(receipt);
    const nativeHooksVerified = exports.NATIVE_HOOK_RECEIPTS.every(has);
    const sdkVerified = has(SDK_ACTIVE_RECEIPT);
    const runnerVerified = has(GOVERNED_RUNNER_RECEIPT);
    const adapterVerified = has(EVENT_ADAPTER_RECEIPT);
    let currentMode = 'tools_only_on_demand';
    let coverageScope = 'explicit_mcp_tool_calls';
    let alwaysOnState = 'not_verified';
    let exactNextAction = 'Use Marrow MCP tools on demand. A custom host needs a bounded event adapter for passive lifecycle coverage; claim coverage only after Marrow observes its receipts.';
    if (nativeHooksVerified) {
        currentMode = 'verified_native_hooks';
        coverageScope = 'observed_hook_lifecycle_only';
        alwaysOnState = 'verified_passive';
        exactNextAction = 'Keep native hooks enabled and monitor observed prompt, pre-action, action-result, and session-end receipts.';
    }
    else if (sdkVerified) {
        currentMode = 'owned_sdk_process';
        coverageScope = 'owned_node_process_while_installed';
        alwaysOnState = 'bounded_process';
        exactNextAction = 'Treat passive coverage as limited to this owned Node process while createPassiveRuntime().install() remains active.';
    }
    else if (runnerVerified) {
        currentMode = 'governed_wrapped_command';
        coverageScope = 'wrapped_command_only';
        alwaysOnState = 'bounded_command';
        exactNextAction = 'Treat governance coverage as limited to the command launched through the governed runner.';
    }
    else if (adapterVerified) {
        currentMode = 'custom_event_adapter';
        coverageScope = 'observed_event_adapter_lifecycle_only';
        alwaysOnState = 'bounded_event_adapter';
        exactNextAction = 'Treat coverage as limited to lifecycle events emitted by the verified custom event adapter.';
    }
    return {
        contract_version: '2026-08-16',
        transport: 'mcp_stdio',
        host: identity.host,
        host_identity_source: identity.source,
        host_identity_affects_coverage: false,
        tools_available: true,
        tool_invocation: 'on_demand',
        current_mode: currentMode,
        coverage_verified: currentMode !== 'tools_only_on_demand',
        coverage_scope: coverageScope,
        certification: {
            source: 'observed_receipts_only',
            model_name_is_evidence: false,
            configuration_detection_is_evidence: false,
            observed_receipts: observed,
        },
        passive_hooks: {
            provided_by_mcp_transport: false,
            external_host_hook_state: nativeHooksVerified ? 'verified' : 'unverified',
            observed_by_this_process: false,
            observed_by_marrow: nativeHooksVerified,
            required_receipts: [...exports.NATIVE_HOOK_RECEIPTS],
        },
        capability_modes: {
            tools_only: { state: 'available', scope: 'explicit_mcp_tool_calls' },
            native_hooks: { state: nativeHooksVerified ? 'verified' : 'unverified', scope: 'observed_hook_lifecycle_only' },
            sdk_passive_runtime: { state: sdkVerified ? 'verified' : 'unverified', scope: 'owned_node_process_while_installed' },
            governed_runner: { state: runnerVerified ? 'verified' : 'unverified', scope: 'wrapped_command_only' },
            custom_host: { state: adapterVerified ? 'verified' : 'adapter_required', scope: 'observed_event_adapter_lifecycle_only' },
        },
        always_on_state: alwaysOnState,
        exact_next_action: exactNextAction,
    };
}
function hostCapabilityInstructions(capability) {
    return [
        `Current coverage: ${capability.current_mode} (${capability.coverage_scope}).`,
        'MCP tools are on demand. Capability boundaries: MCP tools-only is on demand; verified native hooks are passive only for observed hook lifecycle receipts; createPassiveRuntime().install() covers only its owned Node process while installed; a governed runner covers only its wrapped command; a custom host needs a bounded event adapter.',
        'A model name, host label, installed configuration, or detected hook file never certifies coverage. Only observed Marrow receipts do.',
        capability.exact_next_action,
    ].join(' ');
}
//# sourceMappingURL=host-capability.js.map