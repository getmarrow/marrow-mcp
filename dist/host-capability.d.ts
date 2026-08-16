export declare const NATIVE_HOOK_RECEIPTS: readonly ["native_hooks:prompt", "native_hooks:pre_action", "native_hooks:action_result", "native_hooks:session_end"];
export type MarrowCoverageMode = 'tools_only_on_demand' | 'verified_native_hooks' | 'owned_sdk_process' | 'governed_wrapped_command' | 'custom_event_adapter';
export interface HostCapabilityInput {
    /** Display-only hint supplied at the adapter edge. It never grants coverage. */
    hostLabel?: string;
    /** Trusted receipts observed by Marrow. Configuration or model detection is not evidence. */
    observedReceipts?: readonly string[];
}
export interface MarrowHostCapability {
    contract_version: '2026-08-16';
    transport: 'mcp_stdio';
    host: string;
    host_identity_source: 'adapter_hint' | 'generic_fallback';
    host_identity_affects_coverage: false;
    tools_available: true;
    tool_invocation: 'on_demand';
    current_mode: MarrowCoverageMode;
    coverage_verified: boolean;
    coverage_scope: string;
    certification: {
        source: 'observed_receipts_only';
        model_name_is_evidence: false;
        configuration_detection_is_evidence: false;
        observed_receipts: string[];
    };
    passive_hooks: {
        provided_by_mcp_transport: false;
        external_host_hook_state: 'unverified' | 'verified';
        observed_by_this_process: false;
        observed_by_marrow: boolean;
        required_receipts: string[];
    };
    capability_modes: {
        tools_only: {
            state: 'available';
            scope: 'explicit_mcp_tool_calls';
        };
        native_hooks: {
            state: 'unverified' | 'verified';
            scope: 'observed_hook_lifecycle_only';
        };
        sdk_passive_runtime: {
            state: 'unverified' | 'verified';
            scope: 'owned_node_process_while_installed';
        };
        governed_runner: {
            state: 'unverified' | 'verified';
            scope: 'wrapped_command_only';
        };
        custom_host: {
            state: 'adapter_required' | 'verified';
            scope: 'observed_event_adapter_lifecycle_only';
        };
    };
    always_on_state: 'not_verified' | 'verified_passive' | 'bounded_process' | 'bounded_command' | 'bounded_event_adapter';
    exact_next_action: string;
}
export declare function resolveHostCapability(input?: HostCapabilityInput): MarrowHostCapability;
export declare function hostCapabilityInstructions(capability: MarrowHostCapability): string;
//# sourceMappingURL=host-capability.d.ts.map