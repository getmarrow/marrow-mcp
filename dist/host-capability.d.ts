export declare const NATIVE_HOOK_ACTIVITY: readonly ["native_hooks:prompt", "native_hooks:pre_action", "native_hooks:action_result", "native_hooks:session_end"];
export type MarrowCoverageMode = 'tools_only_on_demand';
export interface HostCapabilityInput {
    /** Display-only hint supplied at the adapter edge. It never grants coverage. */
    hostLabel?: string;
    /** Unattested client activity. It is useful telemetry and never grants coverage. */
    clientSelfReportedActivity?: readonly string[];
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
        source: 'independent_authority_required';
        model_name_is_evidence: false;
        configuration_detection_is_evidence: false;
        client_self_reports_certify_control: false;
        certified_receipts: string[];
    };
    activity: {
        source: 'client_self_reported';
        reported: string[];
        complete_native_hook_lifecycle_reported: boolean;
        certifies_control: false;
    };
    passive_hooks: {
        provided_by_mcp_transport: false;
        external_host_hook_state: 'unverified' | 'client_activity_reported';
        observed_by_this_process: false;
        certified_by_marrow: false;
        client_activity_stages: string[];
    };
    capability_modes: {
        tools_only: {
            state: 'available';
            scope: 'explicit_mcp_tool_calls';
        };
        native_hooks: {
            state: 'unverified' | 'activity_reported';
            scope: 'client_self_reported_lifecycle_only';
        };
        sdk_passive_runtime: {
            state: 'unverified' | 'activity_reported';
            scope: 'owned_node_process_while_installed';
        };
        governed_runner: {
            state: 'unverified' | 'activity_reported';
            scope: 'wrapped_command_only';
        };
        custom_host: {
            state: 'adapter_required' | 'activity_reported';
            scope: 'client_self_reported_event_lifecycle_only';
        };
    };
    always_on_state: 'not_verified';
    exact_next_action: string;
}
export declare function resolveHostCapability(input?: HostCapabilityInput): MarrowHostCapability;
export declare function hostCapabilityInstructions(capability: MarrowHostCapability): string;
//# sourceMappingURL=host-capability.d.ts.map