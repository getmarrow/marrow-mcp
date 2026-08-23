export const NATIVE_HOOK_ACTIVITY = [
  'native_hooks:prompt',
  'native_hooks:pre_action',
  'native_hooks:action_result',
  'native_hooks:session_end',
] as const;

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

const SDK_ACTIVE_ACTIVITY = 'sdk_passive_runtime:active';
const GOVERNED_RUNNER_ACTIVITY = 'governed_runner:wrapped_command';
const EVENT_ADAPTER_ACTIVITY = 'event_adapter:lifecycle';
const KNOWN_CLIENT_ACTIVITY = new Set([
  ...NATIVE_HOOK_ACTIVITY,
  SDK_ACTIVE_ACTIVITY,
  GOVERNED_RUNNER_ACTIVITY,
  EVENT_ADAPTER_ACTIVITY,
]);

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
    tools_only: { state: 'available'; scope: 'explicit_mcp_tool_calls' };
    native_hooks: { state: 'unverified' | 'activity_reported'; scope: 'client_self_reported_lifecycle_only' };
    sdk_passive_runtime: { state: 'unverified' | 'activity_reported'; scope: 'owned_node_process_while_installed' };
    governed_runner: { state: 'unverified' | 'activity_reported'; scope: 'wrapped_command_only' };
    custom_host: { state: 'adapter_required' | 'activity_reported'; scope: 'client_self_reported_event_lifecycle_only' };
  };
  always_on_state: 'not_verified';
  exact_next_action: string;
}

function normalizeHostLabel(value: string | undefined): { host: string; source: 'adapter_hint' | 'generic_fallback' } {
  const normalized = String(value || '').trim().toLowerCase();
  return KNOWN_HOST_LABELS.has(normalized)
    ? { host: normalized, source: 'adapter_hint' }
    : { host: 'mcp-client', source: 'generic_fallback' };
}

export function resolveHostCapability(input: HostCapabilityInput = {}): MarrowHostCapability {
  const identity = normalizeHostLabel(input.hostLabel);
  const reported = [...new Set(input.clientSelfReportedActivity || [])]
    .filter((activity): activity is string => typeof activity === 'string' && KNOWN_CLIENT_ACTIVITY.has(activity));
  const has = (activity: string): boolean => reported.includes(activity);
  const completeNativeHookActivity = NATIVE_HOOK_ACTIVITY.every(has);
  const sdkActivity = has(SDK_ACTIVE_ACTIVITY);
  const runnerActivity = has(GOVERNED_RUNNER_ACTIVITY);
  const adapterActivity = has(EVENT_ADAPTER_ACTIVITY);

  return {
    contract_version: '2026-08-16',
    transport: 'mcp_stdio',
    host: identity.host,
    host_identity_source: identity.source,
    host_identity_affects_coverage: false,
    tools_available: true,
    tool_invocation: 'on_demand',
    current_mode: 'tools_only_on_demand',
    coverage_verified: false,
    coverage_scope: 'explicit_mcp_tool_calls',
    certification: {
      source: 'independent_authority_required',
      model_name_is_evidence: false,
      configuration_detection_is_evidence: false,
      client_self_reports_certify_control: false,
      certified_receipts: [],
    },
    activity: {
      source: 'client_self_reported',
      reported,
      complete_native_hook_lifecycle_reported: completeNativeHookActivity,
      certifies_control: false,
    },
    passive_hooks: {
      provided_by_mcp_transport: false,
      external_host_hook_state: completeNativeHookActivity ? 'client_activity_reported' : 'unverified',
      observed_by_this_process: false,
      certified_by_marrow: false,
      client_activity_stages: [...NATIVE_HOOK_ACTIVITY],
    },
    capability_modes: {
      tools_only: { state: 'available', scope: 'explicit_mcp_tool_calls' },
      native_hooks: { state: completeNativeHookActivity ? 'activity_reported' : 'unverified', scope: 'client_self_reported_lifecycle_only' },
      sdk_passive_runtime: { state: sdkActivity ? 'activity_reported' : 'unverified', scope: 'owned_node_process_while_installed' },
      governed_runner: { state: runnerActivity ? 'activity_reported' : 'unverified', scope: 'wrapped_command_only' },
      custom_host: { state: adapterActivity ? 'activity_reported' : 'adapter_required', scope: 'client_self_reported_event_lifecycle_only' },
    },
    always_on_state: 'not_verified',
    exact_next_action: 'Use MCP tools on demand. For consequential CLI actions, use the governed wrapper: npx @getmarrow/install run --agent <agent-id> -- -- <command>. Custom hosts need a bounded event adapter; client activity alone does not certify control.',
  };
}

export function hostCapabilityInstructions(capability: MarrowHostCapability): string {
  return [
    `Current coverage: ${capability.current_mode} (${capability.coverage_scope}).`,
    'MCP tools are on demand. Configured native hooks provide cooperative telemetry or context only; createPassiveRuntime().install() is limited to its owned Node process; the governed wrapper is limited to its wrapped command; a custom host needs a bounded event adapter.',
    'A model name, host label, API key, public hook entrypoint, installed configuration, detected hook file, or client-self-reported lifecycle activity never certifies coverage or enforcement.',
    'For Codex, Grok, Gemini, and similar CLI harnesses, run consequential commands through: npx @getmarrow/install run --agent <agent-id> -- -- <command>.',
    capability.exact_next_action,
  ].join(' ');
}
