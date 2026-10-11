"use strict";
/**
 * Marrow's MCP tool registry: every tool this package can serve, plus the
 * names each MARROW_TOOL_PROFILE exposes. Side-effect free, so the hooks can
 * import the exact registered names (see own-tool.ts).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PRIMARY_TOOL_NAMES = exports.CORE_TOOL_NAMES = exports.TOOLS = void 0;
const model_usage_1 = require("./model-usage");
// Tool definitions (unchanged)
exports.TOOLS = [
    {
        name: 'marrow_orient',
        description: 'Call at session start or before meaningful work. ' +
            'Returns authorized prior lessons and failure warnings for the current account or agent. ' +
            'If shouldPause=true, stop and review the lesson before acting. ' +
            'Use marrow_agent_runtime for the policy gate before a consequential side effect.',
        inputSchema: {
            type: 'object',
            properties: {
                taskType: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Optional: filter warnings to a specific task type you are about to perform',
                },
                autoWarn: {
                    type: 'boolean',
                    description: 'Enable active intervention: scans recent failures, returns HIGH/MEDIUM/LOW severity warnings with recommendations. Recommended: true.',
                },
            },
            required: [],
        },
    },
    {
        name: 'marrow_think',
        description: 'Record intent and retrieve authorized governance intelligence before acting. ' +
            'Returns a decision_id for outcome closure plus relevant patterns, prior outcomes, and recommendedNext. ' +
            'Pass previous_outcome to auto-commit the last decision and open a new one. ' +
            'Response MAY include: onboarding_hint (new accounts), intelligence.collective (cross-account patterns), intelligence.team_context (recent decisions from other sessions).',
        inputSchema: {
            type: 'object',
            properties: {
                idempotency_key: { type: 'string', description: 'Original privacy-safe pending receipt key when resuming the identical think request.' },
                request_hash: { type: 'string', description: 'Pending receipt request_hash; validates unchanged arguments, credentials, agent and session before resuming.' },
                action: { type: 'string', description: 'What the agent is about to do' },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
                },
                context: { type: 'object', description: 'Optional metadata about the current situation' },
                previous_decision_id: { type: 'string', description: 'decision_id from previous think() call — auto-commits that session' },
                previous_success: { type: 'boolean', description: 'Did the previous action succeed?' },
                previous_outcome: { type: 'string', description: 'What happened in the previous action (required if previous_decision_id provided)' },
                checkLoop: { type: 'boolean', description: 'Enable loop detection: warns if you are about to retry a failed approach. Recommended: true.' },
                source_kind: {
                    type: 'string',
                    enum: ['human_directed', 'agent_autonomous', 'scheduled', 'integration', 'system', 'unknown'],
                    description: 'Optional provenance source. Defaults to agent_autonomous for MCP calls.',
                },
                human_directed: { type: 'boolean', description: 'True only when the action is directly requested by the owner/user.' },
                instruction_ref: { type: 'string', description: 'Optional privacy-safe opaque reference. Dates, long digit runs, provider IDs, addresses, and domains are rejected locally; valid values are preserved exactly.' },
                source_meta: { type: 'object', description: 'Optional provenance metadata. PII and raw provider IDs are rejected by the API.' },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_commit',
        description: 'Close a recorded action with success/failure, a specific outcome, and required proof. ' +
            'decision_id comes from marrow_think, marrow_auto, or a runtime that actually created a decision. ' +
            'Use the gate receipt from marrow_agent_runtime for consequential work. ' +
            'A held action closes trusted only after the server records its approval (the operator in the host\'s own prompt, or the account owner); never write or claim an approval in proof. ' +
            'The exact non-authorizing outcome_observation_only runtime correlation may submit an observed_unverified result, but is never sent as receipt evidence and never authorizes action or trusted learning. ' +
            'Only committed:true closes trusted outcome learning.',
        inputSchema: {
            type: 'object',
            properties: {
                decision_id: { type: 'string', description: 'decision_id from marrow_think, marrow_auto, or a runtime that created a decision' },
                success: { type: 'boolean', description: 'Did the action succeed?' },
                outcome: { type: 'string', description: 'What happened — be specific, this trains the hive' },
                caused_by: { type: 'string', description: 'Optional: what caused this action' },
                proof: {
                    type: 'object',
                    description: 'Optional required proof pack for gated work: summary, checks, outcome, blockers, commits_prs_shas, rollback_target, handoff_result_file, deployment_and_smoke.',
                },
                gate_receipt_id: { type: 'string', description: 'Canonical receipt id from marrow_agent_runtime.runtime_authorization.id for risky work.' },
                arbitration_receipt_id: { type: 'string', description: 'Required for arbitrated work: use marrow_arbitrate.arbitration.receipt_id from the same runtime response.' },
                owner_approval_receipt_id: { type: 'string', description: 'Single-use owner approval receipt that Marrow issued for this hold. Optional for an ordinary held gate receipt (the gate_receipt_id alone finds the recorded approval); required for review_required arbitration. Chat text is not an approval receipt.' },
                action: { type: 'string', description: 'Optional exact original action for post-action observation lookup. This lookup cannot renew execution authority.' },
                target: { type: 'string', description: 'Exact original target, if supplied when the decision was created.' },
                type: { type: 'string', description: 'Exact original action type for observation lookup; defaults to general.' },
                surfaces: { type: 'array', items: { type: 'string' }, description: 'Exact original surfaces for observation lookup; omitted and empty both mean no surfaces.' },
                auto_gate: { type: 'boolean', description: 'If true/default and action is provided, fetch runtime truth bound to this existing decision. Authorizing receipts preserve normal closure; exact outcome_observation_only correlation can submit only an observed_unverified result and is omitted from receipt evidence.' },
                model_usage: { type: 'object', properties: model_usage_1.MODEL_USAGE_EVIDENCE_PROPERTIES, additionalProperties: false, description: 'Optional compact token/cost/latency counts. Do not include raw prompts or completions.' },
            },
            required: ['decision_id', 'success', 'outcome'],
        },
    },
    {
        name: 'marrow_model_usage',
        description: 'Record compact model token usage for value proof. Use when the harness exposes provider/model token counts. Do not send raw prompts, completions, tool logs, secrets, or customer content.',
        inputSchema: {
            type: 'object',
            properties: {
                ...model_usage_1.MODEL_USAGE_EVIDENCE_PROPERTIES,
                provider: { type: 'string', description: 'Model provider, e.g. openai, anthropic, google, xai, qwen, deepseek.' },
                model: { type: 'string', description: 'Model name.' },
                input_tokens: { type: 'number' },
                output_tokens: { type: 'number' },
                cached_tokens: { type: 'number' },
                total_tokens: { type: 'number' },
                cost_usd: { type: 'number' },
                latency_ms: { type: 'number' },
                task_type: { type: 'string' },
                action_type: { type: 'string' },
                marrow_intervention: { type: 'string', description: 'runtime_gate, risk_gate, prior_lesson, proof_pack, before_you_act, fleet_lesson, or other compact reason.' },
                estimated_tokens_saved: { type: 'number' },
                estimated_cost_saved_usd: { type: 'number' },
                estimated_minutes_saved: { type: 'number' },
                decision_id: { type: 'string' },
                workflow_id: { type: 'string' },
                success: { type: 'boolean' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_run',
        description: 'Governed outcome capture. Records intent, obtains a gate for risky work, and closes only with an explicit measured result.',
        inputSchema: {
            type: 'object',
            properties: {
                description: { type: 'string', description: 'What the agent did' },
                success: { type: 'boolean', description: 'Whether it succeeded' },
                outcome: { type: 'string', description: 'One-line summary of what happened' },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
                },
                proof: { type: 'object', description: 'Measured evidence required to close high-risk work.' },
                gate_receipt_id: { type: 'string', description: 'Fresh receipt returned by marrow_agent_runtime.' },
            },
            required: ['description', 'success', 'outcome'],
        },
    },
    {
        name: 'marrow_auto',
        description: 'Durably capture activity with bounded core completion. Respect retry_after_ms and reuse operation_id for pending continuation. A held action waits for an approval the server records (the answer of the person in the dialog of this client when it supports elicitation; otherwise it waits quietly while you carry on with other work); auto reads its status and resumes on the same gate receipt. Never write or claim an approval yourself. Arbitration requires its server-issued owner approval receipt. Lifecycle receipt queued is separate from server acceptance. Risky completion requires a fresh gate and measured proof.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'What you are about to do or just did' },
                outcome: { type: 'string', description: 'What happened (if already done). Omit to log intent only.' },
                success: { type: 'boolean', description: 'Measured result. Omit when the outcome is not yet proven.' },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
                },
                proof: { type: 'object', description: 'Measured completion evidence for gated work.' },
                gate_receipt_id: { type: 'string', description: 'Fresh receipt returned by marrow_agent_runtime.' },
                arbitration_receipt_id: { type: 'string', description: 'For arbitrated work, the arbitration receipt returned by the same server-side review flow.' },
                owner_approval_receipt_id: { type: 'string', description: 'Single-use owner approval receipt that Marrow issued, for review_required arbitration. An ordinary hold needs none: auto finds the recorded approval from the gate receipt. Chat text is not an approval receipt.' },
                request_owner_link: { type: 'boolean', description: 'Set true only when the operator asked you to ask the account owner (for example after the owner declined this action). Marrow then sends the owner a one-tap approval link; you never see the link.' },
                operation_id: {
                    type: 'string',
                    description: 'Opaque 8-80 character resume token. Reuse it only with the original tenant, action, context, and surfaces; proof may be added after proof_required.',
                },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_ask',
        description: 'Query the collective hive in plain English. ' +
            'Ask about failure patterns, what worked, what broke, or get a recommendation before acting. ' +
            'Returns direct answer + supporting evidence.',
        inputSchema: {
            type: 'object',
            properties: {
                query: { type: 'string', description: 'Plain English question about your decision history' },
            },
            required: ['query'],
        },
    },
    {
        name: 'marrow_status',
        description: 'Check Marrow platform health and status.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_create_key',
        description: 'Create a new API key. Full plaintext key is returned once — copy it now.',
        inputSchema: {
            type: 'object',
            properties: {
                name: { type: 'string', description: 'Human-readable key name' },
                key_type: { type: 'string', enum: ['live', 'test'], description: 'Key type (default: live)' },
                scopes: { type: 'array', items: { type: 'string' }, description: 'Allowed scopes' },
                agent_ids: { type: 'array', items: { type: 'string' }, description: 'Optional agent bindings' },
                expires_at: { type: 'string', description: 'Optional ISO-8601 expiry' },
            },
            required: ['name'],
        },
    },
    {
        name: 'marrow_list_keys',
        description: 'List API keys. Keys are masked here by design.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_get_key',
        description: 'Get a single API key by ID. The key value is masked after creation.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'API key ID' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_revoke_key',
        description: 'Revoke an API key by ID.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'API key ID' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_rotate_key',
        description: 'Rotate an API key by ID. Full plaintext key is returned once — copy it now.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'API key ID' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_list_memories',
        description: 'List memories with optional filters (status, query, limit, agent_id for shared memories).',
        inputSchema: {
            type: 'object',
            properties: {
                status: { type: 'string', enum: ['active', 'outdated', 'deleted'], description: 'Filter by status' },
                query: { type: 'string', description: 'Search query' },
                limit: { type: 'number', description: 'Max results (default: 20)' },
                agentId: { type: 'string', description: 'Agent ID for shared memories' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_get_memory',
        description: 'Get a single memory by ID.',
        inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'Memory ID' } }, required: ['id'] },
    },
    {
        name: 'marrow_update_memory',
        description: 'Update memory text, tags, or metadata.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID' },
                text: { type: 'string', description: 'New text' },
                source: { type: 'string', description: 'Source' },
                tags: { type: 'array', items: { type: 'string' }, description: 'Tags' },
                actor: { type: 'string', description: 'Actor name' },
                note: { type: 'string', description: 'Audit note' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_delete_memory',
        description: 'Soft delete a memory.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID' },
                actor: { type: 'string', description: 'Actor name' },
                note: { type: 'string', description: 'Audit note' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_mark_outdated',
        description: 'Mark a memory as outdated.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID' },
                actor: { type: 'string', description: 'Actor name' },
                note: { type: 'string', description: 'Audit note' },
            },
            required: ['id'],
        },
    },
    {
        name: 'marrow_supersede_memory',
        description: 'Atomically replace a memory with a new version.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID to supersede' },
                text: { type: 'string', description: 'New memory text' },
                source: { type: 'string', description: 'Source' },
                tags: { type: 'array', items: { type: 'string' }, description: 'Tags' },
                actor: { type: 'string', description: 'Actor name' },
                note: { type: 'string', description: 'Audit note' },
            },
            required: ['id', 'text'],
        },
    },
    {
        name: 'marrow_share_memory',
        description: 'Share a memory with specific agents.',
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID' },
                agentIds: { type: 'array', items: { type: 'string' }, description: 'Agent IDs to share with' },
                actor: { type: 'string', description: 'Actor name' },
            },
            required: ['id', 'agentIds'],
        },
    },
    {
        name: 'marrow_export_memories',
        description: 'Export memories to JSON or CSV.',
        inputSchema: {
            type: 'object',
            properties: {
                format: { type: 'string', enum: ['json', 'csv'], description: 'Export format' },
                status: { type: 'string', enum: ['active', 'all'], description: 'Filter by status' },
                tags: { type: 'string', description: 'Comma-separated tags' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_import_memories',
        description: 'Import memories with merge (dedup) or replace mode.',
        inputSchema: {
            type: 'object',
            properties: {
                memories: { type: 'array', items: { type: 'object', properties: { text: { type: 'string' }, source: { type: 'string' }, tags: { type: 'array', items: { type: 'string' } } } }, description: 'Memories to import' },
                mode: { type: 'string', enum: ['merge', 'replace'], description: 'Import mode' },
            },
            required: ['memories', 'mode'],
        },
    },
    {
        name: 'marrow_retrieve_memories',
        description: 'Full-text search memories with filters (from, to, tags, source, status, shared).',
        inputSchema: {
            type: 'object',
            properties: {
                query: { type: 'string', description: 'Search query' },
                limit: { type: 'number', description: 'Max results' },
                from: { type: 'string', description: 'From date (ISO-8601)' },
                to: { type: 'string', description: 'To date (ISO-8601)' },
                tags: { type: 'string', description: 'Comma-separated tags' },
                source: { type: 'string', description: 'Source filter' },
                status: { type: 'string', enum: ['active', 'outdated', 'deleted'], description: 'Status filter' },
                shared: { type: 'boolean', description: 'Include shared memories' },
            },
            required: ['query'],
        },
    },
    {
        name: 'marrow_workflow',
        description: 'Interact with Marrow Workflow Registry. Register, start, and advance multi-step workflows. ' +
            'Actions: register (create workflow template), list (show all), get (details), start (begin instance), ' +
            'advance (complete a step), instances (list runs).',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', enum: ['register', 'list', 'get', 'update', 'start', 'advance', 'instances'], description: 'Workflow action to perform' },
                workflowId: { type: 'string', description: 'Workflow ID (required for get/start/advance/instances)' },
                instanceId: { type: 'string', description: 'Instance ID (required for advance)' },
                name: { type: 'string', description: 'Workflow name (for register)' },
                description: { type: 'string', description: 'Workflow description (for register/update)' },
                steps: { type: 'array', description: 'Step definitions (for register)', items: { type: 'object', properties: { step: { type: 'number', description: 'Step order (1, 2, 3...)' }, agent_role: { type: 'string', description: 'Expected agent role (e.g., "builder", "auditor")' }, action_type: { type: 'string', description: 'Action type (e.g., "build", "audit", "patch")' }, description: { type: 'string', description: 'Step description' } }, required: ['step', 'description'] } },
                tags: { type: 'array', items: { type: 'string' }, description: 'Tags (for register)' },
                agentId: { type: 'string', description: 'Agent ID starting the workflow (for start)' },
                context: { type: 'object', description: 'Workflow context (for start)' },
                inputs: { type: 'object', description: 'Workflow inputs (for start)' },
                stepCompleted: { type: 'number', description: 'Step number completed (for advance)' },
                outcome: { type: 'string', description: 'Step outcome (for advance)' },
                nextAgentId: { type: 'string', description: 'Next agent for the following step (for advance)' },
                contextUpdate: { type: 'object', description: 'Context changes (for advance)' },
                status: { type: 'string', enum: ['running', 'completed', 'failed', 'cancelled', 'active', 'archived'], description: 'Filter by status (for list/instances)' },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_dashboard',
        description: 'Get operator dashboard — account health, top failures, workflow status, recent activity, Marrow\'s saves metric. ' +
            'One call returns everything an operator needs to see.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_digest',
        description: 'Get periodic summary of agent activity and Marrow impact (default 7-day period). ' +
            'Shows decision counts, success rate trend vs previous period, saves, top improvements and risks.',
        inputSchema: {
            type: 'object',
            properties: {
                period: { type: 'string', description: 'Time period: 7d (default), 14d, or 30d' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_agent_status',
        description: 'Check whether Marrow is passively active for this agent or fleet. ' +
            'Returns connected state, signal quality, non-sensitive proof, and next actions. ' +
            'Use at session start or before owner reporting to prove Marrow is working without a dashboard.',
        inputSchema: {
            type: 'object',
            properties: {
                period: { type: 'string', description: 'Time period: 7d (default), 14d, or 30d' },
                agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_runtime_status',
        description: 'Read live Marrow runtime hook diagnostics from /v1/agent/status. ' +
            'Use this when an agent needs exact passive hook, token-capture, outcome-closure, client-update, and repair-command status.',
        inputSchema: {
            type: 'object',
            properties: {
                fast: { type: 'boolean', description: 'Use fast cached summary path when available. Defaults to true.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_value_report',
        description: 'Get owner-ready proof of Marrow value for this agent or fleet. ' +
            'Returns summary, decision metrics, saves, active agents, top risks, recommendations, and improvement data without raw decision text.',
        inputSchema: {
            type: 'object',
            properties: {
                period: { type: 'string', description: 'Time period: 7d (default), 14d, 30d, or a day count up to 90.' },
                agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_decision_brief',
        description: 'One pre-action call before meaningful or risky work. Returns risk level, workflow/playbook steps, ' +
            'handoff requirements, freshness/source-of-truth checks, minimum verification checks, proof-pack fields, ' +
            'and next actions. Use this before deploys, publishes, merges, audits, patches, secret changes, or production work.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'What the agent is about to do.' },
                type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
                role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
                agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
                sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
                surfaces: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Surfaces to keep current, e.g. github, npm, docs, production, secrets.',
                },
                period: { type: 'number', description: 'Lookback period in days, default 7, max 90.' },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_first_value',
        description: 'First-run Marrow value proof. Returns what is captured, whether outcome closure/runtime gate are active, ' +
            'a plain-English first useful lesson, and a five-minute try-this-now prompt for agents and owners.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'Optional action to test. Defaults to a production deploy safety prompt.' },
                type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
                role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
                agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
                sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
                surfaces: { type: 'array', items: { type: 'string' }, description: 'Surfaces to test, e.g. production, deploy, github, npm.' },
                context: { type: 'object', description: 'Optional non-sensitive metadata.' },
                proof: { type: 'object', description: 'Optional proof fields already collected.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_agent_runtime',
        description: 'One-call agent-native Marrow loop. Returns passive status, decision brief, risk gate, relevant lessons, ' +
            'template suggestion, required proof pack, before-you-act instruction, and exact next action. ' +
            'Its runtime_authorization is the authoritative gate receipt; it returns decision_id only when runtime actually creates a decision. ' +
            'Reuse its server-created decision_id for outcome closure; use marrow_auto or marrow_think only when the completion contract requires decision creation. ' +
            'A review_required hold does not permit the action: wait until the server records an approval, then commit with the same gate receipt. ' +
            'Use this before meaningful work when you want Marrow to guide the whole action in one call.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'What the agent is about to do.' },
                type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
                role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
                agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
                sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
                surfaces: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Surfaces to keep current, e.g. github, npm, docs, production, secrets.',
                },
                context: { type: 'object', description: 'Optional non-sensitive metadata.' },
                proof: { type: 'object', description: 'Optional proof fields already collected, such as checks, rollback_target, smoke_result.' },
                period: { type: 'number', description: 'Lookback period in days, default 7, max 90.' },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_arbitrate',
        description: 'Resolve conflicting next-step proposals from two or more tenant agents before execution. ' +
            'Uses the existing Marrow runtime gate and returns a durable arbitration receipt with the selected, ' +
            'synthesized, review-required, or blocked action and exactly why it changed.',
        inputSchema: {
            type: 'object',
            properties: {
                objective: { type: 'string', description: 'The shared owner or workflow objective.' },
                ownerIntent: { type: 'string', description: 'Optional bounded owner intent used for deterministic alignment.' },
                conflictType: {
                    type: 'string',
                    enum: ['action_conflict', 'policy_conflict', 'evidence_conflict', 'authority_conflict', 'risk_conflict'],
                },
                proposals: {
                    type: 'array',
                    minItems: 2,
                    maxItems: 8,
                    items: {
                        type: 'object',
                        properties: {
                            proposal_id: { type: 'string', description: 'Stable opaque proposal id.' },
                            agent_id: { type: 'string', description: 'Existing agent id in this Marrow account.' },
                            action: { type: 'string', description: 'Proposed next action.' },
                            rationale: { type: 'string', description: 'Optional concise rationale; redacted before transport.' },
                            confidence: { type: 'number', minimum: 0, maximum: 1 },
                            risk_level: { type: 'string', enum: ['low', 'medium', 'high'] },
                            requires_owner_approval: { type: 'boolean' },
                            evidence: {
                                type: 'array',
                                maxItems: 8,
                                items: {
                                    type: 'object',
                                    properties: {
                                        kind: { type: 'string' },
                                        reference: { type: 'string', description: 'Opaque identifier only; no URL, path, or raw evidence.' },
                                    },
                                    required: ['kind', 'reference'],
                                },
                            },
                        },
                        required: ['proposal_id', 'agent_id', 'action'],
                    },
                },
                action: { type: 'string', description: 'Optional runtime action label.' },
                type: { type: 'string', description: 'Optional runtime action type. Defaults to coordination.' },
                agentId: { type: 'string', description: 'Requesting agent id. Defaults to the canonical fleet-bound agent identity.' },
                sessionId: { type: 'string', description: 'Optional workflow session id.' },
                surfaces: { type: 'array', items: { type: 'string' } },
                context: { type: 'object', description: 'Optional non-sensitive runtime metadata.' },
                proof: { type: 'object', description: 'Optional proof already available to the runtime gate.' },
            },
            required: ['objective', 'proposals'],
        },
    },
    {
        name: 'marrow_coordinate',
        description: 'Coordinate tenant agents without sharing transcripts. Acquire or release a bounded resource lease, ' +
            'list current leases, or create/list compact evidence-backed child proof packets for a parent agent.',
        inputSchema: {
            type: 'object',
            properties: {
                action: {
                    type: 'string',
                    enum: ['list_leases', 'acquire_lease', 'release_lease', 'list_proof_packets', 'create_proof_packet'],
                },
                resource_type: { type: 'string', enum: ['file', 'directory', 'service', 'workflow', 'deployment', 'custom'] },
                resource: { type: 'string', maxLength: 160, description: 'Bounded tenant-visible resource label. Do not send secrets.' },
                workflow_id: { type: 'string' },
                ttl_seconds: { type: 'number', minimum: 30, maximum: 3600 },
                lease_id: { type: 'string' },
                lease_token: { type: 'string', description: 'One-time lease capability returned by acquire_lease.' },
                status: { type: 'string', enum: ['active', 'released', 'expired', 'incomplete', 'complete', 'failed'] },
                limit: { type: 'number', minimum: 1, maximum: 100 },
                decision_id: { type: 'string' },
                proof_pack_id: { type: 'string' },
                summary: { type: 'string', maxLength: 280, description: 'Compact result summary; no raw transcript.' },
                evidence_refs: {
                    type: 'array', maxItems: 20, items: { type: 'string' },
                    description: 'Opaque durable evidence identifiers only.',
                },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_replay_compare',
        description: 'Compare two already-recorded outcomes for the same tenant task using durable proof. ' +
            'This does not run a model or replay customer content; it returns complete or insufficient_evidence.',
        inputSchema: {
            type: 'object',
            additionalProperties: false,
            properties: {
                comparison_id: { type: 'string', minLength: 1, description: 'Fetch a prior replay comparison by id.' },
                source_decision_id: {
                    type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9._:-]{1,128}$',
                    description: 'Original task decision used to bind the comparison.',
                },
                workspace_binding_id: {
                    type: 'string', minLength: 34, maxLength: 34, pattern: '^workspace_[a-f0-9]{24}$',
                    description: 'Optional privacy-safe workspace binding from runtime.',
                },
                constraints: {
                    type: 'object',
                    additionalProperties: false,
                    maxProperties: 7,
                    description: 'Allowlisted comparison labels only; prompts, code, transcripts, credentials, and nested content are rejected.',
                    properties: {
                        environment: { type: 'string', maxLength: 80 },
                        tests: { type: 'string', maxLength: 80 },
                        policy_profile_id: { type: 'string', maxLength: 80 },
                        workflow_type: { type: 'string', maxLength: 80 },
                        task_type: { type: 'string', maxLength: 80 },
                        required_proof: { type: 'boolean' },
                        same_workspace: { type: 'boolean' },
                    },
                },
                baseline: {
                    type: 'object',
                    additionalProperties: false,
                    maxProperties: 2,
                    properties: {
                        label: { type: 'string', minLength: 1, maxLength: 80, pattern: '^[A-Za-z0-9._:-]{1,80}$' },
                        decision_id: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9._:-]{1,128}$' },
                    },
                    required: ['decision_id'],
                },
                candidate: {
                    type: 'object',
                    additionalProperties: false,
                    maxProperties: 2,
                    properties: {
                        label: { type: 'string', minLength: 1, maxLength: 80, pattern: '^[A-Za-z0-9._:-]{1,80}$' },
                        decision_id: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9._:-]{1,128}$' },
                    },
                    required: ['decision_id'],
                },
            },
            oneOf: [
                {
                    required: ['comparison_id'],
                    not: {
                        anyOf: [
                            { required: ['source_decision_id'] },
                            { required: ['workspace_binding_id'] },
                            { required: ['constraints'] },
                            { required: ['baseline'] },
                            { required: ['candidate'] },
                        ],
                    },
                },
                {
                    required: ['source_decision_id', 'baseline', 'candidate'],
                    not: { required: ['comparison_id'] },
                },
            ],
        },
    },
    {
        name: 'marrow_governance_control_plane',
        description: 'Return Marrow control-plane proof: governance, runtime gates, proof packs, fleet intelligence, supported harnesses, and exact next action.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_hermes_integration',
        description: 'Return the Hermes Agent integration guide mapping /goal, verification evidence, /learn, /journey, and background subagents into Marrow proof and outcome workflows.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_completion_contracts',
        description: 'List Marrow completion contracts for deploy, merge, publish, database migration, security change, support response, and Hermes goal workflows.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_evaluate_completion_contract',
        description: 'Evaluate whether an agent has enough proof to mark work complete. Returns complete, missing_proof, review_required, or blocked with missing proof fields.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'Action/workflow being completed, e.g. deploy, publish, db_migration, hermes_goal.' },
                workflow_type: { type: 'string', description: 'Optional workflow type if action is not supplied.' },
                risk_level: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Optional risk override.' },
                evidence: { type: 'object', description: 'Non-sensitive proof fields already collected.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_governance_timeline',
        description: 'Return the recent fleet governance timeline across decisions, risk gates, and proof-pack events.',
        inputSchema: {
            type: 'object',
            properties: {
                agentId: { type: 'string', description: 'Optional agent filter. Defaults to the canonical fleet-bound agent identity.' },
                limit: { type: 'number', description: 'Max events to return, default 25, max 100.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_decision_trace',
        description: 'Inspect the tenant-scoped path behind one governed decision and return its owner-readable intervention receipt with gate, required workflow, permit follow-through, proof, and observed outcome.',
        inputSchema: {
            type: 'object',
            properties: {
                decisionId: { type: 'string', description: 'Decision ID owned by this account and agent scope.' },
            },
            required: ['decisionId'],
        },
    },
    {
        name: 'marrow_buyer_proof',
        description: 'Return buyer-grade value proof: failures avoided, risky actions reviewed, proofs completed, token/time saved, failure classes, agent leaderboard, and reliability score.',
        inputSchema: {
            type: 'object',
            properties: {
                agentId: { type: 'string', description: 'Optional agent filter. Defaults to the canonical fleet-bound agent identity.' },
                periodDays: { type: 'number', description: 'Lookback period in days, default 30, max 90.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_mode_recommend',
        description: 'Recommend passive, pilot, or enforce mode from project/workflow signals. Marrow never auto-switches here; the agent/user must accept or override.',
        inputSchema: {
            type: 'object',
            properties: {
                project: { type: 'object', description: 'Project signals: name, type, frameworks, signals, package_scripts, config_files.' },
                workflow: { type: 'object', description: 'Workflow context: action, type, branch, environment.' },
                agent: { type: 'object', description: 'Agent context: id and role.' },
                selected_mode: { type: 'string', enum: ['passive', 'pilot', 'enforce'], description: 'Optional final user-selected mode to log.' },
                selection_source: { type: 'string', enum: ['accepted', 'overridden', 'ignored', 'system'], description: 'How the final mode was selected.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_policy_profiles',
        description: 'List saved Marrow governance policy profiles for this account. Returns default-business when none are saved.',
        inputSchema: { type: 'object', properties: {}, required: [] },
    },
    {
        name: 'marrow_create_policy_profile',
        description: 'Create or update an explicit governance policy profile. Mutating call; requires a key with full scope.',
        inputSchema: {
            type: 'object',
            properties: {
                name: { type: 'string', description: 'Profile name, e.g. default-business or production-agents.' },
                description: { type: 'string', description: 'Optional profile description.' },
                rules: { type: 'array', items: { type: 'object' }, description: 'Rules with match fields and mode passive/pilot/enforce.' },
            },
            required: ['name'],
        },
    },
    {
        name: 'marrow_assign_project_policy_profile',
        description: 'Assign an active governance policy profile to a project key. Mutating call; requires a key with full scope.',
        inputSchema: {
            type: 'object',
            properties: {
                project_key: { type: 'string', description: 'Stable project key, e.g. marrow-api or clinic-api.' },
                profile_id: { type: 'string', description: 'Active policy profile id.' },
            },
            required: ['project_key', 'profile_id'],
        },
    },
    {
        name: 'marrow_policy_resolve',
        description: 'Resolve the explicit mode for a project/workflow from saved policy profiles, falling back to recommendation. Does not auto-apply.',
        inputSchema: {
            type: 'object',
            properties: {
                profile_id: { type: 'string', description: 'Optional policy profile id.' },
                profile_name: { type: 'string', description: 'Optional policy profile name.' },
                project: { type: 'object', description: 'Project signals: name, type, frameworks, signals, package_scripts, config_files.' },
                workflow: { type: 'object', description: 'Workflow context: action, type, branch, environment.' },
                agent: { type: 'object', description: 'Agent context: id and role.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_workflow_gate',
        description: 'Pre-action risk gate for deploys, publishes, merges, DB migrations, key rotation, destructive commands, and production work. ' +
            'Returns allow, warn, review_required, or block plus prior lessons/playbooks.',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'What the agent is about to do.' },
                description: { type: 'string', description: 'Optional extra context for the action.' },
                riskTolerance: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Default high. Use medium/low for stricter gates.' },
                requiresApproval: { type: 'boolean', description: 'Set true when owner approval is required before proceeding.' },
                context: { type: 'object', description: 'Optional metadata. Do not include secrets or raw payloads.' },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_agent_performance',
        description: 'Get agent-facing fleet value metrics: avoided mistakes, reused winning decisions, failed patterns, token/time saved estimate, reliability score, and next improvements.',
        inputSchema: {
            type: 'object',
            properties: {
                period: { type: 'string', description: 'Time period: 7d (default), 14d, 30d, or day count up to 90.' },
                agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_fleet_lessons',
        description: 'Retrieve ranked reusable fleet lessons before similar work. Use before deploys, handoffs, migrations, audits, and repeated task types.',
        inputSchema: {
            type: 'object',
            properties: {
                query: { type: 'string', description: 'Search phrase for similar work.' },
                type: { type: 'string', enum: ['success', 'failure', 'deploy', 'incident', 'handoff', 'general'] },
                agentId: { type: 'string', description: 'Optional agent filter.' },
                limit: { type: 'number', description: 'Max lessons to return, default 10.' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_record_deployment_memory',
        description: 'Record deploy or incident memory: PR, commit, tests, smoke result, rollback plan, production health, and incident notes.',
        inputSchema: {
            type: 'object',
            properties: {
                release_id: { type: 'string' },
                pr_url: { type: 'string' },
                commit_sha: { type: 'string' },
                environment: { type: 'string' },
                status: { type: 'string', enum: ['planned', 'dry_run', 'deployed', 'verified', 'rolled_back', 'incident'] },
                tests: { type: 'array', items: { type: 'string' } },
                smoke_result: { type: 'string' },
                rollback_plan: { type: 'string' },
                prod_health: { type: 'string' },
                incident_summary: { type: 'string' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_create_handoff',
        description: 'Create a structured cross-agent handoff that Marrow can track for pending, stale, blocked, and complete states.',
        inputSchema: {
            type: 'object',
            properties: {
                to_agent_id: { type: 'string' },
                task: { type: 'string' },
                workflow_id: { type: 'string' },
                from_agent_id: { type: 'string' },
                checkpoint: { type: 'string' },
                stale_after_seconds: { type: 'number' },
            },
            required: ['to_agent_id', 'task'],
        },
    },
    {
        name: 'marrow_update_handoff',
        description: 'Update a Marrow handoff checkpoint/status when an agent accepts, blocks, completes, or needs review.',
        inputSchema: {
            type: 'object',
            properties: {
                handoffId: { type: 'string' },
                status: { type: 'string', enum: ['pending', 'accepted', 'working', 'blocked', 'complete', 'stale', 'cancelled'] },
                checkpoint: { type: 'string' },
                result_summary: { type: 'string' },
            },
            required: ['handoffId'],
        },
    },
    {
        name: 'marrow_handoff_status',
        description: 'Ask who is pending, stuck, stale, blocked, or complete across the agent fleet.',
        inputSchema: {
            type: 'object',
            properties: {
                status: { type: 'string' },
                agentId: { type: 'string' },
                limit: { type: 'number' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_session_end',
        description: 'Explicitly end the current session. Optionally auto-commits any open decision. ' +
            'Prevents orphaned decisions when an agent finishes a task.',
        inputSchema: {
            type: 'object',
            properties: {
                autoCommitOpen: { type: 'boolean', description: 'Whether to auto-commit any open decision (default: true)' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_accept_detected',
        description: 'Convert a detected decision pattern into an enforced workflow. ' +
            'The pattern ID comes from suggested_workflows in the orient() response.',
        inputSchema: {
            type: 'object',
            properties: {
                detectedId: { type: 'string', description: 'ID of the detected pattern to accept' },
            },
            required: ['detectedId'],
        },
    },
    {
        name: 'marrow_list_templates',
        description: 'Browse pre-built workflow templates. Filter by industry (insurance, healthcare, ecommerce, legal, saas, fintech, media, enterprise) or category. ' +
            'Use to discover available workflows before installing.',
        inputSchema: {
            type: 'object',
            properties: {
                industry: { type: 'string', description: 'Filter by industry (e.g., insurance, healthcare, saas)' },
                category: { type: 'string', description: 'Filter by category (e.g., claims, engineering, support)' },
                limit: { type: 'number', description: 'Max results (default: 20)' },
            },
            required: [],
        },
    },
    {
        name: 'marrow_install_template',
        description: 'Install a workflow template into your fleet as an active workflow. ' +
            'Use after marrow_list_templates to pick one.',
        inputSchema: {
            type: 'object',
            properties: {
                slug: { type: 'string', description: 'Template slug to install (e.g., code-review-deploy, claims-triage)' },
            },
            required: ['slug'],
        },
    },
];
exports.CORE_TOOL_NAMES = new Set([
    'marrow_agent_runtime',
    'marrow_think',
    'marrow_commit',
    'marrow_ask',
    'marrow_status',
    'marrow_auto',
    'marrow_handoff_status',
]);
exports.PRIMARY_TOOL_NAMES = new Set([
    'marrow_agent_runtime',
    'marrow_arbitrate',
    'marrow_coordinate',
    'marrow_replay_compare',
    'marrow_decision_brief',
    'marrow_think',
    'marrow_commit',
    'marrow_workflow_gate',
    'marrow_completion_contracts',
    'marrow_evaluate_completion_contract',
    'marrow_agent_status',
    'marrow_value_report',
    'marrow_buyer_proof',
    'marrow_governance_timeline',
    'marrow_decision_trace',
    'marrow_fleet_lessons',
    'marrow_model_usage',
]);
//# sourceMappingURL=tool-catalog.js.map