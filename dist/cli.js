#!/usr/bin/env node
"use strict";
/**
 * Marrow MCP stdio server — collective memory for Claude and MCP agents.
 * Exposes: marrow_orient (call first!), marrow_think, marrow_commit, marrow_status
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const readline = __importStar(require("readline"));
const index_1 = require("./index");
const API_KEY = process.env.MARROW_API_KEY || '';
const BASE_URL = process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai';
const SESSION_ID = process.env.MARROW_SESSION_ID || undefined;
const AUTO_ENROLL = process.env.MARROW_AUTO_ENROLL === 'true';
const AGENT_ID = process.env.MARROW_AGENT_ID || `${require('os').hostname()}-${Date.now().toString(36)}`;
if (!API_KEY) {
    process.stderr.write('Error: MARROW_API_KEY environment variable is required\n');
    process.exit(1);
}
// Auto-orient on startup — cache warnings, inject into EVERY marrow_think response
let cachedOrientWarnings = [];
let thinkCallCount = 0;
let orientCallCount = 0; // Track if this is first-time orient (for autoEnroll)
let initialized = false; // Track if initialize() has been called
const pendingDecisions = new Map();
const PENDING_TTL_MS = 30 * 60 * 1000; // 30 min TTL
function actionHash(action) {
    const normalized = action.toLowerCase().trim().replace(/\s+/g, ' ');
    // djb2 hash to prevent decision_id mismatches from normalization-only collisions
    let h = 5381;
    for (let i = 0; i < normalized.length; i++) {
        h = ((h << 5) + h) ^ normalized.charCodeAt(i);
        h = h >>> 0;
    }
    return h.toString(36) + '_' + normalized.slice(0, 32);
}
function cleanupPending() {
    const now = Date.now();
    for (const [key, val] of pendingDecisions) {
        if (now - val.timestamp > PENDING_TTL_MS) {
            pendingDecisions.delete(key);
        }
    }
}
function formatWarningActionably(w) {
    const pct = Math.round(w.failureRate * 100);
    return `⚠️ ${w.type} has ${pct}% failure rate — check what went wrong last time before proceeding`;
}
async function refreshOrientWarnings() {
    try {
        const r = await (0, index_1.marrowOrient)(API_KEY, BASE_URL, undefined, SESSION_ID);
        cachedOrientWarnings = r.warnings;
    }
    catch {
        // ignore
    }
}
// Initial orient
refreshOrientWarnings().then(() => {
    if (cachedOrientWarnings.some((w) => w.failureRate > 0.4)) {
        process.stderr.write(`[marrow] ⚠️ High failure rate detected on startup — call marrow_orient for details before acting\n`);
    }
});
// Auto-commit tracking for session close
let lastDecisionId = null;
let lastCommitted = false;
async function autoCommitOnClose() {
    if (lastDecisionId && !lastCommitted) {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);
            await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                decision_id: lastDecisionId,
                success: false,
                outcome: 'Session ended without explicit commit',
            }, SESSION_ID);
            clearTimeout(timeout);
        }
        catch {
            // ignore
        }
    }
}
process.on('SIGTERM', async () => {
    const forceExit = setTimeout(() => process.exit(0), 5000);
    forceExit.unref();
    await autoCommitOnClose();
    process.exit(0);
});
process.stdin.on('end', async () => {
    await autoCommitOnClose();
});
function send(response) {
    process.stdout.write(JSON.stringify(response) + '\n');
}
function success(id, result) {
    send({ jsonrpc: '2.0', id, result });
}
function error(id, code, message) {
    send({ jsonrpc: '2.0', id, error: { code, message } });
}
// Memory API functions
async function marrowListMemories(apiKey, baseUrl, params, sessionId) {
    const qs = new URLSearchParams();
    if (params?.status)
        qs.set('status', params.status);
    if (params?.query)
        qs.set('query', params.query);
    if (params?.limit)
        qs.set('limit', String(params.limit));
    if (params?.agentId)
        qs.set('agent_id', params.agentId);
    const res = await fetch(`${baseUrl}/v1/memories?${qs.toString()}`, {
        headers: {
            Authorization: `Bearer ${apiKey}`,
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
    });
    const json = await res.json();
    return json.data?.memories || [];
}
async function marrowGetMemory(apiKey, baseUrl, id, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
        headers: {
            Authorization: `Bearer ${apiKey}`,
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
    });
    const json = await res.json();
    return json.data?.memory || null;
}
async function marrowUpdateMemory(apiKey, baseUrl, id, patch, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
        method: 'PATCH',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify(patch),
    });
    const json = await res.json();
    return json.data.memory;
}
async function marrowDeleteMemory(apiKey, baseUrl, id, meta, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
        method: 'DELETE',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify(meta || {}),
    });
    const json = await res.json();
    return json.data.memory;
}
async function marrowMarkOutdated(apiKey, baseUrl, id, meta, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}/outdated`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify(meta || {}),
    });
    const json = await res.json();
    return json.data.memory;
}
async function marrowSupersedeMemory(apiKey, baseUrl, id, replacement, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}/supersede`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify(replacement),
    });
    const json = await res.json();
    return json.data;
}
async function marrowShareMemory(apiKey, baseUrl, id, agentIds, actor, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/${id}/share`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify({ agent_ids: agentIds, actor }),
    });
    const json = await res.json();
    return json.data.memory;
}
async function marrowExportMemories(apiKey, baseUrl, params, sessionId) {
    const qs = new URLSearchParams();
    if (params?.format)
        qs.set('format', params.format);
    if (params?.status)
        qs.set('status', params.status);
    if (params?.tags)
        qs.set('tags', params.tags);
    const res = await fetch(`${baseUrl}/v1/memories/export?${qs.toString()}`, {
        headers: {
            Authorization: `Bearer ${apiKey}`,
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
    });
    const json = await res.json();
    return json.data;
}
async function marrowImportMemories(apiKey, baseUrl, memories, mode, sessionId) {
    const res = await fetch(`${baseUrl}/v1/memories/import`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
        body: JSON.stringify({ memories, mode }),
    });
    const json = await res.json();
    return json.data;
}
async function marrowRetrieveMemories(apiKey, baseUrl, query, params, sessionId) {
    const qs = new URLSearchParams();
    qs.set('q', query);
    if (params?.limit)
        qs.set('limit', String(params.limit));
    if (params?.from)
        qs.set('from', params.from);
    if (params?.to)
        qs.set('to', params.to);
    if (params?.tags)
        qs.set('tags', params.tags);
    if (params?.source)
        qs.set('source', params.source);
    if (params?.status)
        qs.set('status', params.status);
    if (params?.shared !== undefined)
        qs.set('shared', String(params.shared));
    const res = await fetch(`${baseUrl}/v1/memories/retrieve?${qs.toString()}`, {
        headers: {
            Authorization: `Bearer ${apiKey}`,
            ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
        },
    });
    const json = await res.json();
    return json.data;
}
// Tool definitions
const TOOLS = [
    {
        name: 'marrow_orient',
        description: '⚡ CALL THIS FIRST — every session, before any other tool. ' +
            'Returns failure warnings from your history so you avoid known mistakes immediately. ' +
            'If shouldPause=true, review lessons before acting. ' +
            'orient() reads from the hive. think() writes to it. Both are required — this is what makes Marrow compound.',
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
        description: 'Log intent and get collective intelligence before acting. ' +
            'Call this before every meaningful action. ' +
            'Returns pattern insights, similar past decisions, failure detection, and a recommendedNext field — follow it. ' +
            'Pass previous_outcome to auto-commit the last decision and open a new one.',
        inputSchema: {
            type: 'object',
            properties: {
                action: {
                    type: 'string',
                    description: 'What the agent is about to do',
                },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
                },
                context: {
                    type: 'object',
                    description: 'Optional metadata about the current situation',
                },
                previous_decision_id: {
                    type: 'string',
                    description: 'decision_id from previous think() call — auto-commits that session',
                },
                previous_success: {
                    type: 'boolean',
                    description: 'Did the previous action succeed?',
                },
                previous_outcome: {
                    type: 'string',
                    description: 'What happened in the previous action (required if previous_decision_id provided)',
                },
                checkLoop: {
                    type: 'boolean',
                    description: 'Enable loop detection: warns if you are about to retry a failed approach. Recommended: true.',
                },
            },
            required: ['action'],
        },
    },
    {
        name: 'marrow_commit',
        description: 'Explicitly commit the result of an action to Marrow. ' +
            'Optional — marrow_think() auto-commits if you pass previous_outcome. ' +
            'Use when you need explicit control over commit timing.',
        inputSchema: {
            type: 'object',
            properties: {
                decision_id: {
                    type: 'string',
                    description: 'decision_id from the marrow_think call',
                },
                success: {
                    type: 'boolean',
                    description: 'Did the action succeed?',
                },
                outcome: {
                    type: 'string',
                    description: 'What happened — be specific, this trains the hive',
                },
                caused_by: {
                    type: 'string',
                    description: 'Optional: what caused this action',
                },
            },
            required: ['decision_id', 'success', 'outcome'],
        },
    },
    {
        name: 'marrow_run',
        description: 'Zero-ceremony memory logging. Single call handles orient → think → commit automatically. ' +
            'Use this instead of chaining marrow_think + marrow_commit when you want Marrow to just work without managing the loop yourself.',
        inputSchema: {
            type: 'object',
            properties: {
                description: {
                    type: 'string',
                    description: 'What the agent did',
                },
                success: {
                    type: 'boolean',
                    description: 'Whether it succeeded',
                },
                outcome: {
                    type: 'string',
                    description: 'One-line summary of what happened',
                },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
                },
            },
            required: ['description', 'success', 'outcome'],
        },
    },
    {
        name: 'marrow_auto',
        description: 'Zero-friction Marrow logging. One call for any action — Marrow handles everything in the background without blocking. ' +
            'Pass what you are about to do. Optionally pass outcome if already done. ' +
            'Use for ANY action: deploys, file writes, API calls, external sends. ' +
            'If you only have time for one call: pass action + outcome + success together — done in one shot.',
        inputSchema: {
            type: 'object',
            properties: {
                action: {
                    type: 'string',
                    description: 'What you are about to do or just did',
                },
                outcome: {
                    type: 'string',
                    description: 'What happened (if already done). Omit to log intent only.',
                },
                success: {
                    type: 'boolean',
                    description: 'Did it succeed (default: true)',
                },
                type: {
                    type: 'string',
                    enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                    description: 'Type of action (default: general)',
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
                query: {
                    type: 'string',
                    description: 'Plain English question about your decision history',
                },
            },
            required: ['query'],
        },
    },
    {
        name: 'marrow_status',
        description: 'Check Marrow platform health and status.',
        inputSchema: {
            type: 'object',
            properties: {},
            required: [],
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
        inputSchema: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Memory ID' },
            },
            required: ['id'],
        },
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
                action: {
                    type: 'string',
                    enum: ['register', 'list', 'get', 'update', 'start', 'advance', 'instances'],
                    description: 'Workflow action to perform',
                },
                workflowId: { type: 'string', description: 'Workflow ID (required for get/start/advance/instances)' },
                instanceId: { type: 'string', description: 'Instance ID (required for advance)' },
                name: { type: 'string', description: 'Workflow name (for register)' },
                description: { type: 'string', description: 'Workflow description (for register/update)' },
                steps: {
                    type: 'array',
                    description: 'Step definitions (for register)',
                    items: {
                        type: 'object',
                        properties: {
                            step: { type: 'number', description: 'Step order (1, 2, 3...)' },
                            agent_role: { type: 'string', description: 'Expected agent role (e.g., "builder", "auditor")' },
                            action_type: { type: 'string', description: 'Action type (e.g., "build", "audit", "patch")' },
                            description: { type: 'string', description: 'Step description' },
                        },
                        required: ['step', 'description'],
                    },
                },
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
];
// Request handler
async function handleRequest(req) {
    const { id, method, params } = req;
    try {
        if (method === 'initialize') {
            initialized = true;
            success(id, {
                protocolVersion: '2024-11-05',
                capabilities: { tools: {}, prompts: {} },
                serverInfo: { name: 'marrow', version: '2.8.0' },
            });
            // Auto-enroll: emit enrollment notification on connection
            if (AUTO_ENROLL) {
                send({
                    jsonrpc: '2.0',
                    method: 'notifications/message',
                    params: {
                        level: 'info',
                        logger: 'marrow',
                        data: {
                            type: 'auto_enroll',
                            message: 'Marrow auto-enroll active. Call marrow_orient FIRST, then marrow_think before acting, marrow_commit after. Or use marrow_auto / marrow_run for one-call logging.',
                            agentId: AGENT_ID || 'auto',
                        },
                    },
                });
            }
            return;
        }
        if (method === 'prompts/list') {
            // Auto-enroll: only expose marrow-always-on prompt when MARROW_AUTO_ENROLL is set
            if (AUTO_ENROLL) {
                success(id, {
                    prompts: [
                        {
                            name: 'marrow-always-on',
                            description: 'Always-on Marrow memory loop. Instructs the agent to orient at session start, log intent before meaningful actions, and commit outcomes after completion. Install once — works automatically.',
                            arguments: [],
                        },
                    ],
                });
            }
            else {
                success(id, { prompts: [] });
            }
            return;
        }
        if (method === 'prompts/get') {
            const promptName = params?.name;
            // Auto-enroll gate: only serve marrow-always-on when enabled
            if (promptName !== 'marrow-always-on' || !AUTO_ENROLL) {
                error(id, -32602, 'Unknown prompt');
                return;
            }
            success(id, {
                description: 'Always-on Marrow memory loop — automatic, zero-config',
                messages: [
                    {
                        role: 'user',
                        content: {
                            type: 'text',
                            text: `You have Marrow — a memory layer that tells you what went wrong last time before you do it again.

## PRIMARY: Use marrow_auto for everything

One tool. Two calls max. Zero loop management.

The minimum loop:
1. Before any external action: \`marrow_auto({ action: "...what you are about to do" })\`
2. After the action: \`marrow_auto({ action: "...", outcome: "...what happened", success: true/false })\`

If you only have time for one call: \`marrow_auto({ action: "did X", outcome: "result", success: true })\` — that's the whole loop.

You never need think + commit separately. \`marrow_auto\` handles everything.

All Marrow API calls run in the background — \`marrow_auto\` returns instantly with cached warnings so you never wait.

## Query the hive

Use marrow_ask to query your decision history in plain English:
- "what keeps breaking our deploys?"
- "what's our failure rate on security tasks?"
- "what worked last time we published?"

## Advanced mode: fine-grained control

For cases where you need explicit control over the orient → think → act → commit loop:

1. **Session start:** Call marrow_orient FIRST. It surfaces failure warnings so you avoid known mistakes.
2. **Before acting:** Call marrow_think with what you're about to do. Returns pattern insights and recommendedNext — follow it.
3. **After acting:** Call marrow_commit with what happened.
4. **Shortcut:** marrow_run handles orient → think → commit in a single awaited call.

Most agents never need advanced mode. \`marrow_auto\` covers 99% of cases.

## Why you must not skip this

If you skip logging, the hive can't protect you or future agents from this mistake.
Every decision you log compounds. Failure rates drop. Patterns emerge. The next session starts smarter.
Marrow tells you what went wrong last time before you do it again. But only if you logged it.

This is not optional overhead — it's how you stop repeating the same failures.`,
                        },
                    },
                ],
            });
            return;
        }
        if (method === 'tools/list') {
            success(id, { tools: TOOLS });
            return;
        }
        if (method === 'tools/call') {
            const toolName = params?.name;
            const args = (params?.arguments || {});
            if (toolName === 'marrow_orient') {
                orientCallCount++;
                const result = await (0, index_1.marrowOrient)(API_KEY, BASE_URL, { taskType: args.taskType, autoWarn: args.autoWarn ?? true }, SESSION_ID);
                // Auto-enroll: on first orient call, prepend enrollment instructions
                if (AUTO_ENROLL && orientCallCount === 1) {
                    const enrollmentText = `\n\n📋 **Marrow Auto-Enroll Active**\n\n` +
                        `You have Marrow — a collective memory that tells you what went wrong last time before you do it again.\n\n` +
                        `## How it works (2 tools max):\n\n` +
                        `1. **Session start:** Call marrow_orient FIRST. You just did — it surfaces failure warnings.\n` +
                        `2. **Before any action:** Call marrow_think({ action: "..." }) — returns pattern insights + recommendedNext.\n` +
                        `3. **After acting:** Call marrow_commit({ decision_id, success, outcome }) — or pass previous_outcome to auto-commit.\n\n` +
                        `## Quick mode (one tool):\n` +
                        `- marrow_run({ description, success, outcome }) — handles orient → think → commit in one call.\n` +
                        `- marrow_auto({ action, outcome?, success? }) — fire-and-forget background logging.\n\n` +
                        `## Why you must not skip this:\n` +
                        `Every decision you log compounds. Failure rates drop. The next session starts smarter.\n` +
                        `Marrow tells you what went wrong last time — but only if you logged it.\n`;
                    const orientText = JSON.stringify(result, null, 2);
                    success(id, {
                        content: [{ type: 'text', text: enrollmentText + orientText }],
                    });
                }
                else {
                    success(id, {
                        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    });
                }
                return;
            }
            if (toolName === 'marrow_think') {
                const result = await (0, index_1.marrowThink)(API_KEY, BASE_URL, {
                    action: args.action,
                    type: args.type,
                    context: args.context,
                    previous_decision_id: args.previous_decision_id,
                    previous_success: args.previous_success,
                    previous_outcome: args.previous_outcome,
                    checkLoop: args.checkLoop ?? true,
                }, SESSION_ID);
                // Refresh orient warnings every 5th think call
                thinkCallCount++;
                if (thinkCallCount % 5 === 0) {
                    refreshOrientWarnings();
                }
                // Inject cached orient warnings into intelligence.insights
                if (cachedOrientWarnings.length > 0) {
                    const existingInsights = result.intelligence?.insights || [];
                    result.intelligence.insights = [
                        ...cachedOrientWarnings.map((w) => ({
                            type: 'failure_pattern',
                            summary: w.message,
                            action: `Review past ${w.type} failures before proceeding`,
                            severity: (w.failureRate > 0.4 ? 'critical' : 'warning'),
                            count: 0,
                        })),
                        ...existingInsights,
                    ];
                }
                // Track for auto-commit
                lastDecisionId = result.decision_id;
                lastCommitted = false;
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_commit') {
                const result = await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                    decision_id: args.decision_id,
                    success: args.success,
                    outcome: args.outcome,
                    caused_by: args.caused_by,
                }, SESSION_ID);
                lastCommitted = true;
                lastDecisionId = null;
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_run') {
                // marrow_run = orient + think + commit in one call
                await (0, index_1.marrowOrient)(API_KEY, BASE_URL, undefined, SESSION_ID);
                const thinkResult = await (0, index_1.marrowThink)(API_KEY, BASE_URL, {
                    action: args.description,
                    type: args.type || 'general',
                }, SESSION_ID);
                const commitResult = await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                    decision_id: thinkResult.decision_id,
                    success: args.success ?? true,
                    outcome: args.outcome,
                }, SESSION_ID);
                success(id, {
                    content: [
                        {
                            type: 'text',
                            text: JSON.stringify({ think: thinkResult, commit: commitResult }, null, 2),
                        },
                    ],
                });
                return;
            }
            if (toolName === 'marrow_auto') {
                // marrow_auto = fire-and-forget background logging
                // Return immediately with cached orient warnings, API calls happen in background
                const action = args.action;
                const outcome = args.outcome;
                const outcomeSuccess = args.success ?? true;
                const type = args.type || 'general';
                // Return cached warnings immediately
                const response = {
                    action,
                    outcome: outcome || 'pending',
                    warnings: cachedOrientWarnings.map(formatWarningActionably),
                };
                // Fire-and-forget the actual API calls
                (async () => {
                    try {
                        if (!outcome) {
                            // Intent only
                            await (0, index_1.marrowThink)(API_KEY, BASE_URL, { action, type }, SESSION_ID);
                        }
                        else {
                            // Full loop
                            const thinkResult = await (0, index_1.marrowThink)(API_KEY, BASE_URL, { action, type }, SESSION_ID);
                            await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                                decision_id: thinkResult.decision_id,
                                success: outcomeSuccess,
                                outcome,
                            }, SESSION_ID);
                        }
                    }
                    catch (err) {
                        // Log to stderr so agent can see it in logs
                        const msg = err instanceof Error ? err.message : String(err);
                        process.stderr.write(`[marrow] marrow_auto failed: ${msg}\n`);
                    }
                })();
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_ask') {
                const result = await (0, index_1.marrowAsk)(API_KEY, BASE_URL, { query: args.query }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_status') {
                const result = await (0, index_1.marrowStatus)(API_KEY, BASE_URL, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            // Memory control tools
            if (toolName === 'marrow_list_memories') {
                const result = await marrowListMemories(API_KEY, BASE_URL, {
                    status: args.status,
                    query: args.query,
                    limit: args.limit,
                    agentId: args.agentId,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_get_memory') {
                const result = await marrowGetMemory(API_KEY, BASE_URL, args.id, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_update_memory') {
                const result = await marrowUpdateMemory(API_KEY, BASE_URL, args.id, {
                    text: args.text,
                    source: args.source,
                    tags: args.tags,
                    actor: args.actor,
                    note: args.note,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_delete_memory') {
                const result = await marrowDeleteMemory(API_KEY, BASE_URL, args.id, { actor: args.actor, note: args.note }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_mark_outdated') {
                const result = await marrowMarkOutdated(API_KEY, BASE_URL, args.id, { actor: args.actor, note: args.note }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_supersede_memory') {
                const result = await marrowSupersedeMemory(API_KEY, BASE_URL, args.id, {
                    text: args.text,
                    source: args.source,
                    tags: args.tags,
                    actor: args.actor,
                    note: args.note,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_share_memory') {
                const result = await marrowShareMemory(API_KEY, BASE_URL, args.id, args.agentIds || [], args.actor, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_export_memories') {
                const result = await marrowExportMemories(API_KEY, BASE_URL, {
                    format: args.format,
                    status: args.status,
                    tags: args.tags,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_import_memories') {
                const result = await marrowImportMemories(API_KEY, BASE_URL, args.memories || [], args.mode || 'merge', SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_retrieve_memories') {
                const result = await marrowRetrieveMemories(API_KEY, BASE_URL, args.query, {
                    limit: args.limit,
                    from: args.from,
                    to: args.to,
                    tags: args.tags,
                    source: args.source,
                    status: args.status,
                    shared: args.shared,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            if (toolName === 'marrow_workflow') {
                const result = await (0, index_1.marrowWorkflow)(API_KEY, BASE_URL, {
                    action: args.action,
                    workflowId: args.workflowId,
                    instanceId: args.instanceId,
                    name: args.name,
                    description: args.description,
                    steps: args.steps,
                    tags: args.tags,
                    agentId: args.agentId,
                    context: args.context,
                    inputs: args.inputs,
                    stepCompleted: args.stepCompleted,
                    outcome: args.outcome,
                    nextAgentId: args.nextAgentId,
                    contextUpdate: args.contextUpdate,
                    status: args.status,
                }, SESSION_ID);
                success(id, {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                });
                return;
            }
            error(id, -32601, `Method not found: ${toolName}`);
            return;
        }
        error(id, -32601, `Method not found: ${method}`);
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        error(id, -32000, message);
    }
}
// MCP stdio loop
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});
rl.on('line', async (line) => {
    try {
        const msg = JSON.parse(line);
        await handleRequest(msg);
    }
    catch (err) {
        process.stderr.write(`[marrow] Parse error: ${err}\n`);
    }
});
//# sourceMappingURL=cli.js.map