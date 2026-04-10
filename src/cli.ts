#!/usr/bin/env node
/**
 * Marrow MCP stdio server — collective memory for Claude and MCP agents.
 * Exposes: marrow_orient (call first!), marrow_think, marrow_commit, marrow_status
 *
 * Usage:
 *   npx @getmarrow/mcp                          (reads MARROW_API_KEY from env)
 *   npx @getmarrow/mcp --key mrw_abc123          (pass key via CLI flag)
 *   MARROW_API_KEY=mrw_abc123 npx @getmarrow/mcp
 */

import {
  marrowThink,
  marrowCommit,
  marrowOrient,
  marrowStatus,
  marrowAgentPatterns,
  marrowAsk,
  marrowWorkflow,
} from './index';
import type { ThinkResult, OrientResult, MarrowMemory } from './types';

// Parse CLI args for --key flag
function parseArgs(): { apiKey?: string } {
  const args = process.argv.slice(2);
  const result: { apiKey?: string } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--key' && i + 1 < args.length) {
      result.apiKey = args[i + 1];
      i++;
    }
  }
  return result;
}

const cliArgs = parseArgs();
const API_KEY = cliArgs.apiKey || process.env.MARROW_API_KEY || '';
const BASE_URL = process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai';
const SESSION_ID = process.env.MARROW_SESSION_ID || undefined;
const AUTO_ENROLL = process.env.MARROW_AUTO_ENROLL === 'true';
const AGENT_ID = process.env.MARROW_AGENT_ID || `${require('os').hostname()}-${Date.now().toString(36)}`;

if (!API_KEY) {
  process.stderr.write('Error: MARROW_API_KEY environment variable is required\n');
  process.stderr.write('Usage: MARROW_API_KEY=mrw_yourkey npx @getmarrow/mcp\n');
  process.stderr.write('   or: npx @getmarrow/mcp --key mrw_yourkey\n');
  process.exit(1);
}

// Auto-orient on startup — cache warnings, inject into EVERY marrow_think response
let cachedOrientWarnings: Array<{ type: string; failureRate: number; message: string }> = [];
let thinkCallCount = 0;
let orientCallCount = 0; // Track if this is first-time orient (for autoEnroll)
let initialized = false; // Track if initialize() has been called

// Pending decision map for marrow_auto (action hash → decision_id)
interface PendingDecision {
  decision_id: string;
  timestamp: number;
}
const pendingDecisions = new Map<string, PendingDecision>();
const PENDING_TTL_MS = 30 * 60 * 1000; // 30 min TTL

function actionHash(action: string): string {
  const normalized = action.toLowerCase().trim().replace(/\s+/g, ' ');
  // djb2 hash to prevent decision_id mismatches from normalization-only collisions
  let h = 5381;
  for (let i = 0; i < normalized.length; i++) {
    h = ((h << 5) + h) ^ normalized.charCodeAt(i);
    h = h >>> 0;
  }
  return h.toString(36) + '_' + normalized.slice(0, 32);
}

function cleanupPending(): void {
  const now = Date.now();
  for (const [key, val] of pendingDecisions) {
    if (now - val.timestamp > PENDING_TTL_MS) {
      pendingDecisions.delete(key);
    }
  }
}

function formatWarningActionably(w: { type: string; failureRate: number; message: string }): string {
  const pct = Math.round(w.failureRate * 100);
  return `⚠️ ${w.type} has ${pct}% failure rate — check what went wrong last time before proceeding`;
}

async function refreshOrientWarnings(): Promise<void> {
  try {
    const r = await marrowOrient(API_KEY, BASE_URL, undefined, SESSION_ID);
    cachedOrientWarnings = r.warnings;
  } catch {
    // ignore
  }
}

// Initial orient
refreshOrientWarnings().then(() => {
  if (cachedOrientWarnings.some((w) => w.failureRate > 0.4)) {
    process.stderr.write(
      `[marrow] ⚠️ High failure rate detected on startup — call marrow_orient for details before acting\n`
    );
  }
});

// Auto-commit tracking for session close
let lastDecisionId: string | null = null;
let lastCommitted = false;

async function autoCommitOnClose(): Promise<void> {
  if (lastDecisionId && !lastCommitted) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      await marrowCommit(
        API_KEY,
        BASE_URL,
        {
          decision_id: lastDecisionId,
          success: false,
          outcome: 'Session ended without explicit commit',
        },
        SESSION_ID
      );
      clearTimeout(timeout);
    } catch {
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

function send(response: unknown): void {
  process.stdout.write(JSON.stringify(response) + '\n');
}

function success(id: string | number, result: unknown): void {
  send({ jsonrpc: '2.0', id, result });
}

function error(id: string | number, code: number, message: string): void {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

// Memory API functions
async function marrowListMemories(
  apiKey: string,
  baseUrl: string,
  params?: { status?: string; query?: string; limit?: number; agentId?: string },
  sessionId?: string
): Promise<MarrowMemory[]> {
  const qs = new URLSearchParams();
  if (params?.status) qs.set('status', params.status);
  if (params?.query) qs.set('query', params.query);
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.agentId) qs.set('agent_id', params.agentId);

  const res = await fetch(`${baseUrl}/v1/memories?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json: any = await res.json();
  return json.data?.memories || [];
}

async function marrowGetMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  sessionId?: string
): Promise<MarrowMemory | null> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json: any = await res.json();
  return json.data?.memory || null;
}

async function marrowUpdateMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  patch: { text?: string; source?: string | null; tags?: string[]; actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(patch),
  });
  const json: any = await res.json();
  return json.data.memory;
}

async function marrowDeleteMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  meta?: { actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(meta || {}),
  });
  const json: any = await res.json();
  return json.data.memory;
}

async function marrowMarkOutdated(
  apiKey: string,
  baseUrl: string,
  id: string,
  meta?: { actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}/outdated`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(meta || {}),
  });
  const json: any = await res.json();
  return json.data.memory;
}

async function marrowSupersedeMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  replacement: { text: string; source?: string; tags?: string[]; actor?: string; note?: string },
  sessionId?: string
): Promise<{ old: MarrowMemory; replacement: MarrowMemory }> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}/supersede`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(replacement),
  });
  const json: any = await res.json();
  return json.data;
}

async function marrowShareMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  agentIds: string[],
  actor?: string,
  sessionId?: string
): Promise<MarrowMemory> {
  const res = await fetch(`${baseUrl}/v1/memories/${id}/share`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify({ agent_ids: agentIds, actor }),
  });
  const json: any = await res.json();
  return json.data.memory;
}

async function marrowExportMemories(
  apiKey: string,
  baseUrl: string,
  params?: { format?: string; status?: string; tags?: string },
  sessionId?: string
): Promise<{ exported_at: string; account_id: string; count: number; memories: MarrowMemory[] }> {
  const qs = new URLSearchParams();
  if (params?.format) qs.set('format', params.format);
  if (params?.status) qs.set('status', params.status);
  if (params?.tags) qs.set('tags', params.tags);

  const res = await fetch(`${baseUrl}/v1/memories/export?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json: any = await res.json();
  return json.data;
}

async function marrowImportMemories(
  apiKey: string,
  baseUrl: string,
  memories: Array<{ text: string; source?: string; tags?: string[] }>,
  mode: 'merge' | 'replace',
  sessionId?: string
): Promise<{ imported: number; skipped: number; errors: string[] }> {
  const res = await fetch(`${baseUrl}/v1/memories/import`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify({ memories, mode }),
  });
  const json: any = await res.json();
  return json.data;
}

async function marrowRetrieveMemories(
  apiKey: string,
  baseUrl: string,
  query: string,
  params?: { limit?: number; from?: string; to?: string; tags?: string; source?: string; status?: string; shared?: boolean },
  sessionId?: string
): Promise<{ memories: MarrowMemory[]; query: string; count: number }> {
  const qs = new URLSearchParams();
  qs.set('q', query);
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.from) qs.set('from', params.from);
  if (params?.to) qs.set('to', params.to);
  if (params?.tags) qs.set('tags', params.tags);
  if (params?.source) qs.set('source', params.source);
  if (params?.status) qs.set('status', params.status);
  if (params?.shared !== undefined) qs.set('shared', String(params.shared));

  const res = await fetch(`${baseUrl}/v1/memories/retrieve?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json: any = await res.json();
  return json.data;
}

// Tool definitions
const TOOLS = [
  {
    name: 'marrow_orient',
    description:
      '⚡ CALL THIS FIRST — every session, before any other tool. ' +
      'Returns failure warnings from your history so you avoid known mistakes immediately. ' +
      'If shouldPause=true, review lessons before acting. ' +
      'orient() reads from the hive. think() writes to it. Both are required — this is what makes Marrow compound.',
    inputSchema: {
      type: 'object',
      properties: {
        taskType: {
          type: 'string',
          enum: ['implementation', 'security', 'architecture', 'process', 'general'],
          description:
            'Optional: filter warnings to a specific task type you are about to perform',
        },
        autoWarn: {
          type: 'boolean',
          description:
            'Enable active intervention: scans recent failures, returns HIGH/MEDIUM/LOW severity warnings with recommendations. Recommended: true.',
        },
      },
      required: [],
    },
  },
  {
    name: 'marrow_think',
    description:
      'Log intent and get collective intelligence before acting. ' +
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
          description:
            'What happened in the previous action (required if previous_decision_id provided)',
        },
        checkLoop: {
          type: 'boolean',
          description:
            'Enable loop detection: warns if you are about to retry a failed approach. Recommended: true.',
        },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_commit',
    description:
      'Explicitly commit the result of an action to Marrow. ' +
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
    description:
      'Zero-ceremony memory logging. Single call handles orient → think → commit automatically. ' +
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
    description:
      'Zero-friction Marrow logging. One call for any action — Marrow handles everything in the background without blocking. ' +
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
    description:
      'Query the collective hive in plain English. ' +
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
    description:
      'Interact with Marrow Workflow Registry. Register, start, and advance multi-step workflows. ' +
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
async function handleRequest(req: {
  id: string | number;
  method: string;
  params?: { name?: string; arguments?: Record<string, unknown> };
}): Promise<void> {
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
              description:
                'Always-on Marrow memory loop. Instructs the agent to orient at session start, log intent before meaningful actions, and commit outcomes after completion. Install once — works automatically.',
              arguments: [],
            },
          ],
        });
      } else {
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
      const args = (params?.arguments || {}) as Record<string, unknown>;

      if (toolName === 'marrow_orient') {
        orientCallCount++;
        const result = await marrowOrient(
          API_KEY,
          BASE_URL,
          { taskType: args.taskType as string, autoWarn: (args.autoWarn as boolean) ?? true },
          SESSION_ID
        );

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
        } else {
          success(id, {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          });
        }
        return;
      }

      if (toolName === 'marrow_think') {
        const result = await marrowThink(
          API_KEY,
          BASE_URL,
          {
            action: args.action as string,
            type: args.type as string,
            context: args.context as Record<string, unknown>,
            previous_decision_id: args.previous_decision_id as string,
            previous_success: args.previous_success as boolean,
            previous_outcome: args.previous_outcome as string,
            checkLoop: (args.checkLoop as boolean) ?? true,
          },
          SESSION_ID
        );

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
              type: 'failure_pattern' as const,
              summary: w.message,
              action: `Review past ${w.type} failures before proceeding`,
              severity: (w.failureRate > 0.4 ? 'critical' : 'warning') as
                | 'critical'
                | 'warning',
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
        const result = await marrowCommit(
          API_KEY,
          BASE_URL,
          {
            decision_id: args.decision_id as string,
            success: args.success as boolean,
            outcome: args.outcome as string,
            caused_by: args.caused_by as string,
          },
          SESSION_ID
        );
        lastCommitted = true;
        lastDecisionId = null;
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_run') {
        // marrow_run = orient + think + commit in one call
        await marrowOrient(API_KEY, BASE_URL, undefined, SESSION_ID);
        const thinkResult = await marrowThink(
          API_KEY,
          BASE_URL,
          {
            action: args.description as string,
            type: (args.type as string) || 'general',
          },
          SESSION_ID
        );
        const commitResult = await marrowCommit(
          API_KEY,
          BASE_URL,
          {
            decision_id: thinkResult.decision_id,
            success: (args.success as boolean) ?? true,
            outcome: args.outcome as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                { think: thinkResult, commit: commitResult },
                null,
                2
              ),
            },
          ],
        });
        return;
      }

      if (toolName === 'marrow_auto') {
        // marrow_auto = fire-and-forget background logging
        // Return immediately with cached orient warnings, API calls happen in background
        const action = args.action as string;
        const outcome = args.outcome as string | undefined;
        const outcomeSuccess = (args.success as boolean) ?? true;
        const type = (args.type as string) || 'general';

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
              await marrowThink(
                API_KEY,
                BASE_URL,
                { action, type },
                SESSION_ID
              );
            } else {
              // Full loop
              const thinkResult = await marrowThink(
                API_KEY,
                BASE_URL,
                { action, type },
                SESSION_ID
              );
              await marrowCommit(
                API_KEY,
                BASE_URL,
                {
                  decision_id: thinkResult.decision_id,
                  success: outcomeSuccess,
                  outcome,
                },
                SESSION_ID
              );
            }
          } catch (err) {
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
        const result = await marrowAsk(
          API_KEY,
          BASE_URL,
          { query: args.query as string },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_status') {
        const result = await marrowStatus(API_KEY, BASE_URL, SESSION_ID);
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      // Memory control tools
      if (toolName === 'marrow_list_memories') {
        const result = await marrowListMemories(
          API_KEY,
          BASE_URL,
          {
            status: args.status as string,
            query: args.query as string,
            limit: args.limit as number,
            agentId: args.agentId as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_get_memory') {
        const result = await marrowGetMemory(
          API_KEY,
          BASE_URL,
          args.id as string,
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_update_memory') {
        const result = await marrowUpdateMemory(
          API_KEY,
          BASE_URL,
          args.id as string,
          {
            text: args.text as string,
            source: args.source as string | null,
            tags: args.tags as string[],
            actor: args.actor as string,
            note: args.note as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_delete_memory') {
        const result = await marrowDeleteMemory(
          API_KEY,
          BASE_URL,
          args.id as string,
          { actor: args.actor as string, note: args.note as string },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_mark_outdated') {
        const result = await marrowMarkOutdated(
          API_KEY,
          BASE_URL,
          args.id as string,
          { actor: args.actor as string, note: args.note as string },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_supersede_memory') {
        const result = await marrowSupersedeMemory(
          API_KEY,
          BASE_URL,
          args.id as string,
          {
            text: args.text as string,
            source: args.source as string,
            tags: args.tags as string[],
            actor: args.actor as string,
            note: args.note as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_share_memory') {
        const result = await marrowShareMemory(
          API_KEY,
          BASE_URL,
          args.id as string,
          (args.agentIds as string[]) || [],
          args.actor as string,
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_export_memories') {
        const result = await marrowExportMemories(
          API_KEY,
          BASE_URL,
          {
            format: args.format as string,
            status: args.status as string,
            tags: args.tags as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_import_memories') {
        const result = await marrowImportMemories(
          API_KEY,
          BASE_URL,
          (args.memories as Array<{ text: string; source?: string; tags?: string[] }>) || [],
          (args.mode as 'merge' | 'replace') || 'merge',
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_retrieve_memories') {
        const result = await marrowRetrieveMemories(
          API_KEY,
          BASE_URL,
          args.query as string,
          {
            limit: args.limit as number,
            from: args.from as string,
            to: args.to as string,
            tags: args.tags as string,
            source: args.source as string,
            status: args.status as string,
            shared: args.shared as boolean,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_workflow') {
        const result = await marrowWorkflow(
          API_KEY,
          BASE_URL,
          {
            action: args.action as any,
            workflowId: args.workflowId as string,
            instanceId: args.instanceId as string,
            name: args.name as string,
            description: args.description as string,
            steps: args.steps as any,
            tags: args.tags as string[],
            agentId: args.agentId as string,
            context: args.context as Record<string, unknown>,
            inputs: args.inputs as Record<string, unknown>,
            stepCompleted: args.stepCompleted as number,
            outcome: args.outcome as string,
            nextAgentId: args.nextAgentId as string,
            contextUpdate: args.contextUpdate as Record<string, unknown>,
            status: args.status as string,
          },
          SESSION_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      error(id, -32601, `Method not found: ${toolName}`);
      return;
    }

    error(id, -32601, `Method not found: ${method}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    error(id, -32000, message);
  }
}

// MCP stdio loop — raw stdin, no readline (readline writes prompts to stdout which breaks MCP)
let buffer = '';

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  buffer += chunk;
  const lines = buffer.split('\n');
  buffer = lines.pop() || ''; // keep incomplete line in buffer
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    handleRequest(JSON.parse(trimmed)).catch((err) => {
      process.stderr.write(`[marrow] Handler error: ${err}\n`);
    });
  }
});

process.stdin.on('end', async () => {
  // Process any remaining buffered line
  if (buffer.trim()) {
    try {
      await handleRequest(JSON.parse(buffer.trim()));
    } catch (err) {
      process.stderr.write(`[marrow] Parse error on remaining: ${err}\n`);
    }
  }
  await autoCommitOnClose();
  process.exit(0);
});

process.stdin.on('error', (err) => {
  process.stderr.write(`[marrow] stdin error: ${err}\n`);
  process.exit(1);
});
