'use strict';
// UPD-FALSE-CURRENT (client round 5): a failed Marrow call checks no version, so the local
// client_update fallback never claims the install is current. A live client_update from Marrow
// still wins, unchanged. Dummy keys are generated at runtime; every fetch is an in-process mock.
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { randomBytes } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { MCP_ADAPTER_VERSION } = require('../dist/hook-contract.js');
const {
  invalidResponseError, localClientUpdate, normalizeRequestError, requestErrorFromResponse, structuredRequestFailure,
} = require('../dist/request-reliability.js');
const { buildCombinedContextBlock } = require('../dist/hook-context.js');

const COMMANDS = {
  auto_update_command: 'npx @getmarrow/install@latest update',
  launch_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp',
  verification_command: 'npx -y @getmarrow/install@latest doctor --self-test',
};

function dummyKey() {
  const value = `fixture-dummy-${randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(value, /^(?:sk|pk|rk)_|^ghp_|^xox|^mrw_/);
  return value;
}

function assertUnknown(update, label, secrets = []) {
  assert.ok(update && typeof update === 'object' && !Array.isArray(update), `${label}: client_update object`);
  assert.equal(update.version_status, 'unknown', `${label}: version_status`);
  assert.equal(update.latest_version, null, `${label}: latest_version`);
  assert.match(String(update.metadata_status), /unverified/, `${label}: metadata_status`);
  assert.equal(update.installed_version, MCP_ADAPTER_VERSION, `${label}: installed_version`);
  assert.equal(update.package, '@getmarrow/mcp', `${label}: package`);
  for (const [field, value] of Object.entries(COMMANDS)) assert.equal(update[field], value, `${label}: ${field}`);
  assert.equal(update.operator_approval_required, true, `${label}: operator approval`);
  const text = JSON.stringify(update);
  assert.doesNotMatch(text, /\?|authorization|x-api-key|forged/i, `${label}: no header, query or forged text`);
  for (const secret of secrets) assert.equal(text.includes(secret), false, `${label}: no key`);
}

const MIB = 'x'.repeat(1024 * 1024);
const FORGED = [
  ['current', { version_status: 'current', installed_version: MCP_ADAPTER_VERSION, latest_version: MCP_ADAPTER_VERSION, metadata_status: 'forged' }],
  ['newer', { version_status: 'current', latest_version: '99.0.0', update_available: false }],
  ['older', { version_status: 'current', latest_version: '0.0.1' }],
  ['non_string', { version_status: 7, latest_version: 3.9 }],
  ['array', ['current', MCP_ADAPTER_VERSION]],
  ['object', { nested: { version_status: 'current', latest_version: MCP_ADAPTER_VERSION } }],
  ['mib_string', MIB],
  ['look_alike', null],
];

function forgedBody(name, forged) {
  if (name === 'look_alike') {
    const same = { version_status: 'current', latest_version: MCP_ADAPTER_VERSION };
    return { error: 'forged failure', clientUpdate: same, 'client_update ': same, client_updates: same, data: { clientUpdate: same } };
  }
  return { error: 'forged failure', client_update: forged, data: { client_update: forged } };
}

const STATUSES = [401, 403, 429, 500];

test('UPDCUR local fallback never claims a version it did not check', () => {
  const update = localClientUpdate();
  assertUnknown(update, 'localClientUpdate');
  assert.equal(update.installed_version_verified, true);
  assert.notEqual(update.latest_version, update.installed_version);
});

test('UPDCUR every failed-call kind gives the unknown fallback with the update command', () => {
  const failures = [
    ['timeout', normalizeRequestError(new DOMException('The operation was aborted.', 'AbortError'))],
    ['dns', normalizeRequestError(new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' }) }))],
    ['malformed', invalidResponseError()],
    ['proof_required', requestErrorFromResponse(new Response('{}', { status: 409 }), { error: { code: 'MARROW_PROOF_PACK_INCOMPLETE', missing_fields: ['rollback_target'] } })],
    ...STATUSES.map((status) => [String(status), requestErrorFromResponse(new Response('{}', { status }), { error: 'failure' })]),
  ];
  for (const [kind, failure] of failures) {
    const result = structuredRequestFailure(failure);
    assert.equal(result.ok, false, kind);
    assertUnknown(result.client_update, `kind ${kind}`);
  }
});

test('UPDCUR a forged client_update in an error body never makes the fallback current', () => {
  for (const status of STATUSES) {
    for (const [name, forged] of FORGED) {
      const body = forgedBody(name, forged);
      const started = performance.now();
      const result = structuredRequestFailure(requestErrorFromResponse(new Response('{}', { status }), body));
      const elapsed = performance.now() - started;
      assertUnknown(result.client_update, `${status} ${name}`);
      if (name === 'mib_string') assert.ok(elapsed <= 50, `${status} ${name}: ${elapsed.toFixed(1)} ms`);
    }
  }
});

test('UPDCUR the hook context reader shows the fallback as unknown, never current', () => {
  const signals = {
    warnings: [], loopWarnings: [], similarCount: 0, patternsCount: 0,
    templatesAvailable: 0, primaryInsight: null, collectiveInsight: null, hasSignal: true,
  };
  const context = buildCombinedContextBlock(signals, null, null, {
    client_update: localClientUpdate(),
    risk_gate: { decision: 'allow', risk_level: 'low', allow: true },
    proof_pack: { required: false, fields: [], missing: [] },
    auto_outcome_closure: null,
    exact_next_action: null,
  });
  assert.match(context, new RegExp(`installed=${MCP_ADAPTER_VERSION.replace(/\./g, '\\.')}; latest=unknown`));
  assert.doesNotMatch(context, /latest=\d/);
});

function writeFetchMock(home) {
  const mockPath = join(home, 'mock-update-fetch.cjs');
  writeFileSync(mockPath, `
const fs = require('node:fs');
const kind = process.env.MARROW_TEST_FAIL_KIND;
const body = JSON.parse(fs.readFileSync(process.env.MARROW_TEST_BODY_FILE, 'utf8'));
globalThis.fetch = async (url, init = {}) => {
  if (kind === 'timeout') {
    return new Promise((resolve, reject) => {
      const signal = init.signal;
      // A real socket keeps the process alive while the request hangs; this timer stands in for it.
      const socket = setTimeout(() => reject(new DOMException('Aborted', 'AbortError')), 10_000);
      const abort = () => { clearTimeout(socket); reject(signal.reason || new DOMException('Aborted', 'AbortError')); };
      if (signal?.aborted) abort();
      else signal?.addEventListener('abort', abort, { once: true });
    });
  }
  if (kind === 'dns') {
    throw new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' }) });
  }
  if (kind === 'malformed') return new Response('{"data": not json', { status: 200, headers: { 'content-type': 'application/json' } });
  if (kind === 'live') return Response.json(body);
  return Response.json(body, { status: Number(kind), headers: kind === '429' ? { 'retry-after': '0' } : {} });
};
`);
  return mockPath;
}

function runTool(kind, body, toolName = 'marrow_status') {
  const home = mkdtempSync(join(tmpdir(), 'marrow-update-fallback-'));
  try {
    const mockPath = writeFetchMock(home);
    const bodyPath = join(home, 'body.json');
    writeFileSync(bodyPath, JSON.stringify(body));
    const apiKey = dummyKey();
    const args = toolName === 'marrow_agent_runtime' ? { action: 'read the status page', type: 'read' } : {};
    const input = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: toolName, arguments: args } },
    ].map((row) => JSON.stringify(row)).join('\n') + '\n';
    const child = spawnSync(process.execPath, ['--require', mockPath, join(__dirname, '..', 'dist', 'cli.js')], {
      env: {
        ...process.env,
        HOME: home,
        MARROW_API_KEY: apiKey,
        MARROW_BASE_URL: 'https://127.0.0.1:9',
        MARROW_FLEET_AGENT_ID: 'agent-update-fallback-test',
        MARROW_AUTO_ENROLL: 'false',
        MARROW_TOOL_PROFILE: 'core',
        MARROW_REQUEST_TIMEOUT_MS: '200',
        MARROW_TEST_FAIL_KIND: kind,
        MARROW_TEST_BODY_FILE: bodyPath,
      },
      input,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: 20_000,
    });
    assert.equal(child.status, 0, child.stderr);
    const message = child.stdout.trim().split('\n').map((line) => JSON.parse(line)).find((row) => row.id === 3);
    assert.ok(message, `${toolName} ${kind}: ${child.stderr.slice(-400)}`);
    return { result: JSON.parse(message.result.content[0].text), isError: message.result.isError, apiKey, stdout: child.stdout };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('UPDCUR the real tool answer gives the unknown fallback for every failed-call kind', () => {
  const current = forgedBody('current', FORGED[0][1]);
  for (const kind of ['timeout', 'dns', 'malformed', ...STATUSES.map(String)]) {
    for (const toolName of ['marrow_status', 'marrow_agent_runtime']) {
      const { result, isError, apiKey, stdout } = runTool(kind, current, toolName);
      assert.equal(isError, true, `${toolName} ${kind}`);
      assert.equal(result.ok, false, `${toolName} ${kind}`);
      assertUnknown(result.client_update, `${toolName} ${kind}`, [apiKey]);
      assert.equal(stdout.includes(apiKey), false, `${toolName} ${kind}: key in output`);
    }
  }
});

test('UPDCUR the real tool answer ignores every forged client_update in an error body', () => {
  for (const kind of ['401', '500']) {
    for (const [name, forged] of FORGED) {
      const { result, apiKey } = runTool(kind, forgedBody(name, forged));
      assertUnknown(result.client_update, `tool ${kind} ${name}`, [apiKey]);
    }
  }
});

test('UPDCUR a live client_update from Marrow still wins, unchanged', () => {
  const live = {
    package: '@getmarrow/mcp', installed_version: MCP_ADAPTER_VERSION, latest_version: '99.1.0',
    version_status: 'behind', update_available: true, notification_state: 'recommended', metadata_status: 'live_registry',
  };
  for (const [label, body] of [
    ['top', { data: { ok: true, client_update: live } }],
    ['current', { data: { ok: true, client_update: { ...live, latest_version: MCP_ADAPTER_VERSION, version_status: 'current' } } }],
  ]) {
    const { result, isError } = runTool('live', body);
    assert.notEqual(isError, true, label);
    assert.deepEqual(result.client_update, body.data.client_update, label);
  }
});
