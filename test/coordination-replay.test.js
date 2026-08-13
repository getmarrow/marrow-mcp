const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const test = require('node:test');

const { marrowCoordinate, marrowReplayCompare } = require('../dist/index.js');

test('coordination uses the tenant governance routes and bound agent identity', async (t) => {
  const originalFetch = global.fetch;
  const calls = [];
  global.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    return Response.json({ data: { ok: true } });
  };
  t.after(() => { global.fetch = originalFetch; });

  await marrowCoordinate('key', 'https://api.example.test', {
    action: 'acquire_lease',
    resource_type: 'file',
    resource: 'src/service.ts',
  }, 'session-one', 'agent-one');
  await marrowCoordinate('key', 'https://api.example.test', {
    action: 'release_lease',
    lease_id: 'lease_12345678',
    lease_token: 'a'.repeat(32),
  }, 'session-one', 'agent-one');

  assert.equal(calls[0].url, 'https://api.example.test/v1/agent/governance/leases/acquire');
  assert.equal(JSON.parse(calls[0].init.body).agent_id, 'agent-one');
  assert.equal(calls[1].url, 'https://api.example.test/v1/agent/governance/leases/lease_12345678/release');
  assert.equal(JSON.parse(calls[1].init.body).lease_token, 'a'.repeat(32));

  await assert.rejects(
    marrowCoordinate('key', 'https://api.example.test', {
      action: 'acquire_lease', agent_id: 'agent-two', resource_type: 'file', resource: 'src/other.ts',
    }, 'session-one', 'agent-one'),
    /must match the authenticated Marrow fleet agent id/,
  );
  await assert.rejects(
    marrowCoordinate('key', 'https://api.example.test', {
      action: 'create_proof_packet', source_agent_id: 'agent-two', summary: 'done',
    }, 'session-one', 'agent-one'),
    /must match the authenticated Marrow fleet agent id/,
  );
  assert.equal(calls.length, 2);
});

test('replay comparison submits only recorded decision evidence and can fetch by id', async (t) => {
  const originalFetch = global.fetch;
  const calls = [];
  global.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    return Response.json({ data: { status: 'complete', generated_by_model: false } });
  };
  t.after(() => { global.fetch = originalFetch; });

  const compared = await marrowReplayCompare('key', 'https://api.example.test', {
    source_decision_id: 'decision-source',
    constraints: { tests: 'same', environment: 'staging', required_proof: true },
    baseline: { label: 'model-a', decision_id: 'decision-a' },
    candidate: { label: 'model-b', decision_id: 'decision-b' },
  }, 'session-one', 'agent-one');
  await marrowReplayCompare('key', 'https://api.example.test', {
    comparison_id: 'replay_12345678',
  }, 'session-one', 'agent-one');

  assert.equal(compared.generated_by_model, false);
  assert.equal(calls[0].url, 'https://api.example.test/v1/agent/governance/replay-comparisons');
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body).constraints, {
    environment: 'staging', required_proof: true, tests: 'same',
  });
  assert.equal(calls[1].url, 'https://api.example.test/v1/agent/governance/replay-comparisons/replay_12345678');
});

test('coordination and replay reject path traversal and remain advertised MCP tools', async () => {
  await assert.rejects(
    marrowCoordinate('key', 'https://api.example.test', {
      action: 'release_lease', lease_id: '../lease', lease_token: 'a'.repeat(32),
    }, 'session-one', 'agent-one'),
    /invalid characters/,
  );
  await assert.rejects(
    marrowReplayCompare('key', 'https://api.example.test', { comparison_id: '../replay' }),
    /invalid characters/,
  );
  for (const constraints of [
    { prompt: 'customer prompt' },
    { code: 'rm -rf /' },
    { transcript: 'private conversation' },
    { environment: { nested: 'staging' } },
    { unknown: 'value' },
    { environment: 'x'.repeat(81) },
  ]) {
    await assert.rejects(
      marrowReplayCompare('key', 'https://api.example.test', {
        source_decision_id: 'decision-source',
        baseline: { decision_id: 'decision-a' },
        candidate: { decision_id: 'decision-b' },
        constraints,
      }),
      /constraints/,
    );
  }
  const cli = readFileSync(resolve(__dirname, '../src/cli.ts'), 'utf8');
  assert.match(cli, /name: 'marrow_coordinate'/);
  assert.match(cli, /name: 'marrow_replay_compare'/);
  assert.match(cli, /does not run a model/);
  const coordinateSchema = cli.slice(cli.indexOf("name: 'marrow_coordinate'"), cli.indexOf("name: 'marrow_replay_compare'"));
  assert.doesNotMatch(coordinateSchema, /^\s*agent_id:/m);
  assert.doesNotMatch(coordinateSchema, /^\s*source_agent_id:/m);
  assert.match(cli, /additionalProperties: false/);
});
