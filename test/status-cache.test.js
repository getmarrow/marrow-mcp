const assert = require('node:assert/strict');
const { chmodSync, lstatSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { cachedStatusPayload, readStatusCache, writeStatusCache } = require('../dist/status-cache.js');

function measuredStatus(overrides = {}) {
  return {
    ok: true,
    health: 'healthy',
    enabled: true,
    measurement_availability: {
      available: true,
      state: 'measured',
      exact: false,
      source: 'shared_runtime_snapshot',
    },
    memory: { has_memory: true, decision_count: 20 },
    has_memory: true,
    decision_count: 20,
    outcome_count: 7,
    route_contract: { endpoint_inventory: Array.from({ length: 100 }, () => 'must-not-be-cached') },
    diagnostics: { key_valid: true, query_ms: 19, token_value_proof: 'must-not-be-cached' },
    ...overrides,
  };
}

test('last-known status is private, tenant-and-agent scoped, compact, and non-authorizing', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-status-cache-'));
  try {
    assert.equal(writeStatusCache({
      apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-one',
      source: 'runtime', status: measuredStatus(), home,
    }), true);
    const hit = readStatusCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-one', home });
    assert.ok(hit);
    assert.equal(hit.status.decision_count, 20);
    assert.equal(hit.status.has_memory, true);
    assert.equal(readStatusCache({ apiKey: 'key-two', baseUrl: 'https://api.example.test', agentId: 'agent-one', home }), null);
    assert.equal(readStatusCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-two', home }), null);
    assert.equal(lstatSync(join(home, '.marrow', 'cache')).mode & 0o077, 0);

    const cached = cachedStatusPayload(hit);
    assert.equal(cached.live, false);
    assert.equal(cached.authorization_state, 'status_only_non_authorizing');
    assert.equal(cached.fresh_runtime_gate_required_for_high_risk, true);
    const text = JSON.stringify(cached);
    assert.doesNotMatch(text, /endpoint_inventory|token_value_proof|must-not-be-cached/);
    assert.ok(Buffer.byteLength(text, 'utf8') < 8_000);

    const realNow = Date.now;
    Date.now = () => realNow() + 31_000;
    try {
      const stale = readStatusCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-one', home });
      assert.equal(stale.freshness, 'stale');
      const stalePayload = cachedStatusPayload(stale);
      assert.equal(stalePayload.stale, true);
      assert.equal(stalePayload.authorization_state, 'status_only_non_authorizing');
    } finally {
      Date.now = realNow;
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('status cache rejects fake measured state and permissive boundaries', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-status-cache-'));
  try {
    assert.equal(writeStatusCache({
      apiKey: 'key-one', baseUrl: 'https://api.example.test', source: 'status',
      status: measuredStatus({ memory: { has_memory: true }, decision_count: undefined }), home,
    }), false);
    assert.equal(writeStatusCache({
      apiKey: 'key-one', baseUrl: 'https://api.example.test', source: 'status', status: measuredStatus(), home,
    }), true);
    chmodSync(join(home, '.marrow', 'cache'), 0o755);
    assert.throws(
      () => readStatusCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', home }),
      /owner-only/,
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('warming status remains unknown instead of fabricating an empty account', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-status-cache-'));
  try {
    assert.equal(writeStatusCache({
      apiKey: 'key-one', baseUrl: 'https://api.example.test', source: 'status', home,
      status: {
        ok: true,
        health: 'warming',
        has_memory: false,
        decision_count: 0,
        measurement_availability: { available: false, state: 'warming', exact: false, source: 'none' },
      },
    }), true);
    const hit = readStatusCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', home });
    assert.ok(hit);
    assert.equal(hit.status.has_memory, null);
    assert.equal(hit.status.decision_count, null);
    assert.equal(hit.status.memory.state, 'unknown');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
