const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { resolvePingTimeoutMs, updatePingState } = require('../dist/ping-state.js');

test('ping timeout tolerates real network latency and remains bounded', () => {
  assert.equal(resolvePingTimeoutMs(undefined), 2_500);
  assert.equal(resolvePingTimeoutMs('not-a-number'), 2_500);
  assert.equal(resolvePingTimeoutMs('200'), 500);
  assert.equal(resolvePingTimeoutMs('1750.9'), 1_750);
  assert.equal(resolvePingTimeoutMs('9000'), 5_000);
});

test('ping history reports measured p50/p99 and preserves last success across failure', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-ping-state-'));
  try {
    for (const latencyMs of [100, 120, 200, 350]) {
      updatePingState({ apiKey: 'key-one', baseUrl: 'https://api.example.test', latencyMs, success: true, home });
    }
    const failed = updatePingState({ apiKey: 'key-one', baseUrl: 'https://api.example.test', success: false, home });
    assert.equal(failed.sample_count, 4);
    assert.equal(failed.p50_ms, 120);
    assert.equal(failed.p99_ms, 350);
    assert.match(failed.last_success_at, /^\d{4}-\d{2}-\d{2}T/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
