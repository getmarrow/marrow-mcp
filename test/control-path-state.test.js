const assert = require('node:assert/strict');
const test = require('node:test');

const {
  controlPathStats,
  recordControlPathSample,
  resetControlPathState,
} = require('../dist/control-path-state.js');

test('control-path latency reports current, p50, p99, and success/failure totals', () => {
  resetControlPathState();
  for (const [elapsedMs, success] of [[30, true], [10, true], [900, false], [50, true]]) {
    recordControlPathSample('marrow_status', elapsedMs, success);
  }
  assert.deepEqual(controlPathStats('marrow_status'), {
    tool: 'marrow_status',
    current_ms: 50,
    p50_ms: 30,
    p99_ms: 900,
    sample_count: 4,
    success_count: 3,
    failure_count: 1,
    last_success_at: controlPathStats('marrow_status').last_success_at,
  });
  assert.match(controlPathStats('marrow_status').last_success_at, /^\d{4}-\d{2}-\d{2}T/);
});

test('control-path latency retains only the newest bounded sample window', () => {
  resetControlPathState();
  for (let index = 1; index <= 60; index += 1) {
    recordControlPathSample('marrow_ask', index, true);
  }
  const status = controlPathStats('marrow_ask');
  assert.equal(status.sample_count, 50);
  assert.equal(status.current_ms, 60);
  assert.equal(status.p50_ms, 35);
  assert.equal(status.p99_ms, 60);
});
