'use strict';

// Test-only. Never shipped (package.json "files" lists dist and vendor/classifier only) and never required by src.
// Preloaded (NODE_OPTIONS=--require, after host-approval-fetch-mock.cjs) into one hook subprocess by
// test/host-approvals.test.js. It counts the marker-wait ticks of a post-tool hook, so "does not wait for a
// marker" is asserted as an event instead of a wall-clock bound that CPU load can break. The product is not
// changed: the probe only observes setTimeout(.., 100) calls made from dist/host-approval.js, which is the one
// 100 ms timer in settleAfterTool's marker-wait loop (LATE_MARKER_WAIT_MS / 100 ticks when it runs to its end).
const { writeFileSync } = require('node:fs');
const { join } = require('node:path');

const target = join(process.env.MARROW_TEST_MOCK_DIR, 'post-hook-probe.json');
const probe = { marker_wait_ticks: 0 };
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = function probedSetTimeout(callback, delay, ...rest) {
  if (Number(delay) === 100 && /[\\/]dist[\\/]host-approval\.js[:)]/.test(new Error().stack || '')) probe.marker_wait_ticks += 1;
  return realSetTimeout.call(this, callback, delay, ...rest);
};
process.on('exit', () => {
  try { writeFileSync(target, JSON.stringify(probe)); } catch { /* the test reports a missing file */ }
});
