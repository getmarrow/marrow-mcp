const assert = require('node:assert/strict');
const { chmodSync, lstatSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { readGuidanceCache, writeGuidanceCache } = require('../dist/guidance-cache.js');

test('last-known guidance is private, account-key scoped, and bounded', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-guidance-cache-'));
  try {
    writeGuidanceCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-one', context: 'known safe guidance', home });
    const hit = readGuidanceCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', agentId: 'agent-one', home });
    const wrongKey = readGuidanceCache({ apiKey: 'key-two', baseUrl: 'https://api.example.test', agentId: 'agent-one', home });
    assert.equal(hit.context, 'known safe guidance');
    assert.equal(wrongKey, null);
    assert.equal(lstatSync(join(home, '.marrow', 'cache')).mode & 0o077, 0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('last-known guidance rejects a permissive cache boundary', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-guidance-cache-'));
  try {
    writeGuidanceCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', context: 'first', home });
    chmodSync(join(home, '.marrow', 'cache'), 0o755);
    assert.throws(
      () => readGuidanceCache({ apiKey: 'key-one', baseUrl: 'https://api.example.test', home }),
      /owner-only/,
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
