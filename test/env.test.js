const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveMarrowEnv } = require('../dist/env.js');

test('resolveMarrowEnv loads MARROW_KEY alias from project env file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-env-'));
  fs.mkdirSync(path.join(dir, '.marrow'));
  fs.writeFileSync(path.join(dir, '.marrow', 'env'), [
    'OTHER_SERVICE_SECRET=do_not_materialize',
    'MARROW_KEY=mrw_test_mcp_alias_key_123456789',
    'MARROW_FLEET_AGENT_ID=mcp-agent',
    '',
  ].join('\n'));

  const resolved = resolveMarrowEnv({
    cwd: dir,
    home: path.join(dir, 'home'),
    env: {},
  });

  assert.equal(resolved.apiKey, 'mrw_test_mcp_alias_key_123456789');
  assert.equal(resolved.agentId, 'mcp-agent');
  assert.match(resolved.source, /\.marrow\/env:MARROW_KEY$/);
});

test('resolveMarrowEnv ignores non-Marrow env file assignments', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-env-whitelist-'));
  fs.mkdirSync(path.join(dir, '.marrow'));
  fs.writeFileSync(path.join(dir, '.marrow', 'env'), [
    'OTHER_SERVICE_SECRET=should_not_be_read',
    'DATABASE_URL=postgres://example',
    'MARROW_KEY=mrw_test_mcp_whitelist_key_123456789',
    '',
  ].join('\n'));

  const resolved = resolveMarrowEnv({
    cwd: dir,
    home: path.join(dir, 'home'),
    env: {},
  });

  assert.equal(resolved.apiKey, 'mrw_test_mcp_whitelist_key_123456789');
  assert.doesNotMatch(JSON.stringify(resolved), /should_not_be_read|postgres/);
});

test('resolveMarrowEnv gives exact setup fix when no key is available', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-missing-env-'));
  const resolved = resolveMarrowEnv({
    cwd: dir,
    home: path.join(dir, 'home'),
    env: {},
  });

  assert.equal(resolved.missing, true);
  assert.equal(resolved.apiKey, '');
  assert.match(resolved.exactFix, /\.marrow\/env/);
  assert.doesNotMatch(resolved.exactFix, /mrw_live_[A-Za-z0-9_-]{8,}/);
});
