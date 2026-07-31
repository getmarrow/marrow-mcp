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
    'MARROW_KEY=synthetic-mcp-alias-key',
    'MARROW_FLEET_AGENT_ID=mcp-agent',
    '',
  ].join('\n'));

  const resolved = resolveMarrowEnv({
    cwd: dir,
    home: path.join(dir, 'home'),
    env: {},
  });

  assert.equal(resolved.apiKey, 'synthetic-mcp-alias-key');
  assert.equal(resolved.agentId, 'mcp-agent');
  assert.match(resolved.source, /\.marrow\/env:MARROW_KEY$/);
});

test('trusted enforcement identity uses owner config and cannot be shadowed by repository env files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-env-precedence-'));
  const home = path.join(dir, 'home');
  fs.mkdirSync(path.join(dir, '.marrow'), { recursive: true });
  fs.mkdirSync(path.join(home, '.marrow'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, '.env'), [
    'MARROW_API_KEY=synthetic-project-key',
    'MARROW_BASE_URL=https://hostile.invalid',
    'MARROW_AGENT_ID=hostile-agent',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(home, '.marrow', 'env'), [
    'MARROW_API_KEY=synthetic-owner-key',
    'MARROW_BASE_URL=https://api.getmarrow.ai',
    'MARROW_AGENT_ID=owner-agent',
    '',
  ].join('\n'), { mode: 0o600 });

  const resolved = resolveMarrowEnv({ cwd: dir, home, env: {}, trustedOnly: true });

  assert.equal(resolved.apiKey, 'synthetic-owner-key');
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
  assert.equal(resolved.agentId, 'owner-agent');
  assert.match(resolved.source, /home\/\.marrow\/env:MARROW_API_KEY$/);
  assert.doesNotMatch(JSON.stringify(resolved), /hostile/);
});

test('trusted enforcement rejects permissive and symbolic owner credential files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-env-private-'));
  const home = path.join(dir, 'home');
  const ownerDir = path.join(home, '.marrow');
  fs.mkdirSync(ownerDir, { recursive: true, mode: 0o700 });
  const credential = path.join(ownerDir, 'env');
  fs.writeFileSync(credential, 'MARROW_API_KEY=synthetic-permissive-key\n', { mode: 0o644 });

  const permissive = resolveMarrowEnv({ cwd: dir, home, env: {}, trustedOnly: true });
  assert.equal(permissive.missing, true);
  assert.doesNotMatch(JSON.stringify(permissive), /synthetic-permissive-key/);

  const outside = path.join(dir, 'outside-env');
  fs.writeFileSync(outside, 'MARROW_API_KEY=synthetic-symlink-key\n', { mode: 0o600 });
  fs.rmSync(credential);
  fs.symlinkSync(outside, credential);
  const symbolic = resolveMarrowEnv({ cwd: dir, home, env: {}, trustedOnly: true });
  assert.equal(symbolic.missing, true);
  assert.doesNotMatch(JSON.stringify(symbolic), /synthetic-symlink-key/);
});

test('resolveMarrowEnv ignores non-Marrow env file assignments', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-mcp-env-whitelist-'));
  fs.mkdirSync(path.join(dir, '.marrow'));
  fs.writeFileSync(path.join(dir, '.marrow', 'env'), [
    'OTHER_SERVICE_SECRET=should_not_be_read',
    'DATABASE_URL=postgres://example',
    'MARROW_KEY=synthetic-whitelist-key',
    '',
  ].join('\n'));

  const resolved = resolveMarrowEnv({
    cwd: dir,
    home: path.join(dir, 'home'),
    env: {},
  });

  assert.equal(resolved.apiKey, 'synthetic-whitelist-key');
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
  assert.match(resolved.exactFix, /~\/\.marrow\/env/);
  assert.doesNotMatch(resolved.exactFix, /mrw_live_[A-Za-z0-9_-]{8,}/);
});
