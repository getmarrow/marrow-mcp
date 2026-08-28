const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const control = require('../dist/control-state.js');
const { localControlAllowOutput } = require('../dist/hook-pre-action.js');

function homeFixture(enabled = false) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-control-'));
  const directory = path.join(home, '.marrow'); fs.mkdirSync(directory, { mode: 0o700 });
  const value = { version: 1, enabled, changed_at: '2026-08-28T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli' };
  fs.writeFileSync(path.join(directory, 'control.json'), `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return home;
}

test('local control is default enabled and strict private state parses byte-equivalently', () => {
  const missing = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-control-missing-'));
  assert.deepEqual(control.readLocalControlState({ home: missing }), { enabled: true, state: 'default_enabled', changed_at: null });
  const home = homeFixture(false);
  assert.equal(control.readLocalControlState({ home }).state, 'disabled');
  fs.chmodSync(path.join(home, '.marrow', 'control.json'), 0o644);
  assert.throws(() => control.readLocalControlState({ home }), /unsafe or invalid/);
});

test('unsafe schemas and symlinked owner paths fail closed without external mutation', () => {
  const home = homeFixture(false); const target = path.join(home, '.marrow', 'control.json');
  fs.chmodSync(target, 0o600); fs.writeFileSync(target, '{"enabled":false,"unknown":true}\n');
  assert.throws(() => control.readLocalControlState({ home }), /unsafe/);
  const linkedHome = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-control-link-'));
  fs.symlinkSync(path.join(home, '.marrow'), path.join(linkedHome, '.marrow'));
  assert.throws(() => control.readLocalControlState({ home: linkedHome }), /unsafe/);
});

test('disabled protected hooks preserve every native host allow schema', () => {
  assert.deepEqual(localControlAllowOutput('claude-code'), {});
  assert.deepEqual(localControlAllowOutput('codex'), {});
  assert.deepEqual(localControlAllowOutput('cursor'), { permission: 'allow' });
  assert.deepEqual(localControlAllowOutput('cline'), { cancel: false });
  assert.equal(localControlAllowOutput('windsurf'), null);
  assert.deepEqual(localControlAllowOutput('gemini'), { decision: 'allow' });
  assert.deepEqual(localControlAllowOutput('grok'), { decision: 'allow' });
});

test('all native lifecycle adapters poll local state and fixed receipt excludes private payload fields', () => {
  for (const file of ['hook-context.ts', 'hook-pre-action.ts', 'hook.ts', 'hook-session.ts']) assert.match(fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8'), /readLocalControlState/);
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'hook-pre-action.ts'), 'utf8');
  assert.match(source, /CONTROL_BYPASS_ACTION/);
  assert.doesNotMatch(control.CONTROL_BYPASS_ACTION, /tool|command|target|path|prompt|result|credential|service/i);
});
