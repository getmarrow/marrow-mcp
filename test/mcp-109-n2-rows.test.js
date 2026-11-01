const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { keyClassOf } = require('../dist/key-class.js');
const { CONTROL_CHANGED_BY } = require('../dist/control-state.js');
const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { backendCategories, missing } = require('./support/mcp-109-n2-categories.cjs');

// mcp-109-n2, the auditor's n2 rows (reaudit-mcp109 tools n2.cjs + n2.json): 19 commands, each a chain with a T2 write or an MCP-10 route in
// one segment and a deploy, publish, merge, migration or secret read in another. For each: the keyed hook's runtime body (action, type,
// surfaces) gives every backend category 3.9.108 gives (test/fixtures/mcp-109-n2/n2-base.json), the MCP's own mirror localApprovalCategories
// gives every local category 3.9.108 gives, and the call is denied.
const FETCH = join(__dirname, 'support', 'fetch-status.cjs');
const GUARD = join(__dirname, 'support', 'loopback-net-guard.cjs');
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const KEY = `n2dummy${randomBytes(12).toString('hex')}`;
assert.equal(keyClassOf(KEY), null);
const ROWS = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'mcp-109-n2', 'n2-base.json'), 'utf8'));

function run(rawCommand) {
  const home = mkdtempSync(join(tmpdir(), 'n2-rows-'));
  try {
    const control = join(home, '.marrow');
    mkdirSync(control, { mode: 0o700 });
    chmodSync(control, 0o700);
    writeFileSync(join(control, 'control.json'), JSON.stringify({ version: 1, enabled: true, changed_at: new Date(0).toISOString(), changed_by: CONTROL_CHANGED_BY, change_id: `ctl_${'c'.repeat(32)}` }), { mode: 0o600 });
    mkdirSync(join(home, 'w'));
    const capture = join(home, 'cap.jsonl');
    writeFileSync(capture, '');
    const env = { HOME: home, PATH: process.env.PATH, CAPTURE_FILE: capture, FETCH_STATUS: '503', TMPDIR: home, MARROW_API_KEY: KEY };
    const command = rawCommand.replaceAll('$H', home);
    const event = { hook_event_name: 'PreToolUse', session_id: 'sess-n2', tool_name: 'Bash', tool_input: { command }, cwd: join(home, 'w'), permission_mode: 'default' };
    const result = spawnSync(process.execPath, ['--require', FETCH, '--require', GUARD, CLI, 'claude-pre-action-hook'], { input: JSON.stringify(event), env, encoding: 'utf8', timeout: 30000 });
    let decision = 'EMPTY';
    try { const j = JSON.parse(result.stdout.trim()); decision = j.hookSpecificOutput?.permissionDecision || Object.keys(j).join('+'); } catch { /* keep EMPTY */ }
    const bodies = readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => { try { return JSON.parse(JSON.parse(line).body); } catch { return {}; } });
    const runtime = bodies.find((body) => typeof body.type === 'string' && 'normalized_action' in body);
    const local = localApprovalCategories(classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: join(home, 'w'), hook_event_name: 'PreToolUse' }, { cwd: join(home, 'w') }));
    return { decision, runtime, local, leak: (result.stdout + result.stderr + JSON.stringify(bodies)).includes(KEY) };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('mcp-109-n2 rows: the 19 chains keep every BASE backend and local category and stay denied', () => {
  assert.equal(ROWS.length, 19);
  for (const row of ROWS) {
    const result = run(row.command);
    assert.equal(result.decision, 'deny', row.command);
    assert.equal(result.leak, false, row.command);
    assert.ok(result.runtime, `${row.command}: no runtime body`);
    const got = backendCategories(result.runtime.action, result.runtime.type, result.runtime.surfaces);
    const wanted = row.backend.map((category) => category.replace(/\?$/, ''));
    assert.deepEqual(missing(wanted, got), [], `${row.command}: backend category lost (sent ${result.runtime.type} on ${(result.runtime.surfaces || []).join('+')})`);
    assert.deepEqual(missing(row.local, result.local), [], `${row.command}: local mirror category lost`);
  }
});
