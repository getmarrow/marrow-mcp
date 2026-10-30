const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { keyClassOf } = require('../dist/key-class.js');
const { CONTROL_CHANGED_BY } = require('../dist/control-state.js');
const { backendCategories, missing } = require('./support/mcp-109-n2-categories.cjs');

// mcp-109-n2 (reaudit-mcp109 B1/B2, N2): an early return in the pre-action hook (the MCP-10 control route, the T2 control-file and persistence
// writes, the fail-closed corrupt control.json) must never drop a risk category that 3.9.108 gives the same command. The matrix is early return
// x hold x order (48 cells), through the real claude-pre-action-hook, keyless and keyed (a dummy key drawn at run time, every fetch captured
// and answered locally with 503, nothing leaves the process). BASE categories come from test/fixtures/mcp-109-n2/shortcut-base.tsv (the 3.9.108
// hook's body, categories per the backend matcher). The decision stays a denial in every cell, both modes.
const FETCH = join(__dirname, 'support', 'fetch-status.cjs');
const GUARD = join(__dirname, 'support', 'loopback-net-guard.cjs');
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const draw = () => {
  const value = `n2dummy${randomBytes(12).toString('hex')}`;
  assert.equal(keyClassOf(value), null);
  return value;
};
const KEY = draw();

const RETURNS = {
  none: '',
  'mcp10-route': 'npx @getmarrow/install control disable',
  't2-control': "echo '{}' > $H/.marrow/control.json",
  't2-persist': 'echo x >> $H/.bashrc',
  failclosed: '',
};
const HOLDS = {
  'secret-path': 'cat $H/.aws/credentials',
  'system-path': 'echo x > /etc/hosts',
  'prod-deploy': 'wrangler deploy --env production',
  'npm-publish': 'npm publish',
  'wk5-patch': 'git apply $H/w/p.diff',
  'wk5-stdin': 'git am',
};
const BASE = new Map(readFileSync(join(__dirname, 'fixtures', 'mcp-109-n2', 'shortcut-base.tsv'), 'utf8').split('\n')
  .filter((line) => line && !line.startsWith('#'))
  .map((line) => { const [ret, hold, order, , cats] = line.split('\t'); return [`${ret}|${hold}|${order}`, cats ? cats.split(',') : []]; }));

function runCell(ret, hold, order, keyed) {
  const home = mkdtempSync(join(tmpdir(), 'n2-short-'));
  try {
    const control = join(home, '.marrow');
    mkdirSync(control, { mode: 0o700 });
    chmodSync(control, 0o700);
    const file = join(control, 'control.json');
    if (ret === 'failclosed') writeFileSync(file, '{nope', { mode: 0o600 });
    else writeFileSync(file, JSON.stringify({ version: 1, enabled: true, changed_at: new Date(0).toISOString(), changed_by: CONTROL_CHANGED_BY, change_id: `ctl_${'d'.repeat(32)}` }), { mode: 0o600 });
    mkdirSync(join(home, 'w'));
    mkdirSync(join(home, '.aws'));
    writeFileSync(join(home, 'w', 'p.diff'), 'diff --git a/.claude/settings.json b/.claude/settings.json\n--- a/.claude/settings.json\n+++ b/.claude/settings.json\n@@ -1 +1 @@\n-{}\n+{"hooks":{}}\n');
    const capture = join(home, 'cap.jsonl');
    writeFileSync(capture, '');
    const env = { HOME: home, PATH: process.env.PATH, CAPTURE_FILE: capture, FETCH_STATUS: '503', TMPDIR: home };
    if (keyed) env.MARROW_API_KEY = KEY;
    const r = RETURNS[ret];
    const h = HOLDS[hold];
    const command = (order === 'hold' ? h : order === 'ret&&hold' ? `${r} && ${h}` : `${h}; ${r}`).replaceAll('$H', home);
    const event = { hook_event_name: 'PreToolUse', session_id: 'sess-n2', tool_name: 'Bash', tool_input: { command }, cwd: join(home, 'w'), permission_mode: 'default' };
    const run = spawnSync(process.execPath, ['--require', FETCH, '--require', GUARD, CLI, 'claude-pre-action-hook'], { input: JSON.stringify(event), env, encoding: 'utf8', timeout: 30000 });
    let decision = 'EMPTY';
    try { const j = JSON.parse(run.stdout.trim()); decision = j.hookSpecificOutput?.permissionDecision || Object.keys(j).join('+'); } catch { /* keep EMPTY */ }
    const bodies = readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => { try { return JSON.parse(JSON.parse(line).body); } catch { return {}; } });
    const runtime = bodies.find((body) => typeof body.type === 'string' && 'normalized_action' in body);
    const leak = (run.stdout + run.stderr + JSON.stringify(bodies)).includes(KEY);
    return { decision, runtime, leak, status: run.status };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

for (const ret of Object.keys(RETURNS)) {
  test(`mcp-109-n2 shortcut: ${ret} x every hold keeps every BASE category and denies`, () => {
    const orders = ret === 'none' || ret === 'failclosed' ? ['hold'] : ['ret&&hold', 'hold;ret'];
    const problems = [];
    let cells = 0;
    for (const hold of Object.keys(HOLDS)) {
      for (const order of orders) {
        const cell = `${ret}|${hold}|${order}`;
        assert.ok(BASE.has(cell), `fixture row ${cell}`);
        cells += 1;
        const keyless = runCell(ret, hold, order, false);
        if (keyless.decision !== 'deny') problems.push(`${cell} keyless decision ${keyless.decision}`);
        if (keyless.leak) problems.push(`${cell} keyless leak`);
        const keyed = runCell(ret, hold, order, true);
        if (keyed.decision !== 'deny') problems.push(`${cell} keyed decision ${keyed.decision}`);
        if (keyed.leak) problems.push(`${cell} keyed leak`);
        if (ret === 'failclosed') {
          // The corrupt control file is answered locally, before any gate call, exactly as in 3.9.108: there is no body whose categories could shrink.
          if (keyed.runtime !== undefined) problems.push(`${cell} sent a runtime body`);
          continue;
        }
        if (!keyed.runtime) { problems.push(`${cell} keyed hook sent no runtime body`); continue; }
        const got = backendCategories(keyed.runtime.action, keyed.runtime.type, keyed.runtime.surfaces);
        const lost = missing(BASE.get(cell), got);
        if (lost.length) problems.push(`${cell} LOST ${lost.join('+')} (sent ${keyed.runtime.type} on ${(keyed.runtime.surfaces || []).join('+')}: ${keyed.runtime.action})`);
        if (ret === 'mcp10-route' || ret === 't2-control' || ret === 't2-persist') {
          if (!got.includes('secrets_security')) problems.push(`${cell} gained no secrets_security`);
          if (keyed.runtime.type !== 'security') problems.push(`${cell} type ${keyed.runtime.type}`);
        }
      }
    }
    assert.equal(cells, ret === 'none' || ret === 'failclosed' ? 6 : 12);
    assert.deepEqual(problems, [], `${problems.length} problem(s) in ${cells} cells`);
  });
}
