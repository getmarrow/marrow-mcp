'use strict';

// CURSOR-SPEED-A: the Cursor hook gets a 9 s budget (it was 4 s) inside Cursor's 15 s hooks.json timeout, plus an
// off-by-default timing log (MARROW_HOOK_TIMING=1). The budget only gives the same control path more time: a slow, failed
// or partial server answer still holds, never an allow. Rows FC1-FC10 and T1-T3 drive the real hook CLI (dist/cli.js) in a
// child process against a scripted API with chosen delays (test/support/cursor-budget-stub.cjs). Assertions use the
// answer and generous time bounds, not exact milliseconds. CB_CLI_ROOT=<other build> runs the same rows on that build.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { runHook, makeHome, allowed, denied, ROOT } = require('./support/cursor-budget-run.cjs');
const { HELD_SLOW_TEXT, HELD_OFFLINE_TEXT, classifyTool } = require(`${ROOT}/dist/hook-pre-action.js`);
const { preToolBudgetMs, settleBudgetMs } = require(`${ROOT}/dist/host-approval.js`);
const { runFaulted, FAULTS } = require('./support/hook-stderr-faults.cjs');

const COMMIT = 'git commit -m t';
const FORCE = 'git push --force origin main';
const HOST_LIMIT_BOUND_MS = 9_800; // the 9 s hook deadline plus load margin; the host kills at 15 s
const heldSlow = (r) => denied(r) && r.out.includes(HELD_SLOW_TEXT);
const say = (r) => `${r.answer?.permission || 'none'} status=${r.status} wall=${r.wallMs} ${r.out.replace(/\s+/g, ' ').slice(0, 200)}`;

test('FC8 BUD: the hook budget per host: only Cursor moved (9 s); Codex 2 s, Grok and Gemini 4 s, every other host 14 s', () => {
  const table = Object.fromEntries(['codex', 'cursor', 'grok', 'gemini', 'claude-code', 'windsurf', 'cline', 'other'].map((host) => [host, preToolBudgetMs(host)]));
  assert.deepEqual(table, { codex: 2_000, cursor: 9_000, grok: 4_000, gemini: 4_000, 'claude-code': 14_000, windsurf: 14_000, cline: 14_000, other: 14_000 });
  assert.ok(table.cursor + 6_000 <= 15_000, 'at least 6 s inside the 15 s hooks.json timeout');
});

test('F4: the post-tool settle budget is unchanged by the Cursor pre-tool budget: Codex and Cursor 4 s, every other host 9 s', () => {
  const table = Object.fromEntries(['codex', 'cursor', 'grok', 'gemini', 'claude-code', 'windsurf', 'cline', 'other'].map((host) => [host, settleBudgetMs(host)]));
  assert.deepEqual(table, { codex: 4_000, cursor: 4_000, grok: 9_000, gemini: 9_000, 'claude-code': 9_000, windsurf: 9_000, cline: 9_000, other: 9_000 });
});

test('FC8: non-Cursor hosts answer as before (Claude Code and Codex, a commit with three 1.2 s calls)', async () => {
  const [claude, codex] = await Promise.all([
    runHook({ host: 'claude', command: COMMIT, delays: { runtime: 1200, issue: 1200, verify: 1200 } }),
    runHook({ host: 'codex', command: COMMIT, delays: { runtime: 1200, issue: 1200, verify: 1200 } }),
  ]);
  assert.ok(allowed(claude), say(claude));
  assert.equal(claude.calls.filter((c) => c.includes('enforcement')).length, 2, 'Claude Code (14 s budget) finished all three calls');
  assert.ok(heldSlow(codex), `Codex keeps its 2 s budget: ${say(codex)}`);
});

test('FC3: Cursor commit, each server call 1.2 s (3.6 s in all): the real answer, not the slow hold (master held it)', async () => {
  const r = await runHook({ command: COMMIT, delays: { runtime: 1200, issue: 1200, verify: 1200 } });
  assert.ok(allowed(r), say(r));
  assert.equal(r.out.includes(HELD_SLOW_TEXT), false, say(r));
  assert.deepEqual(r.calls.filter((c) => c.startsWith('/v1/agent/runtime') || c.includes('enforcement')), ['/v1/agent/runtime', '/v1/agent/enforcement#issue', '/v1/agent/enforcement#verify']);
});

// Every control call also has its own transport ceiling (src/request-reliability.ts boundedTimeout: runtime 4.5 s, the others 4 s),
// which this change leaves alone: one call slower than that is cut and held at once, the 9 s budget helps several calls that are
// each under it. Both cuts end in the same held answer.
test('FC1: verify answers after 9.5 s: held with the slow text (cut by the 4 s request ceiling), never allow; a hook that started 3 s late and meets three 3 s calls still answers before its 9 s deadline', async () => {
  const [plain, late] = await Promise.all([
    runHook({ command: COMMIT, delays: { verify: 9_500 } }),
    runHook({ command: COMMIT, delays: { runtime: 3_000, issue: 3_000, verify: 3_000 }, env: { CB_START_DELAY_MS: '3000' } }),
  ]);
  for (const r of [plain, late]) {
    assert.ok(heldSlow(r), say(r));
    assert.equal(allowed(r), false, say(r));
    assert.ok(r.wallMs < HOST_LIMIT_BOUND_MS, `the answer is written before the 9 s deadline: ${say(r)}`);
  }
  assert.ok(late.wallMs > 6_500, `the control timeout was cut by the remaining hook time, not skipped: ${say(late)}`);
});

test('FC2: runtime 3 s, issue 3 s, verify 3 s (9 s in all): held with the slow text, never allow', async () => {
  const r = await runHook({ command: COMMIT, delays: { runtime: 3_000, issue: 3_000, verify: 3_000 } });
  assert.ok(heldSlow(r), say(r));
  assert.equal(allowed(r), false, say(r));
  assert.ok(r.wallMs < HOST_LIMIT_BOUND_MS, say(r));
});

test('FC4: Marrow down: the outage rules answer as before (a force push is held, a routine commit keeps the offline policy)', async () => {
  const [force, commit] = await Promise.all([
    runHook({ command: FORCE, scenario: 'down' }),
    runHook({ command: COMMIT, scenario: 'down' }),
  ]);
  assert.ok(denied(force), say(force));
  assert.match(force.out, /cannot be reached right now, so this high-risk action is held/);
  assert.equal(commit.answer.permission, 'allow', say(commit));
  assert.match(commit.out, /Marrow is offline\. This action is allowed\./);
  assert.equal(force.out.includes(HELD_SLOW_TEXT) || commit.out.includes(HELD_SLOW_TEXT), false);
  assert.ok(force.wallMs < 3_000 && commit.wallMs < 3_000, 'a refused connection answers at once');
});

test('FC5: partial or contradictory answers deny: no verified permit, a different permit id, a runtime body with no gate', async () => {
  const rows = await Promise.all([
    runHook({ command: COMMIT, scenario: 'verify-false' }),
    runHook({ command: COMMIT, scenario: 'verify-other-permit' }),
    runHook({ command: COMMIT, scenario: 'partial-runtime' }),
  ]);
  for (const r of rows) assert.ok(denied(r) && !allowed(r), say(r));
  assert.match(rows[0].out, /permit verification did not match the issued permit/);
  assert.match(rows[1].out, /permit verification did not match the issued permit/);
  assert.match(rows[2].out, /Marrow is unavailable, so this protected action was denied/);
});

test('FC6: an allowed commit is not reused for a later action in the same home: the next hook process makes its own server calls and gets its own answer', async () => {
  const world = makeHome();
  try {
    const first = await runHook({ command: COMMIT, world });
    assert.ok(allowed(first), say(first));
    const second = await runHook({ command: 'rm -rf x', scenario: 'review', world });
    assert.ok(denied(second) && !allowed(second), say(second));
    assert.ok(second.calls.includes('/v1/agent/runtime'), 'the second action asked the server itself');
  } finally { world.cleanup(); }
});

test('FC7: agent A is allowed, agent B (another key and session, no permit) gets its own server answer and is held', async () => {
  const world = makeHome();
  try {
    const a = await runHook({ command: COMMIT, world, agentId: 'cb-agent-A' });
    assert.ok(allowed(a), say(a));
    const b = await runHook({ command: COMMIT, scenario: 'review', world, agentId: 'cb-agent-B' });
    assert.ok(denied(b) && !allowed(b), say(b));
    assert.notEqual(a.key, b.key);
    assert.ok(b.calls.includes('/v1/agent/runtime'));
  } finally { world.cleanup(); }
});

test('FC9: a force push with the gate answering review_required: after 3.8 s the owner-review hold is shown (master: the slow hold) and finishes inside the 9 s deadline; after 6 s it is held as slow; never allow', async () => {
  const [near, far] = await Promise.all([
    runHook({ command: FORCE, scenario: 'review', delays: { runtime: 3_800 } }),
    runHook({ command: FORCE, scenario: 'review', delays: { runtime: 6_000 } }),
  ]);
  assert.ok(denied(near) && !allowed(near), say(near));
  assert.match(near.out, /Marrow requires owner review before this action/);
  assert.ok(near.wallMs < HOST_LIMIT_BOUND_MS, `the hold flow finishes inside the deadline: ${say(near)}`);
  assert.ok(heldSlow(far) && !allowed(far), say(far));
});

test('K1: follow-up work after the answer (owner link, status, lifecycle events on a 20 s route) stays inside the 9 s deadline and never turns the hold into an allow', async () => {
  const r = await runHook({ command: FORCE, scenario: 'review', delays: { runtime: 3_800, other: 20_000 } });
  assert.ok(denied(r) && !allowed(r), say(r));
  assert.match(r.out, /Marrow requires owner review before this action/);
  assert.ok(r.wallMs < HOST_LIMIT_BOUND_MS, say(r));
  const ok = await runHook({ command: COMMIT, delays: { other: 20_000 } });
  assert.ok(allowed(ok) && ok.wallMs < HOST_LIMIT_BOUND_MS, say(ok));
});

const PRODUCTION_GOLDEN = [
  ['kubectl --context prod delete pod x', 'high', true, 'production:deploy'],
  ['kubectl get pods && kubectl --context prod delete ns a', 'high', true, 'production:deploy'],
  ['bash -c "kubectl --context=prod delete pod x"', 'high', true, 'production:deploy'],
  ['kubectl --context staging --context prod delete pod x', 'high', true, 'production:deploy'],
  ['kubectl --context prod get pods; echo staging', 'high', true, 'production:process'],
  ['FOO=staging kubectl --context prod delete pod x', 'high', true, 'production:deploy'],
  ['git commit -m "deploy to staging only"', 'high', true, 'github:deploy'],
  [FORCE, 'high', true, 'github:review'],
];

test('FC10: production-labelled commands (chains, bash -c, repeated flags, a variable, misleading words) classify exactly as on master; with a slow gate they are held, never allowed', async () => {
  for (const [command, risk, isProtected, target] of PRODUCTION_GOLDEN) {
    const got = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    assert.deepEqual([got.risk, got.protected, got.target], [risk, isProtected, target], command);
  }
  const rows = await Promise.all(PRODUCTION_GOLDEN.slice(0, 4).map(([command]) => runHook({ command, scenario: 'review', delays: { runtime: 3_800 } })));
  for (const r of rows) assert.ok(denied(r) && !allowed(r) && /requires owner review/.test(r.out), say(r));
});

const TIMING_LINE = /^marrow-hook-timing route=(runtime|think|issue|verify|total) ms=\d+$/;

test('T1: MARROW_HOOK_TIMING is on only for exactly 1: unset, 0, true, " 1", "1 ", 01, yes and empty print nothing', async () => {
  const values = [undefined, '0', 'true', ' 1', '1 ', '01', 'yes', ''];
  const rows = await Promise.all(values.map((value) => runHook({ command: COMMIT, env: value === undefined ? {} : { MARROW_HOOK_TIMING: value } })));
  rows.forEach((r, i) => {
    assert.ok(allowed(r), say(r));
    assert.equal(r.err, '', `value ${JSON.stringify(values[i])}: stderr must be empty, got ${JSON.stringify(r.err.slice(0, 120))}`);
  });
  const on = await runHook({ command: COMMIT, env: { MARROW_HOOK_TIMING: '1' } });
  assert.match(on.err, /marrow-hook-timing route=runtime ms=\d+/);
});

test('T2: with timing on, stderr holds only fixed route names and whole milliseconds: no key, no URL, no query secret, no command text, no agent id', async () => {
  const secret = `dummy-query-${crypto.randomBytes(8).toString('hex')}`;
  const command = `git commit -m "see https://example.test/p?api_key=${secret}&x=1"`;
  const agentId = `cb-agent-${crypto.randomBytes(4).toString('hex')}`;
  const r = await runHook({ command, agentId, env: { MARROW_HOOK_TIMING: '1' } });
  assert.ok(allowed(r), say(r));
  const lines = r.err.split('\n').filter(Boolean);
  assert.ok(lines.length >= 4, r.err);
  for (const line of lines) assert.match(line, TIMING_LINE);
  assert.deepEqual(lines.map((line) => line.match(TIMING_LINE)[1]).sort(), ['issue', 'runtime', 'total', 'verify']);
  for (const needle of [r.key, secret, 'example.test', 'api_key', 'commit', agentId, 'https', 'Bearer', 'mrw']) {
    assert.equal(`${r.err}${r.out}`.includes(needle), false, `timing output must not carry ${needle === r.key ? 'the key' : needle}`);
  }
});

test('T3: timing on does not change the hook answer or the server calls: stdout and the call list equal timing off (allow, review hold, slow hold)', async () => {
  const cases = [
    { command: COMMIT },
    { command: FORCE, scenario: 'review' },
    { command: COMMIT, delays: { verify: 9_500 } },
  ];
  for (const row of cases) {
    const [off, on] = await Promise.all([runHook(row), runHook({ ...row, env: { MARROW_HOOK_TIMING: '1' } })]);
    assert.equal(on.out, off.out, `${row.command}: stdout`);
    assert.equal(on.status, off.status);
    assert.deepEqual(on.calls, off.calls, `${row.command}: the same requests`);
    assert.equal(off.err.includes('marrow-hook-timing'), false);
    assert.ok(on.err.includes('marrow-hook-timing route='), on.err);
  }
});

// ---------------------------------------------------------------- C1R1: a stderr fault drops the timing lines, never the answer
// Each row runs the same hook twice under the same stderr fault, MARROW_HOOK_TIMING unset and =1, and needs equal stdout
// bytes, exit status and (timing-on) stderr, no timing text on stdout, and timing on at most 100 ms later to the last
// stdout byte and to exit. Only a time miss is measured again (load), at most three times.
const VERIFY_HANG = { command: FORCE, delays: { verify: 60_000 } };
const ROUTINE = { command: COMMIT };
const sayF = (r) => `${r.host}/${r.fault}/${r.timing ? 'on' : 'off'} status=${r.status} signal=${r.signal} last=${r.lastOutMs} exit=${r.exitMs} out=${JSON.stringify(r.out.slice(0, 120))}`;

function pairDiff(off, on) {
  if (on.out !== off.out) return 'stdout differs';
  if (on.status !== off.status || on.signal !== off.signal) return 'exit differs';
  if (on.out.includes('marrow-hook-timing')) return 'timing text on stdout';
  // Where stderr stays readable, it holds what timing off holds plus whole timing lines at most: no uncaught error text.
  if (['throw', 'async-error'].includes(on.fault) && on.err.replace(/^marrow-hook-timing route=\w+ ms=\d+\n/gm, '') !== off.err) return 'stderr differs';
  if ((off.lastOutMs === null) !== (on.lastOutMs === null)) return 'stdout presence differs';
  if (on.lastOutMs !== null && on.lastOutMs > off.lastOutMs + 100) return 'time: last stdout byte';
  if (on.exitMs > off.exitMs + 100) return 'time: exit';
  return '';
}

async function faultPair(base, fault, arm = '') {
  let why = '';
  let pair;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const [off, on] = await Promise.all([false, true].map((timing) => runFaulted({ root: ROOT, ...base, fault, arm, timing })));
    pair = { off, on };
    why = pairDiff(off, on);
    if (!why || !why.startsWith('time')) break;
  }
  assert.equal(why, '', `${why}: ${sayF(pair.off)} | ${sayF(pair.on)}`);
  return pair;
}

/** Every fault for one host and row: the four short faults side by side, then the full pipe alone. */
async function allFaults(base) {
  const pairs = await Promise.all(FAULTS.filter((f) => f !== 'full').map((fault) => faultPair(base, fault)));
  pairs.push(await faultPair(base, 'full'));
  return pairs;
}

test('B1a-B1e: a held force push (verify hangs) stays held with timing on under every stderr fault, on Cursor, Claude Code and Codex', async () => {
  for (const host of ['cursor', 'claude', 'codex']) {
    for (const { off, on } of await allFaults({ ...VERIFY_HANG, host })) {
      assert.ok(heldSlow(on) && heldSlow(off), `held: ${sayF(on)}`);
      if (on.fault !== 'throw') assert.equal(on.status, 0, sayF(on));
    }
  }
});

test('B1b: a routine commit with a fast ok server answers as timing off under every stderr fault, on Cursor, Claude Code and Codex', async () => {
  for (const host of ['cursor', 'claude', 'codex']) {
    for (const { on } of await allFaults({ ...ROUTINE, host })) {
      if (on.fault !== 'throw') assert.ok(allowed(on), `allowed: ${sayF(on)}`);
    }
  }
});

test('B1f: the route=total exit line under a fault that starts only at exit (reader closed after the answer, a throwing or erroring write)', async () => {
  for (const host of ['cursor', 'claude', 'codex']) {
    const pairs = await Promise.all([
      faultPair({ ...ROUTINE, host }, 'epipe-after-answer'),
      faultPair({ ...ROUTINE, host }, 'throw', 'exit'),
      faultPair({ ...ROUTINE, host }, 'async-error', 'exit'),
      faultPair({ ...VERIFY_HANG, host }, 'async-error', 'exit'),
    ]);
    for (const { on } of pairs) assert.equal(on.status, 0, sayF(on));
  }
});

test('B1g: the hook\'s own stderr text (Windsurf deny with exit 2, the outage warning) is unchanged by timing under every stderr fault', async () => {
  for (const { off, on } of await allFaults({ ...VERIFY_HANG, host: 'windsurf' })) {
    if (on.fault !== 'throw') assert.equal(on.status, 2, sayF(on));
    if (on.fault === 'async-error') assert.equal(on.err, off.err);
  }
  const plain = await runFaulted({ root: ROOT, ...VERIFY_HANG, host: 'windsurf', timing: true });
  assert.ok(plain.err.includes(HELD_SLOW_TEXT) && /marrow-hook-timing route=total ms=\d+\n$/.test(plain.err), plain.err);
  for (const host of ['cursor', 'claude']) await allFaults({ command: FORCE, scenario: 'down', host });
});

test('TMO: a verify call that ignores the abort (control timeout) or whose body reader throws stays held with timing on under a stalled or closed stderr', async () => {
  const rows = [];
  for (const scenario of ['verify-hang-ignore-abort', 'verify-cut']) {
    rows.push(...await Promise.all(['none', 'epipe', 'async-error'].map((fault) => faultPair({ command: FORCE, scenario }, fault))));
    rows.push(await faultPair({ command: FORCE, scenario }, 'full'));
  }
  for (const { on } of rows) assert.ok(denied(on) && on.status === 0, sayF(on));
});
