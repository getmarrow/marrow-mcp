'use strict';
// MCP-2 T3 (A-TAMP7) and M1 (G22): the stable entry puts three things under ~/.marrow: the owner-only `runtime/current` record, the
// digest-pinned launcher `runtime/launcher/<sha256>.cjs`, and `identity-record.json`, the file the installer restores an agent id from.
// An agent write to any of them must stay held as self-protection (S0) in the keyless seatbelt and as `marrow-control` in the keyed
// hook, through every tool and shell form below: the Write/Edit tools, a redirect, `cd ... && mv`, `bash -c`, `$HOME`, `&&`, `;`, `||`,
// a pipe into `tee`, a subshell. They are all held today through the `.marrow` rule; this file pins that, so a later narrowing of the
// rule goes red. Reads (`cat` of `current`, which holds no key) stay not-S0. No source of the seatbelt changed in this PR: every row
// here is green on BASE as well (the before/after table in the result is the same rows run on both builds).
const assert = require('node:assert/strict');
const test = require('node:test');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { selfProtectKind } = require('../dist/self-protect.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const { ROWS, READS, FOREIGN, TARGETS } = require('./support/stable-entry-s0-rows.cjs');

const seatbelt = (event, platform = 'linux') => evaluateSeatbelt(event, makeEnv({ platform }));
const show = (d) => `${d.decision} ${d.rule} [${d.reasons.join(',')}]`;

test('T3/M1: every write, chain, wrapper and subshell against current, the launcher and identity-record.json is held as S0', () => {
  assert.ok(ROWS.length >= 400, `rows: ${ROWS.length}`);
  assert.deepEqual(TARGETS.map((t) => t.id), ['current', 'launcher', 'record']);
  const ids = new Set();
  for (const row of ROWS) {
    assert.ok(!ids.has(row.id), `duplicate row id ${row.id}`);
    ids.add(row.id);
    const d = seatbelt(row.event);
    assert.equal(d.decision, 'stop', `${row.id}: ${show(d)}`);
    assert.equal(d.rule, 'S0.self_protection', `${row.id}: ${show(d)}`);
  }
});

test('T3/M1: the keyed hook labels the same rows marrow-control (the account policy then holds them)', () => {
  for (const row of ROWS) assert.equal(selfProtectKind(row.event, '/home/u/proj'), 'marrow-control', row.id);
});

test('T3/M1: the same writes are held on macOS (case-folded paths) and win32 hosts, and with a case-changed .MARROW', () => {
  for (const platform of ['darwin', 'win32']) {
    for (const row of ROWS.filter((r) => /\/(redirect|mv|cp|tee)$|^[a-z]+\/(Write|Edit)$/.test(r.id)).slice(0, 80)) {
      const d = seatbelt(row.event, platform);
      assert.equal(d.decision, 'stop', `${platform} ${row.id}: ${show(d)}`);
      assert.match(d.rule, /^S0\./, `${platform} ${row.id}: ${show(d)}`);
    }
    for (const command of ['printf x > ~/.MARROW/runtime/current', 'printf x > ~/.Marrow/runtime/CURRENT', 'cp x ~/.MARROW/identity-record.json']) {
      const d = seatbelt({ tool_name: 'Bash', tool_input: { command } }, platform);
      assert.equal(d.decision, 'stop', `${platform} ${command}: ${show(d)}`);
    }
  }
});

test('T3/M3: a read-only cat of current (no key in it), the launcher or the record is not S0', () => {
  assert.ok(READS.length >= 25);
  for (const row of READS) {
    const d = seatbelt(row.event);
    assert.equal(d.decision, 'pass', `${row.id}: ${show(d)}`);
    assert.equal(selfProtectKind(row.event, '/home/u/proj'), null, `${row.id}: keyed`);
  }
});

test('T3 (UNICODE_FOLD): a homoglyph inside Marrow\'s folder is held; a look-alike folder is not Marrow\'s and is exactly as on BASE', () => {
  for (const row of ROWS.filter((r) => r.id.startsWith('homoglyph/') || r.id.startsWith('trailing-space/'))) {
    assert.equal(seatbelt(row.event).decision, 'stop', row.id);
  }
  // BASE: a different folder name is a different folder (nothing of Marrow's is written); the keyed label reads `.marrow` case-blind.
  const keyed = { 'foreign/upper-case-dir-linux': 'marrow-control' };
  for (const row of FOREIGN) {
    const d = seatbelt(row.event);
    assert.equal(d.decision, 'pass', `${row.id}: ${show(d)}`);
    assert.equal(selfProtectKind(row.event, '/home/u/proj'), keyed[row.id] ?? null, `${row.id}: keyed`);
  }
  // ... and the real folder spelled next to it is held, so a homoglyph never lifts a hold.
  assert.equal(seatbelt({ tool_name: 'Bash', tool_input: { command: 'printf x > ~/.mаrrow/x; printf y > ~/.marrow/runtime/current' } }).decision, 'stop');
});

test('T3 (SHORTCUT): a not-official verdict never lifts an S0 hold, and an official one never exempts the entry files from S0', () => {
  // The identity check (own-server-identity) and the write holds are separate: with the official stable entry configured and proven,
  // a write to the launcher and to `current` is still held; with a look-alike, it is held the same.
  const osi = require('../dist/own-server-identity.js');
  const S = require('./support/stable-entry.cjs');
  const official = osi.cursorOfficialMarrowServer({
    home: S.HOME, cwds: [S.PROJECT], processCwd: '/virtual/x', read: S.files({ [`${S.PROJECT}/.cursor/mcp.json`]: S.cursorJson(S.posixFor(S.D)) }), onlyServer: false, ownLoader: S.KNOWN,
  }).official;
  const lookalike = osi.cursorOfficialMarrowServer({
    home: S.HOME, cwds: [S.PROJECT], processCwd: '/virtual/x', read: S.files({ [`${S.PROJECT}/.cursor/mcp.json`]: S.cursorJson(S.posixFor(S.sha('x'))) }), onlyServer: false, ownLoader: S.KNOWN,
  }).official;
  assert.deepEqual([official, lookalike], [true, false]);
  for (const row of ROWS.filter((r) => /^(current|launcher)\/(Write|tilde\/redirect)$/.test(r.id))) assert.equal(seatbelt(row.event).decision, 'stop', row.id);
});
