'use strict';

// Hook data words, the one patch round (MAIN-RULING patch-hookdata): only L01, L10, L12 and D01-D23 still lower, each behind
// the ruling's proofs (B1-B4, F2); a call the tip still holds classifies byte-equal to BASE (B5); the cut shapes L02-L09 and
// L11 are BASE again. Every row is a hook INPUT; nothing is ever run. BASE answers come from the `patch` key of
// test/fixtures/hookdata/base-classification.json (recorded from cb1918f261f2 by the patch job).
const assert = require('node:assert/strict');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { localControlEvidence } = require('../dist/control-state.js');
const BASE = require('./fixtures/hookdata/base-classification.json');

const FIELDS = ['action', 'target', 'type', 'role', 'surfaces', 'risk', 'protected', 'readOnly'];
const pick = (c) => Object.fromEntries(FIELDS.map((field) => [field, c[field]]));
const bash = (row) => ({ tool_name: 'Bash', tool_input: { command: row.command, ...(row.extra || {}) } });
const rows = Object.values(BASE.patch);

test('the patch rows are recorded from BASE, and every row is held on BASE', () => {
  assert.equal(BASE.base, 'cb1918f261f2dde66dcaf29bbd1f99861bbe92f5');
  assert.ok(rows.length >= 200, String(rows.length));
  assert.equal(rows.filter((row) => row.id.startsWith('B2-audit-')).length, 101);
  for (const row of rows) assert.equal(row.pre.protected, true, row.id);
});

for (const fix of ['B1', 'B2', 'B3', 'B4', 'B5', 'F2', 'F5', 'CUT', 'KEEP']) {
  for (const row of rows.filter((item) => item.fix === fix)) {
    test(`${row.id} ${row.expect} (${row.shape})`, () => {
      const pre = pick(classifyTool(bash(row)));
      const post = pick(classifyTool(bash(row), { postTool: true }));
      if (row.expect === 'ALLOW') {
        assert.equal(pre.protected, false, `${row.id}: ${pre.action}`);
        assert.equal(post.action, pre.action, row.id);
      } else {
        assert.deepEqual(pre, row.pre, `${row.id} keeps the BASE classification`);
        assert.deepEqual(post, row.post, `${row.id} keeps the BASE PostToolUse classification`);
      }
    });
  }
}

test('B5: every held row of the hookdata fixtures classifies byte-equal to BASE', () => {
  const held = rows.filter((row) => pick(classifyTool(bash(row))).protected);
  assert.ok(held.length > 0);
  for (const row of held) assert.deepEqual(pick(classifyTool(bash(row))), row.pre, row.id);
});

test('F1: the control-disable next step names `--yes`, the form the installer accepts', () => {
  const sentence = 'The account owner runs `npx @getmarrow/install control disable --yes` in their own terminal; it asks for a confirmation code. Agents cannot turn control off.';
  const { mkdtempSync, rmSync } = require('node:fs');
  const { tmpdir } = require('node:os');
  const { join } = require('node:path');
  const home = mkdtempSync(join(tmpdir(), 'hookdata-patch-f1-'));
  const saved = process.env.HOME;
  try {
    process.env.HOME = home;
    const evidence = localControlEvidence(false);
    const control = evidence.local_control || evidence;
    assert.equal(Buffer.compare(Buffer.from(control.exact_next_action, 'utf8'), Buffer.from(sentence, 'utf8')), 0, control.exact_next_action);
  } finally {
    process.env.HOME = saved;
    rmSync(home, { recursive: true, force: true });
  }
});
