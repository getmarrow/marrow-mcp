'use strict';

// U5 finding F1: the write-target reader used one value-flag set for every program, so a boolean `-s` or
// `-r` swallowed the next word: `ln -s SRC DEST`, `cp -r SRC DEST`, `rm -r PATH`, `rsync -t SRC DEST`
// lost their write target and S0 self-protection let them through once the keyless hook passes non-S
// actions. Both readings are now checked. Rows run on the mapper with the fake host (home /home/u,
// workspace /home/u/proj) and once through the corpus gates the other seatbelt tests already run.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const sh = (cmd) => evaluateSeatbeltShell(cmd, makeEnv({}));

// A write into a protected location through a boolean flag that used to be read as taking a value.
const STOP_S0 = [
  'ln -s /bin/true ~/.local/bin/npx',
  'ln -s /bin/true /home/u/.local/bin/marrow-mcp',
  'ln -s /dev/null ~/.marrow/control.json',
  'ln -s /bin/true /usr/local/bin/npx',
  'ln -r -s /tmp/evil ~/.local/bin/git',
  'cp -r /tmp/evil ~/.marrow/control.json',
  'cp -r /tmp/evil.json ~/.claude/settings.json',
  'cp -s /tmp/evil ~/.local/bin/npx',
  'cp -r -t ~/.local/bin /tmp/evil',
  'rm -r .claude/settings.json',
  'rsync -t /tmp/evil ~/.claude/settings.json',
  'rsync -r /tmp/evil/ ~/.local/bin/',
  'install -s /tmp/evil ~/.local/bin/npx',
  'touch -m ~/.local/bin/npx',
  'scp -r host:evil ~/.local/bin/npx',
  // F2: a symbolic mode that starts with '-' is not an option.
  'chmod -r ~/.claude/settings.json',
  'chmod -w ~/.marrow/env',
  'chattr -i ~/.claude/settings.json',
];
// Ordinary uses of the same flags in the workspace or temp still pass.
const PASS = [
  'ln -s ../src/index.ts link.ts', 'cp -r src dist', 'rm -r build', 'rsync -av src/ /tmp/out/', 'rsync -t a.txt b.txt',
  'touch -m README.md', 'install -m 755 bin/tool /tmp/tool', 'cp -s a.txt b.txt', 'scp -r host:logs ./logs', 'truncate -s 0 app.log',
  'chmod -x scripts/build.sh', 'chmod 755 scripts/build.sh', 'chown -R me:me dist', 'chmod --reference README.md dist/app.js',
];

test('F1/F2: boolean -s/-r/-t/-m and a mode like -r no longer hide the write target of ln, cp, rm, rsync, install, touch, scp, chmod, chattr (S0)', () => {
  for (const cmd of STOP_S0) {
    const d = sh(cmd);
    assert.equal(d.decision, 'stop', cmd);
    assert.equal(d.category, 'S0', `${cmd}: ${d.rule} ${d.reasons.join(',')}`);
  }
  for (const cmd of PASS) assert.equal(sh(cmd).decision, 'pass', `${cmd}: ${sh(cmd).reasons.join(',')}`);
});

test('F1: the change only adds write targets: every row that stopped before still stops (value-flag readings)', () => {
  // A real value flag still consumes its value: the value is not a target, the operand after it is.
  assert.equal(sh('cp -S .bak notes.txt ~/.bashrc').decision, 'stop');
  assert.equal(sh('install -m 755 /tmp/evil ~/.local/bin/npx').decision, 'stop');
  assert.equal(sh('truncate -s 0 ~/.claude/settings.json').decision, 'stop');
  assert.equal(sh('touch -r README.md ~/.marrow/claimed').decision, 'stop');
  assert.equal(sh('ln -sf /dev/null ~/.claude/settings.json').decision, 'stop');
  assert.equal(sh('cp -R /tmp/evil ~/.local/bin/npx').decision, 'stop');
  // The old reading is kept as well: rsync -t (--times) used to read the next word as a target directory.
  assert.equal(sh('rsync -t ~/.claude/settings.json /tmp/x').decision, 'stop');
});
