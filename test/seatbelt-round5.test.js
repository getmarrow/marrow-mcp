'use strict';

// Patch round 5 (exact-final audit of 3.9.103, R4-F1, R4-F2, R4-L1, R4-L2). A fixed table, not a search for spellings:
//  item 1  env -S / --split-string with no command in the text or after it prints the whole environment: S4 env_dump_env
//  item 2  an unknown working folder (env / sudo / doas option) also stops a relative operand of a non-reader that some protected path ends with
//  item 3  zip: a -TT after a letter the scan cannot read still takes a command
//  item 4  the four rows the round-4 mutants survived (attached env -CDIR, attached sudo -DDIR, nested wrapper keeps the strict folder, sudo value long option)
// The same forms run through the real hook CLI on the 7 host paths in seatbelt-round5-hook.test.js; the table rows of item 2 and 3
// are also in test/support/long-options-table.cjs (three forms on three targets).
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const { FILES, DIRS, TARGETS } = require('./support/long-options-table.cjs');

const sh = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ files: FILES, dirs: DIRS }));
const dump = (d) => d.decision === 'stop' && d.hits.some((h) => h.category === 'S4') && d.reasons.some((r) => r === 'env_dump_env');
const s0operand = (d) => d.decision === 'stop' && d.hits.some((h) => h.category === 'S0') && d.reasons.some((r) => r.startsWith('protected_path_operand'));

test('R4-F1: env -S / --split-string with no command prints the environment and stops (S4 env_dump_env), as plain env does', () => {
  // the exact and attached spellings the audit found, and the older forms that were never stopped
  for (const c of ['env --split-string=', 'env --split-string="FOO=1"', 'env -SFOO=1', "env -S ''", 'env -S "FOO=1"', 'env -S "FOO=1 BAR=2"', "env --split-string ''", 'env -S "-u FOO"', 'env -S "--chdir=/tmp"',
    "env -S '#node app.js'", 'env -S "FOO=1" BAR=2', 'env FOO=1 -S ""', 'env -u FOO -S ""']) {
    assert.ok(dump(sh(c)), `${c}: ${sh(c).reasons}`);
  }
  // the control and the two other spellings of the option (first 4 letters and made up) reach the plain env rule
  for (const c of ['env', 'env --spli=', 'env --spli="FOO=1"', 'env --zz-unknown', 'env --zz-unknown=1']) assert.ok(dump(sh(c)), `${c}: ${sh(c).reasons}`);
});

test('R4-F1: -i, --ignore-environment or a lone - clears the environment, a command word makes it a command: these pass', () => {
  for (const c of ["env -i -S ''", 'env -i -S "FOO=1"', "env --ignore-environment --split-string=", "env - -S 'FOO=1'", 'env -S "-i"', 'env -S "FOO=1 -i"', "env -S '' -i", 'env -i -u X -S ""',
    'env -S "FOO=1 node app.js"', 'env --split-string="NODE_ENV=prod npm start"', 'env -SFOO=1\\ node', "env -S 'FOO=1' node app.js", "env -S '' node app.js", 'env -S "FOO=1" "$CMD"',
    'env -S "env -i"', 'env -S "-u FOO ls"', 'env --split-string="--chdir=/tmp ls"']) {
    const d = sh(c);
    assert.ok(!dump(d), `${c}: ${d.reasons}`);
  }
  // nothing else about the command changed: only the dump rule is new
  for (const c of ['env -S "FOO=1 node app.js"', 'env --split-string="NODE_ENV=prod npm start"', "env -S '' node app.js"]) assert.equal(sh(c).decision, 'pass', c);
  // `env -i env` is an old stop (the inner env does not inherit the clearing -i); this round neither adds nor lifts it
  assert.ok(dump(sh('env -i env')));
});

test('R4-F1 (abuse rows): chains, pipes, subshells, shells, wrappers, repeated flags, variables and misleading words', () => {
  for (const c of ["true && env -S ''", "false || env --split-string=", "ls; env -S 'FOO=1'", "env -S '' | head -1", "(env -S '')", "bash -c \"env -S ''\"", "sh -c 'env --split-string=FOO=1'",
    "sudo env -S ''", "env env -S ''", "env FOO=1 env -S ''", "env -S 'FOO=1' ; echo x", "echo x | sudo env --split-string=", "timeout 5 env -S ''",
    // repeated flags: a clearing option BEFORE the text counts, one that comes after another -S text in a later env does not rescue this one
    "env -S '' -S 'BAR=1'", "env -S 'FOO=1' -S ''"]) {
    assert.ok(dump(sh(c)), `${c}: ${sh(c).reasons}`);
  }
  // -i anywhere in the words of the same env clears it, also across repeated -S texts
  assert.ok(!dump(sh("env -i -S '' -S ''")));
  assert.ok(!dump(sh("env -S '' -S '-i'")));
  // variables and misleading words: text only, or a dynamic word that env would expand itself
  for (const c of ["echo env -S ''", 'echo "env --split-string="', "git commit -m \"env -S ''\"", "printf '%s' 'sudo env -S FOO=1'", 'env -S "$TEXT"', 'X=1; env -S "$X" ls']) {
    assert.ok(!dump(sh(c)), `${c}: ${sh(c).reasons}`);
  }
});

test('R4-F2: under an unknown working folder a relative operand that a protected path ends with stops (S0 protected_path_operand); the three option forms, 3 targets', () => {
  for (const t of TARGETS) {
    for (const c of [
      `env --chdir=${t.PN} vim ${t.N}`, `env --chdi=${t.PN} vim ${t.N}`, `env --zz-unknown=${t.PN} vim ${t.N}`, `env --zz-unknown vim ${t.N}`,
      `sudo --chdir=${t.PN} vim ${t.N}`, `sudo --chdi=${t.PN} vim ${t.N}`, `sudo --zz-unknown vim ${t.N}`, `doas --chdir=${t.PN} vim ${t.N}`, `doas --chdi=${t.PN} vim ${t.N}`, `doas --zz-unknown vim ${t.N}`,
      `env -C "$D" vim ${t.N}`, `env --chdir "$D" node tool.js ${t.N}`, `sudo -D "$D" python3 tool.py ${t.N}`, `sudo --chdir "$D" vim -es -c '%d|x' ${t.N}`,
      // chains, pipes, subshells and shells
      `true && env --zz-unknown vim ${t.N}`, `false || sudo --zz-unknown vim ${t.N}`, `ls; env --zz-unknown vim ${t.N}`, `echo x | sudo --zz-unknown vim ${t.N}`, `(env --zz-unknown vim ${t.N})`,
      `bash -c 'env --zz-unknown vim ${t.N}'`, `sh -c "sudo --chdi=${t.PN} vim ${t.N}"`, `env --zz-unknown bash -c 'vim ${t.N}'`, `env --zz-unknown sh -c 'node tool.js ${t.N}'`,
      // nested wrappers
      `env --zz-unknown sudo --user=root vim ${t.N}`, `sudo --zz-unknown env FOO=1 vim ${t.N}`, `env --zz-unknown env -C sub vim ${t.N}`, `sudo -D "$D" env --unset=FOO node tool.js ${t.N}`,
      // repeated flags: an unlisted option after a readable chdir makes the folder unknown again; a variable after one too
      `env --chdir=/tmp/p5-work --chdi=${t.PN} vim ${t.N}`, `env --chdir=/tmp/p5-work --zz-unknown vim ${t.N}`, `sudo --chdir=/tmp/p5-work -D "$D" vim ${t.N}`,
      // variables for the folder
      `D=${t.PN}; env -C $D vim ${t.N}`, `P=--zz-unknown; env $P vim ${t.N}`,
      // the file part inside an option value
      `env --zz-unknown vim --cmd=${t.N}`,
    ]) {
      const d = sh(c);
      assert.ok(s0operand(d), `${c}: ${d.decision} ${d.reasons}`);
    }
    // a readable chdir to a folder that is not protected is the folder the command runs in (last one wins): it passes
    for (const c of [`env --zz-unknown --chdir=/tmp/p5-work vim ${t.N}`, `sudo --zz-unknown -D /tmp/p5-work vim ${t.N}`, `env --chdir=/tmp/p5-work vim ${t.N}`, `sudo --user=www node server.js ${t.N}`,
      `env --chdir=/tmp/p5-work -C "$D" --chdir=/tmp/p5-other vim ${t.N}`]) {
      assert.equal(sh(c).decision, 'pass', `${c}: ${sh(c).reasons}`);
    }
    // misleading words: only text
    for (const c of [`echo env --zz-unknown vim ${t.N}`, `git commit -m "sudo --chdi=${t.PN} vim ${t.N}"`, `printf '%s' "env -C $D vim ${t.N}"`, `echo cd ${t.PN} '&&' vim ${t.N}`]) {
      assert.equal(sh(c).decision, 'pass', `${c}: ${sh(c).reasons}`);
    }
  }
});

test('R4-F2: readers keep their behaviour, and ordinary commands with an unknown folder keep passing (friction, non-protected names)', () => {
  for (const c of [
    // readers are not judged by the operand rule
    'env --zz-unknown cat settings.json', 'sudo --zz-unknown head plugins/installed_plugins.json', 'doas --zz-unknown grep x settings.json', 'env -C "$D" less settings.json',
    // the brief's friction rows (non-protected paths)
    'env --chdir=/tmp vim notes.txt', 'sudo --user=www node server.js', 'cd /tmp && vim plugins/installed_plugins.json', 'cd /tmp && vim settings.json',
    // an unknown folder with a name no protected path ends with
    'env --zz-unknown vim notes.txt', 'sudo --zz-unknown node server.js', 'sudo --zz-unknown systemctl restart nginx', 'env -C "$D" npm test', 'sudo -D "$D" make install', 'doas --zz-unknown vim src/app.ts',
    'env --zz-unknown python3 -m pytest tests/', 'env -C "$D" git status', 'sudo --zz-unknown tar czf out.tgz src',
    // absolute operands are judged as before, whatever the folder
    'env --zz-unknown vim /tmp/p5-notes.txt', 'sudo --zz-unknown node /tmp/p5-tool.js',
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
  // and the known-folder form still resolves a relative operand the way it always did
  assert.ok(s0operand(sh(`cd ${TARGETS[0].PN} && vim ${TARGETS[0].N}`)));
});

test('R4-L1: zip -TT after a letter the scan cannot read still takes a command (read by meaning, as -TT is)', () => {
  const cd = 'cd ~/.claude && rm settings.json';
  for (const c of [`zip /tmp/p5.zip /tmp/p5-in -T -mTT "${cd}"`, `zip /tmp/p5.zip /tmp/p5-in -T -mTT="${cd}"`, `zip /tmp/p5.zip /tmp/p5-in -T -mTT'${cd}'`, `zip /tmp/p5.zip /tmp/p5-in -T -m -TT "${cd}"`,
    `zip /tmp/p5.zip /tmp/p5-in -T -ATT "${cd}"`, `zip /tmp/p5.zip /tmp/p5-in -mrTT "${cd}"`, `true && zip /tmp/p5.zip /tmp/p5-in -T -mTT "${cd}"`, `sudo zip /tmp/p5.zip /tmp/p5-in -T -mTT "${cd}"`,
    `bash -c 'zip /tmp/p5.zip /tmp/p5-in -T -mTT "${cd}"'`, `(zip /tmp/p5.zip /tmp/p5-in -T -mTT "${cd}")`]) {
    const d = sh(c);
    assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
    assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
  }
  // a command without a protected target, and the zip rows of earlier rounds, keep their answer
  for (const c of ['zip /tmp/p5.zip /tmp/p5-in -T -mTT "unzip -tqq /tmp/p5.zip"', 'zip /tmp/p5.zip /tmp/p5-in -T -TT "unzip -tqq"', 'zip -rq out.zip src', 'zip -m out.zip src', 'zip -r -ds 1m out.zip src']) assert.equal(sh(c).decision, 'pass', c);
  // misleading words
  assert.equal(sh(`echo "zip a.zip b -mTT '${cd}'"`).decision, 'pass');
});

test('R4-L2: the rows the four surviving mutants of the audit are killed by', () => {
  for (const t of TARGETS) {
    // attached env -CDIR and attached sudo -DDIR read the folder (a known protected folder: the relative destination resolves into it)
    for (const c of [`env -C${t.PA} cp /tmp/p5-x ${t.F}`, `sudo -D${t.PA} cp /tmp/p5-x ${t.F}`, `env -C${t.PN} vim ${t.N}`, `sudo -D${t.PN} vim ${t.N}`]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
    }
    // the same attached options with a folder that is not protected pass
    for (const c of ['env -C/tmp/p5-work cp a b', 'sudo -D/tmp/p5-work cp a b']) assert.equal(sh(c).decision, 'pass', c);
    // a nested wrapper keeps the strict folder of the outer one (a relative chdir inside an unknown folder is still unknown)
    for (const c of [`env --zz-unknown env -C sub cp /tmp/p5-x ${t.F}`, `sudo --zz-unknown env --chdir=sub cp /tmp/p5-x ${t.F}`, `env -C "$D" sudo -D sub cp /tmp/p5-x ${t.F}`, `env --zz-unknown env --unset=FOO cp /tmp/p5-x ${t.F}`]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.reasons.some((r) => /^cp_write_protected_path$/.test(r)), `${c}: ${d.reasons}`);
    }
    // an absolute chdir inside an unknown folder is known again
    assert.equal(sh('env --zz-unknown env -C /tmp/p5-work cp a b').decision, 'pass');
    // a listed sudo option that takes a value consumes its word: the command is cp (writer code), not the value word
    for (const c of [`sudo --role r cp /tmp/p5-x ${t.T}`, `sudo --type t cp /tmp/p5-x ${t.T}`, `sudo --chroot=/c --role r cp /tmp/p5-x ${t.T}`]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.reasons.some((r) => /^cp_write_protected_path$/.test(r)), `${c}: the value word must not be read as the command: ${d.reasons}`);
    }
  }
  // an ordinary command after the same option passes (the value word is consumed, not run)
  assert.equal(sh('sudo --role r cp /tmp/p5-a /tmp/p5-b').decision, 'pass');
});
