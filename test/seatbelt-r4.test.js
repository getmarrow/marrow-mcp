'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const os = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

// Patch round 4 for Barvis's final delta audit of ecd0d1a6 (F1, F2, F3, L4).
// One structural rule instead of more variants: a resolver gives a DEFINITE
// answer only when every construct in the input is on a short allowlist;
// anything unusual (control characters, anything that can change what runs or
// where) is `other` / `unknown` / `dynamic`. The audit's own rows are in
// seatbelt-audit-final.test.js; these add the class variants and the oracle.

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { nodeSeatbeltFs } = require('../dist/seatbelt-fs.js');
const S = require('../dist/seatbelt-scripts.js');

const nfs = nodeSeatbeltFs();
const ROOT = fsn.realpathSync(fsn.mkdtempSync(join(os.tmpdir(), 'seatbelt-r4-')));
let counter = 0;
const fresh = () => {
  const dir = join(ROOT, `d${counter++}`);
  fsn.mkdirSync(dir, { mode: 0o700 });
  return dir;
};
test.after(() => fsn.rmSync(ROOT, { recursive: true, force: true }));

// ---------------------------------------------------------------- F1: shebang

const script = (text) => S.readScriptFile(createFakeFs().file('/s/x.sh', text), '/s/x.sh');
/** Never a definite shell: `unknown`, or `other`. */
const notShell = (r) => r.status !== 'ok' || r.interpreter !== 'shell';

test('F1: a control character anywhere in the shebang line is never `shell` (CR, VT, FF, NUL, DEL, ESC, non-ASCII)', () => {
  const lines = [
    '#!/bin/bash\r', '#!/bin/sh\r', '#!/opt/homebrew/bin/bash\r', '#!/usr/local/bin/bash\r', '#!/usr/bin/env bash\r',
    '#!/bin/bash -e\r', '#!/bin/bash\v', '#!/bin/bash\f', '#!/bin/bash\0', '#!/bin/bash\x7f', '#!/bin/bash\x1b', '#!/bin/bash \r-e',
    '#!/usr/bin/env -S bash\r-c "echo PAYLOAD_RAN"', '#!/usr/bin/env -S bash -e\r-c "echo PAYLOAD_RAN"', '#!/usr/bin/env -S bash\r./planted.sh',
    '#!/usr/bin/env -S bash\rBASH_ENV=x', '#!/usr/bin/env -S bash\v-c "echo PAYLOAD_RAN"', '#!/usr/bin/env -S bash\f-c "echo PAYLOAD_RAN"',
    '#!/usr/bin/env\r-S bash', '#!/usr/bin/env -S\rbash', '#!/usr/bin/env -S bash -e\r', '#!/bin/bash ', '#!/bin/bash -c', '#!/bin/bash -e\u0085',
    '#!/usr/bin/env python3\r', '#!/usr/bin/python3\r',
  ];
  for (const line of lines) assert.ok(notShell(script(`${line}\necho body\n`)), JSON.stringify(line));
  // The plain forms the audit named are `other` (a definite non-shell), not `unknown`.
  for (const line of ['#!/bin/bash\r', '#!/opt/homebrew/bin/bash\r', '#!/usr/bin/env bash\r', '#!/bin/bash -e\r']) {
    const r = script(`${line}\necho body\n`);
    assert.equal(r.status, 'ok', JSON.stringify(line));
    assert.equal(r.interpreter, 'other', JSON.stringify(line));
  }
});

test('F1: the line is cut at \\n only: CR-split env -S payloads are seen as the command that runs', () => {
  const split = script('#!/usr/bin/env -S bash\r-c "echo PAYLOAD_RAN"\necho body\n');
  assert.equal(split.status, 'ok');
  assert.equal(split.interpreter, 'other');
  assert.equal(split.shebangCommand, 'echo PAYLOAD_RAN');
  const flagged = script('#!/usr/bin/env -S bash -e\r-c "echo PAYLOAD_RAN"\necho body\n');
  assert.equal(flagged.interpreter, 'other');
  assert.equal(flagged.shebangCommand, 'echo PAYLOAD_RAN');
  // A cwd file named after the CR is an operand the shebang runs: unknown, as for any operand.
  assert.deepEqual(script('#!/usr/bin/env -S bash\r./planted.sh\necho body\n'), { status: 'unknown', reason: 'shebang' });
  // Nothing may hide in the part after a CR: it is part of the line.
  assert.ok(notShell(script('#!/bin/sh\recho hi')));
  assert.ok(notShell(script('#!/bin/sh\r')));
});

test('F1: a line that was `unknown` stays `unknown` when it also has a control character (never looser)', () => {
  for (const line of ['#!./bash\r', '#!/usr/bin/env -S BASH_ENV=./evil.sh bash\r', '#!/home/u/proj/bin/bash\r', '#!/usr/bin/env -C /tmp bash\r', '#!/bin/bash -i\r', '#!/usr/bin/env -S bash -c\r']) {
    assert.deepEqual(script(`${line}\necho body\n`), { status: 'unknown', reason: 'shebang' }, JSON.stringify(line));
  }
});

test('F1: the allowlist: plain LF forms stay `shell`; tab is allowed', () => {
  for (const line of ['#!/bin/sh', '#!/bin/bash', '#! /bin/bash -e', '#!/usr/bin/env bash', '#!/usr/bin/env -S bash -e', '#!/bin/bash\t-e', '#!/usr/bin/env\tbash', '#!/usr/bin/env -u X bash', '#!/usr/bin/env -i bash', '#!/usr/bin/env -S bash -euo pipefail']) {
    assert.equal(script(`${line}\necho body\n`).interpreter, 'shell', JSON.stringify(line));
  }
  assert.equal(script('echo no shebang\n').interpreter, 'shell');
  assert.equal(script('').interpreter, 'shell');
  // A later line may hold anything: only the first line decides.
  assert.equal(script('#!/bin/bash\necho a\rb\n').interpreter, 'shell');
});

test('F1: a first line longer than the kernel is sure to read whole is never `shell`', () => {
  const padded = `#!/bin/bash ${'-e '.repeat(60)}`;
  assert.ok(padded.length > 127);
  assert.ok(notShell(script(`${padded}\necho body\n`)));
  const edge = `#!/bin/bash${' '.repeat(127 - '#!/bin/bash'.length - 3)} -e`;
  assert.equal(edge.length, 127);
  assert.equal(script(`${edge}\necho body\n`).interpreter, 'shell');
  assert.ok(notShell(script(`${edge} \necho body\n`.replace(' \n', '  \n'))));
});

test('F1: env options off the allowlist (-0, -v, --null, --debug) are never `shell`; -i, -u, -S, - stay', () => {
  for (const line of ['#!/usr/bin/env -0 bash', '#!/usr/bin/env -v bash', '#!/usr/bin/env --null bash', '#!/usr/bin/env --debug bash', '#!/usr/bin/env -vS bash -e', '#!/usr/bin/env -S -v bash', '#!/usr/bin/env -iv bash']) {
    const r = script(`${line}\necho body\n`);
    assert.equal(r.status, 'ok', line);
    assert.equal(r.interpreter, 'other', line);
  }
  const withCommand = script('#!/usr/bin/env -vS bash -c "echo PAYLOAD_RAN"\necho body\n');
  assert.equal(withCommand.interpreter, 'other');
  assert.equal(withCommand.shebangCommand, 'echo PAYLOAD_RAN');
  for (const line of ['#!/usr/bin/env -i bash', '#!/usr/bin/env - bash', '#!/usr/bin/env --ignore-environment bash', '#!/usr/bin/env -u X bash', '#!/usr/bin/env --unset=X bash', '#!/usr/bin/env -S bash -e', '#!/usr/bin/env --split-string=bash']) {
    assert.equal(script(`${line}\necho body\n`).interpreter, 'shell', line);
  }
});

test('F1: a control character produced by an env -S escape is never `shell`', () => {
  // `\r`, `\t`, `\f` ... inside the split string become characters of a word, not blanks.
  for (const line of ['#!/usr/bin/env -S -u "X\\r" bash', "#!/usr/bin/env -S -u 'X' -u \"Y\\f\" bash -e", '#!/usr/bin/env -S -u X\\tY bash']) {
    const r = script(`${line}\necho body\n`);
    assert.ok(notShell(r), line);
  }
});

test('F1: no shebang: binary magic or control characters in the first line are not a shell script', () => {
  for (const text of ['\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0>\0\x01\0\0\0', 'MZ\x90\0\x03\0\0\0\x04\0\0\0', '\xcf\xfa\xed\xfe\x07\0\0\x01', 'touch x\r\necho hi\r\n', 'echo a\0b\n']) {
    const r = script(text);
    assert.equal(r.status, 'ok', JSON.stringify(text));
    assert.equal(r.interpreter, 'other', JSON.stringify(text));
  }
  // UTF-8 text, a BOM and tabs are ordinary text.
  assert.equal(script('# café\necho hi\n').interpreter, 'shell');
  assert.equal(script('﻿#!/bin/sh\necho hi\n').interpreter, 'shell');
  assert.equal(script('echo\thi\n').interpreter, 'shell');
});

// F1 oracle: the real kernel and coreutils `env -S`, with a harmless payload (touch a marker in a fresh dir).
const envSplitSupported = process.platform === 'linux' && spawnSync('/usr/bin/env', ['-S', 'true']).status === 0;
test('F1 oracle: where the kernel + env really run the payload, the resolver never says `shell`', { skip: !envSplitSupported && 'needs Linux and coreutils env -S' }, () => {
  const rows = {
    S_CR_bash_c: { text: '#!/usr/bin/env -S bash\r-c "touch @MARKER@"\necho body\n', ran: true },
    S_CR_bash_e_c: { text: '#!/usr/bin/env -S bash -e\r-c "touch @MARKER@"\necho body\n', ran: true },
    S_CR_planted: { text: '#!/usr/bin/env -S bash\r./planted.sh\necho body\n', ran: true, planted: true },
    S_VT_bash_c: { text: '#!/usr/bin/env -S bash\v-c "touch @MARKER@"\necho body\n', ran: true },
    S_FF_bash_c: { text: '#!/usr/bin/env -S bash\f-c "touch @MARKER@"\necho body\n', ran: true },
    vS_bash_c: { text: '#!/usr/bin/env -vS bash -c "touch @MARKER@"\necho body\n', ran: true },
    plain_CR: { text: '#!/bin/bash\r\ntouch @MARKER@\r\n', ran: false },
    env_bash_CR: { text: '#!/usr/bin/env bash\r\ntouch @MARKER@\r\n', ran: false },
    LF_bash: { text: '#!/bin/bash\ntouch @MARKER@\n', ran: true, shell: true },
    LF_env_S: { text: '#!/usr/bin/env -S bash -e\ntouch @MARKER@\n', ran: true, shell: true },
  };
  for (const [name, row] of Object.entries(rows)) {
    const dir = fresh();
    const marker = join(dir, 'MARKER');
    const file = join(dir, 'x.sh');
    fsn.writeFileSync(file, row.text.split('@MARKER@').join(marker), { mode: 0o755 });
    if (row.planted) fsn.writeFileSync(join(dir, 'planted.sh'), `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o755 });
    spawnSync(file, [], { cwd: dir, env: { PATH: '/usr/bin:/bin' }, timeout: 5000 });
    assert.equal(fsn.existsSync(marker), row.ran, `${name}: oracle`);
    const r = S.readScriptFile(nfs, file);
    if (row.shell) assert.equal(r.interpreter, 'shell', name);
    else assert.ok(notShell(r), `${name}: ${JSON.stringify(r.status === 'ok' ? r.interpreter : r)}`);
  }
});
