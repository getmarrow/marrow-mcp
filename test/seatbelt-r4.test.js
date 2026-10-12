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

// ---------------------------------------------------------------- Makefile helpers

const make = (text, targets = ['all'], options = {}) => S.resolveMakeTargets(createFakeFs().file('/m/Makefile', text), '/m', targets, options);
const definite = (r) => r.status === 'ok' && !r.dynamic;
/** The environment of a clean developer shell (what the caller of the resolver states). */
const ENV = { PATH: '/usr/bin:/bin', HOME: '/home/u' };

// GNU make as the oracle: `make -n` and a real run with harmless payloads (a marker file, an echoed variable).
// Set SEATBELT_ORACLE_MAKE to a GNU make binary, or have `make` on PATH; otherwise the oracle rows are skipped.
function findMake() {
  for (const candidate of [process.env.SEATBELT_ORACLE_MAKE, 'make', 'gmake']) {
    if (!candidate) continue;
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (probe.status === 0 && /GNU Make/.test(probe.stdout)) return candidate;
  }
  return null;
}
const MAKE_BINARY = findMake();
const oracleSkip = MAKE_BINARY === null && 'GNU make not available (set SEATBELT_ORACLE_MAKE)';

/**
 * Row: { name, makefile, files, overrides, env (null = empty), targets, badOutput }.
 * `@DIR@` is the row's directory; `RISKY` stands for a deploy command. Hazard:
 * the real run created the marker, printed `badOutput`, or ran a RISKY command
 * the resolver did not list. The resolver must then not give a definite answer;
 * when it does, its command list must equal `make -n`.
 */
function checkAgainstMake(rows) {
  const strip = (command) => command.replace(/^[\s@+-]+/, '').trim().split(MAKE_BINARY).join('make');
  const failures = [];
  for (const row of rows) {
    const dir = fresh();
    const sub = (text) => text.split('@DIR@').join(dir);
    fsn.mkdirSync(join(dir, 'tools'));
    fsn.writeFileSync(join(dir, 'Makefile'), sub(row.makefile));
    fsn.writeFileSync(join(dir, 'evil.sh'), `#!/bin/sh\n/usr/bin/touch "${dir}/MARKER"\n`, { mode: 0o755 });
    fsn.copyFileSync(join(dir, 'evil.sh'), join(dir, 'tools', 'git'));
    for (const [name, text] of Object.entries(row.files || {})) {
      fsn.mkdirSync(join(dir, name, '..'), { recursive: true });
      fsn.writeFileSync(join(dir, name), sub(text));
    }
    const overrides = Object.fromEntries(Object.entries(row.overrides || {}).map(([k, v]) => [k, sub(v)]));
    const targets = row.targets || ['all'];
    const env = row.env === null ? {} : { PATH: '/usr/bin:/bin', ...(row.env || {}) };
    const args = [...Object.entries(overrides).map(([k, v]) => `${k}=${v}`), ...targets];
    // stdin is /dev/null: bash reads BASH_ENV only when stdin is not a socket (Node's own pipes are sockets).
    const run = (extra) => spawnSync(MAKE_BINARY, [...extra, ...args], { cwd: dir, env, encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
    const dry = run(['-n']);
    const real = run([]);
    const hazard = fsn.existsSync(join(dir, 'MARKER')) || (row.badOutput !== undefined && real.stdout.includes(row.badOutput));
    const resolver = S.resolveMakeTargets(nfs, dir, targets, { overrides, ...(row.omitEnv ? {} : { env }) });
    if (!(resolver.status === 'ok' && !resolver.dynamic)) continue;
    if (hazard) failures.push(`${row.name}: definite answer while make changed what runs`);
    else if (/RISKY/.test(real.stdout) && !resolver.commands.some((c) => /RISKY/.test(c))) failures.push(`${row.name}: definite answer without the RISKY command make ran`);
    else if (!row.subMake) {
      const listed = dry.stdout.split('\n').filter(Boolean).map(strip);
      if (JSON.stringify(resolver.commands.map(strip)) !== JSON.stringify(listed)) failures.push(`${row.name}: resolver ${JSON.stringify(resolver.commands)} vs make -n ${JSON.stringify(listed)}`);
    }
  }
  assert.deepEqual(failures, []);
}

// ---------------------------------------------------------------- F2: command-line overrides

test('F2: an override of an execution variable, a dot-name or a name make reads at start-up is dynamic', () => {
  const makefile = 'all:\n\techo hello\n';
  const names = {
    SHELL: './evil.sh', MAKEFLAGS: '-f evil.mk', MAKEFILES: 'evil.mk', '.SHELLFLAGS': '-c "echo PAYLOAD_RAN; :"', VPATH: '/tmp',
    '.DEFAULT_GOAL': 'other', '.RECIPEPREFIX': '>', '.ONESHELL': '1', '.VARIABLES': 'x', '.X': 'y', MAKE: './evil', MFLAGS: '-f x', GNUMAKEFLAGS: '-f x',
    MAKEOVERRIDES: 'x', MAKELEVEL: '0', MAKE_COMMAND: './evil', MAKECMDGOALS: 'deploy', CURDIR: '/tmp',
  };
  for (const [name, value] of Object.entries(names)) {
    const r = make(makefile, ['all'], { overrides: { [name]: value }, env: ENV });
    assert.ok(!definite(r), `${name}=${value}: ${JSON.stringify(r)}`);
  }
});

test('F2: SHELL on the command line is understood only for a plain system shell, exactly', () => {
  const makefile = 'all:\n\techo hello\n';
  for (const shell of ['/bin/sh', '/bin/bash', '/usr/bin/bash', '/usr/local/bin/zsh', '/bin/dash']) {
    const r = make(makefile, ['all'], { overrides: { SHELL: shell }, env: ENV });
    assert.ok(definite(r), `${shell}: ${JSON.stringify(r)}`);
    assert.deepEqual(r.commands, ['echo hello']);
  }
  for (const shell of [' /bin/sh', '/bin/sh ', '/bin/sh -x', './sh', 'sh', '/tmp/evil/sh', '/bin/sh\n', '$(HOME)/sh', '/bin/bash -c', '', '/opt/x/bin/bash']) {
    assert.ok(!definite(make(makefile, ['all'], { overrides: { SHELL: shell }, env: ENV })), JSON.stringify(shell));
  }
});

test('F2: a command-line value with `$` or a control character is dynamic even when nothing uses it (make expands exported values for every recipe)', () => {
  const makefile = 'all:\n\techo hello\n';
  for (const value of ['$(shell touch x)', '${shell touch x}', '$(eval X=1)', '$X', '$$', 'a$', '$(HOME)/x', 'a\nb', 'a\tb', 'a\0b', 'a\rb']) {
    assert.ok(!definite(make(makefile, ['all'], { overrides: { X: value }, env: ENV })), JSON.stringify(value));
  }
  // The same value on a name the Makefile uses is still not definite: the exported copy is expanded too.
  assert.ok(!definite(make('X = a\nall:\n\techo $(X)\n', ['all'], { overrides: { X: '$(shell touch x)' }, env: ENV })));
});

test('F2: a command-line name the Makefile never mentions is dynamic (it can only act through the recipes\' environment)', () => {
  const makefile = 'all:\n\techo hello\n';
  for (const name of ['GOFLAGS', 'RUSTFLAGS', 'CARGO_HOME', 'FOO', 'STAGE', 'A B', '1X', '', 'x=y']) {
    assert.ok(!definite(make(makefile, ['all'], { overrides: { [name]: 'v' }, env: ENV })), JSON.stringify(name));
  }
  // Used by the file: referenced in a recipe, a prerequisite, a name, or assigned (command line wins).
  const used = {
    recipe: 'all:\n\techo $(STAGE)\n',
    braces: 'all:\n\techo ${STAGE}\n',
    prerequisite: 'all: $(STAGE)\nproduction:\n\techo p\n',
    assigned: 'STAGE = dev\nall:\n\techo hello\n',
    optional: 'STAGE ?= dev\nall:\n\techo hello\n',
    appended: 'STAGE += x\nall:\n\techo hello\n',
    override: 'override STAGE = dev\nall:\n\techo hello\n',
  };
  for (const [name, text] of Object.entries(used)) {
    const r = make(text, ['all'], { overrides: { STAGE: 'production' }, env: ENV });
    assert.ok(definite(r), `${name}: ${JSON.stringify(r)}`);
  }
});

test('F2: a plain override still reaches the recipes and the followed sub-make (visible in the command list)', () => {
  const r = make('STAGE = dev\nship:\n\twrangler deploy --env $(STAGE)\n', ['ship'], { overrides: { STAGE: 'production' }, env: ENV });
  assert.ok(definite(r));
  assert.deepEqual(r.commands, ['wrangler deploy --env production']);
  const sub = make('STAGE = dev\nall:\n\t$(MAKE) deploy\ndeploy:\n\tvercel --env $(STAGE)\n', ['all'], { overrides: { STAGE: 'production' }, env: ENV });
  assert.ok(definite(sub));
  assert.ok(sub.commands.some((c) => /--env production/.test(c)));
  // A hazard override still stops the sub-make.
  assert.ok(!definite(make('all:\n\t$(MAKE) deploy\ndeploy:\n\techo d\n', ['all'], { overrides: { SHELL: './evil.sh' }, env: ENV })));
});

test('F2 oracle: GNU make runs the payload / reads the extra file where the resolver must not be definite', { skip: oracleSkip }, () => {
  checkAgainstMake([
    { name: 'SHELL=./evil.sh', makefile: 'all:\n\techo hello\n', overrides: { SHELL: './evil.sh' } },
    { name: 'SHELL=/bin/sh', makefile: 'all:\n\techo hello\n', overrides: { SHELL: '/bin/sh' } },
    { name: 'MAKEFLAGS', makefile: 'all:\n\techo hello\n', overrides: { MAKEFLAGS: '-f evil.mk' }, files: { 'evil.mk': 'all:\n\techo RISKY\n' } },
    { name: 'MAKEFILES', makefile: 'all:\n\techo hello\n', overrides: { MAKEFILES: 'evil.mk' }, files: { 'evil.mk': 'all: deploy\ndeploy:\n\techo RISKY\n' } },
    { name: '.SHELLFLAGS', makefile: 'all:\n\techo hello\n', overrides: { '.SHELLFLAGS': '-c "touch @DIR@/MARKER; :"' } },
    { name: 'VPATH', makefile: 'all: gen\n\techo hello\ngen:\n\techo gen\n', overrides: { VPATH: '@DIR@/vp' }, files: { 'vp/gen': 'x\n' } },
    { name: '.DEFAULT_GOAL', makefile: 'all:\n\techo all\nother:\n\techo RISKY\n', overrides: { '.DEFAULT_GOAL': 'other' }, targets: [] },
    { name: 'PATH', makefile: 'all:\n\tgit status\n', overrides: { PATH: './tools' } },
    { name: 'BASH_ENV', makefile: 'SHELL := /bin/bash\nall:\n\t@echo hi; true\n', overrides: { BASH_ENV: '@DIR@/evil.sh' } },
    { name: 'unused function value', makefile: 'all:\n\techo hello\n', overrides: { X: '$(shell touch @DIR@/MARKER)' } },
    { name: 'unused exported name', makefile: 'all:\n\t@echo "GOFLAGS=[$$GOFLAGS]"\n', overrides: { GOFLAGS: '-toolexec=./evil' }, badOutput: 'GOFLAGS=[-toolexec=./evil]' },
    { name: 'STAGE referenced (control)', makefile: 'STAGE = dev\nall:\n\t@echo deploy $(STAGE)\n', overrides: { STAGE: 'production' } },
    { name: 'STAGE ?= (control)', makefile: 'STAGE ?= dev\nall:\n\t@echo deploy $(STAGE)\n', overrides: { STAGE: 'production' } },
  ]);
});

// ---------------------------------------------------------------- F3: what make hands to the recipes

test('F3: .EXPORT_ALL_VARIABLES and every export/unexport directive are dynamic', () => {
  const rows = {
    export_all: '.EXPORT_ALL_VARIABLES:\nall:\n\techo hi\n',
    export_all_after: 'all:\n\techo hi\n.EXPORT_ALL_VARIABLES:\n',
    export_all_prerequisite_form: '.EXPORT_ALL_VARIABLES: all\nall:\n\techo hi\n',
    export_all_bash_env: 'SHELL := /bin/bash\n.EXPORT_ALL_VARIABLES:\nBASH_ENV = ./evil.sh\nall:\n\techo hi\n',
    export_all_git_dir: '.EXPORT_ALL_VARIABLES:\nGIT_DIR = ./evil.git\nall:\n\tgit status\n',
    export_names: 'FOO = 1\nexport FOO\nall:\n\techo hi\n',
    export_assign: 'export FOO = 1\nall:\n\techo hi\n',
    export_bare: 'FOO = 1\nexport\nall:\n\techo hi\n',
    unexport: 'unexport FOO\nall:\n\techo hi\n',
    unexport_bare: 'unexport\nall:\n\techo hi\n',
    override_export: 'override export FOO = 1\nall:\n\techo hi\n',
    export_override: 'export override FOO = 1\nall:\n\techo hi\n',
    export_define: 'export define X\nendef\nall:\n\techo hi\n',
    target_specific_export: 'all: export FOO = 1\nall:\n\techo hi\n',
    tab_led_export: '\texport FOO = 1\nall:\n\techo hi\n',
  };
  for (const [name, text] of Object.entries(rows)) {
    const r = make(text, ['all'], { env: ENV });
    assert.ok(!definite(r), `${name}: ${JSON.stringify(r)}`);
  }
  // `exports = 1` is an ordinary variable, not the directive.
  assert.ok(definite(make('exports = 1\nall:\n\techo hi\n', ['all'], { env: ENV })));
});

test('F3: an assignment (any operator, any spelling) to a name make hands to recipes and that changes what runs is dynamic', () => {
  const names = [
    'PATH', 'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'IFS', 'CDPATH', 'ZDOTDIR', 'HOME', 'TMPDIR', 'PS4', 'PROMPT_COMMAND',
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT', 'GIT_EXEC_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
    'NODE_OPTIONS', 'NODE_PATH', 'NPM_CONFIG_PREFIX', 'npm_config_registry', 'NPM_CONFIG_USERCONFIG', 'PYTHONPATH', 'PYTHONSTARTUP', 'PERL5LIB', 'PERL5OPT',
    'RUBYOPT', 'RUBYLIB', 'XDG_CONFIG_HOME', 'XDG_DATA_DIRS', 'EDITOR', 'PAGER', 'GOFLAGS', 'JAVA_TOOL_OPTIONS', 'LESSOPEN', 'Path',
  ];
  for (const name of names) {
    for (const op of ['=', ':=', '::=', '+=', '?=', '!=']) {
      const r = make(`${name} ${op} ./tools\nall:\n\tgit status\n`, ['all'], { env: { PATH: '/usr/bin' } });
      assert.ok(!definite(r), `${name} ${op}: ${JSON.stringify(r)}`);
    }
    assert.ok(!definite(make(`override ${name} = ./tools\nall:\n\tgit status\n`, ['all'], { env: ENV })), `override ${name}`);
  }
  // The audit's rows.
  assert.ok(!definite(make('PATH := ./tools:$(PATH)\nall:\n\tgit status\n', ['all'], { env: { PATH: '/usr/bin:/bin' } })));
  assert.ok(!definite(make('PATH = ./tools\nall:\n\tgit status\n', ['all'], { env: {} })));
});

test('F3: an assignment to a name that exists in the environment is dynamic (make exports it with the new value)', () => {
  const env = { PATH: '/usr/bin', FOO: 'orig', Mixed_Case: '1', RUSTUP_TOOLCHAIN: 'stable' };
  for (const op of ['=', ':=', '+=', '?=', '!=']) {
    for (const name of ['FOO', 'foo', 'RUSTUP_TOOLCHAIN', 'mixed_case']) {
      const r = make(`${name} ${op} changed\nall:\n\techo hi\n`, ['all'], { env });
      assert.ok(!definite(r), `${name} ${op}: ${JSON.stringify(r)}`);
    }
  }
  // The same assignment with the name absent from the environment is an ordinary Makefile variable.
  assert.ok(definite(make('FOO = changed\nall:\n\techo $(FOO)\n', ['all'], { env: { PATH: '/usr/bin' } })));
  // A name that is in the environment but only referenced is not an assignment.
  const referenced = make('all:\n\techo $(FOO)\n', ['all'], { env });
  assert.ok(definite(referenced));
  assert.deepEqual(referenced.commands, ['echo orig']);
  // On the command line too.
  assert.ok(!definite(make('all:\n\techo $(FOO)\n', ['all'], { env, overrides: { FOO: 'new' } })));
});

test('F3: SHELL assigned to a plain system shell stays definite; other values, operators and spellings do not', () => {
  for (const text of ['SHELL := /bin/bash\nall:\n\techo hi\n', 'SHELL = /bin/sh\nall:\n\techo hi\n', 'SHELL ::= /usr/bin/zsh\nall:\n\techo hi\n']) {
    assert.ok(definite(make(text, ['all'], { env: { ...ENV, SHELL: '/bin/zsh' } })), text);
  }
  for (const text of ['SHELL := ./evil.sh\nall:\n\techo hi\n', 'SHELL += -x\nall:\n\techo hi\n', 'SHELL ?= /bin/sh\nall:\n\techo hi\n', 'SHELL != echo /bin/sh\nall:\n\techo hi\n', 'SHELL = $(X)\nall:\n\techo hi\n']) {
    assert.ok(!definite(make(text, ['all'], { env: ENV })), text);
  }
});

test('F3: the routine Makefile (plain variables, simple recipes, .PHONY, SHELL := /bin/bash) stays definite', () => {
  const text = 'CC = gcc\nOUT = build\nCFLAGS ?= -O2\nSRC := $(wildcard src/*.c)\nSHELL := /bin/bash\n.PHONY: all clean\nall: $(OUT)/app\n$(OUT)/app:\n\t$(CC) $(CFLAGS) -o $@ main.c\nclean:\n\trm -rf $(OUT)\n';
  const r = make(text, ['all'], { env: ENV });
  assert.equal(r.status, 'ok');
  // $(wildcard) is a function: that variable is unresolved but unused, so only the targets decide; the file stays as it was at ecd0d1a6.
  const plain = make('CC = gcc\nOUT = build\nall:\n\t$(CC) -o $(OUT)/app main.c\n', ['all'], { env: ENV });
  assert.ok(definite(plain));
  assert.deepEqual(plain.commands, ['gcc -o build/app main.c']);
});

test('F3 oracle: GNU make exports the new value / runs the payload where the resolver must not be definite', { skip: oracleSkip }, () => {
  checkAgainstMake([
    { name: 'PATH :=', makefile: 'PATH := ./tools:$(PATH)\nall:\n\tgit status\n' },
    { name: 'PATH =', makefile: 'PATH = ./tools\nall:\n\tgit status\n' },
    { name: 'PATH = (no PATH in env)', makefile: 'PATH = ./tools\nall:\n\tgit status\n', env: null },
    { name: 'export_all + BASH_ENV', makefile: 'SHELL := /bin/bash\n.EXPORT_ALL_VARIABLES:\nBASH_ENV = ./evil.sh\nall:\n\t@echo hi; true\n' },
    { name: 'export_all + GIT_DIR', makefile: '.EXPORT_ALL_VARIABLES:\nGIT_DIR = ./evil.git\nall:\n\t@echo "GIT_DIR=[$$GIT_DIR]"\n', badOutput: 'GIT_DIR=[./evil.git]' },
    { name: 'export NAME = v', makefile: 'export GIT_DIR = ./evil.git\nall:\n\t@echo "GIT_DIR=[$$GIT_DIR]"\n', badOutput: 'GIT_DIR=[./evil.git]' },
    { name: 'export NAME', makefile: 'GIT_DIR = ./evil.git\nexport GIT_DIR\nall:\n\t@echo "GIT_DIR=[$$GIT_DIR]"\n', badOutput: 'GIT_DIR=[./evil.git]' },
    { name: 'export bare', makefile: 'GIT_DIR = ./evil.git\nexport\nall:\n\t@echo "GIT_DIR=[$$GIT_DIR]"\n', badOutput: 'GIT_DIR=[./evil.git]' },
    { name: 'env name =', makefile: 'FOO = changed\nall:\n\t@echo "FOO=[$$FOO]"\n', env: { FOO: 'orig' }, badOutput: 'FOO=[changed]' },
    { name: 'env name :=', makefile: 'FOO := changed\nall:\n\t@echo "FOO=[$$FOO]"\n', env: { FOO: 'orig' }, badOutput: 'FOO=[changed]' },
    { name: 'env name +=', makefile: 'FOO += more\nall:\n\t@echo "FOO=[$$FOO]"\n', env: { FOO: 'orig' }, badOutput: 'FOO=[orig more]' },
    { name: 'env name with a function value', makefile: 'X = $(shell touch @DIR@/MARKER)\nall:\n\t@echo hello\n', env: { X: '1' } },
    { name: 'env name overridden on the command line', makefile: 'all:\n\t@echo "FOO=[$$FOO]"\n', env: { FOO: 'orig' }, overrides: { FOO: 'new' }, badOutput: 'FOO=[new]' },
    { name: 'non-exported name (control)', makefile: 'BAR = x\nall:\n\t@echo "BAR=[$$BAR]"\n' },
    { name: 'CC / OUT (control)', makefile: 'CC = gcc\nOUT = build\n.PHONY: all\nall:\n\t@echo $(CC) -o $(OUT)/app\n' },
    { name: 'SHELL := /bin/bash (control)', makefile: 'SHELL := /bin/bash\nall:\n\t@echo hi; true\n' },
  ]);
});

// ---------------------------------------------------------------- L4: the environment must be stated

test('L4: with `env` omitted every Makefile answer is dynamic (the commands are still listed); with `env: {}` the same file is definite', () => {
  const text = 'CC = gcc\nOUT = build\nall:\n\t$(CC) -o $(OUT)/app main.c\n';
  const omitted = make(text, ['all']);
  assert.equal(omitted.status, 'ok');
  assert.equal(omitted.dynamic, true);
  assert.deepEqual(omitted.commands, ['gcc -o build/app main.c']);
  for (const env of [undefined, null]) assert.equal(make(text, ['all'], { env }).dynamic, true, String(env));
  const stated = make(text, ['all'], { env: {} });
  assert.ok(definite(stated));
  assert.deepEqual(stated.commands, ['gcc -o build/app main.c']);
  assert.ok(definite(make(text, ['all'], { env: ENV })));
});

test('L4: omitted env is dynamic for every decision that reads it: MAKEFLAGS/MAKEFILES, ?=, +=, unknown names, $(MAKE), overrides', () => {
  const rows = {
    plain: 'all:\n\techo hi\n',
    optional: 'STAGE ?= dev\nall:\n\techo $(STAGE)\n',
    append: 'FLAGS += -x\nall:\n\techo $(FLAGS)\n',
    unknown_name: 'all:\n\techo $(WHO)\n',
    sub_make: 'all:\n\t$(MAKE) safe\nsafe:\n\techo safe\n',
    assignment: 'FOO = 1\nall:\n\techo $(FOO)\n',
  };
  for (const [name, text] of Object.entries(rows)) assert.equal(make(text, ['all']).dynamic, true, name);
  assert.equal(make('all:\n\techo $(STAGE)\n', ['all'], { overrides: { STAGE: 'production' } }).dynamic, true, 'overrides without env');
  // The audit's "MAKE contract" row: env MAKEFLAGS / MAKEFILES cannot be seen, so the answer cannot be definite.
  for (const name of ['MAKEFLAGS', 'MAKEFILES', 'GNUMAKEFLAGS', 'MAKEOVERRIDES', 'MFLAGS']) {
    assert.equal(make('all:\n\t$(MAKE) safe\nsafe:\n\techo safe\n', ['all'], { env: { [name]: 'x' } }).dynamic, true, name);
  }
});

test('L4: names that are keys of Object.prototype are never environment variables (no throw, no value)', () => {
  for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
    const r = make(`all:\n\techo $(${name})\n`, ['all'], { env: {} });
    assert.equal(r.status, 'ok', name);
    assert.equal(r.dynamic, true, name);
    const optional = make(`${name} ?= x\nall:\n\techo $(${name})\n`, ['all'], { env: {} });
    assert.equal(optional.status, 'ok', name);
    assert.deepEqual(optional.commands, ['echo x'], name);
  }
  // An environment value that is not a string is not a value.
  assert.ok(definite(make('all:\n\techo hi\n', ['all'], { env: { MAKEFLAGS: undefined, FOO: 1 } })));
});

test('L4 oracle: environment MAKEFILES / MAKEFLAGS change what make reads; the resolver is dynamic with env given and with env omitted', { skip: oracleSkip }, () => {
  const files = { 'evil.mk': 'all: deploy\ndeploy:\n\techo RISKY\n' };
  checkAgainstMake([
    { name: 'env MAKEFILES', makefile: 'all:\n\techo hello\n', env: { MAKEFILES: 'evil.mk' }, files },
    { name: 'env MAKEFILES, env omitted', makefile: 'all:\n\techo hello\n', env: { MAKEFILES: 'evil.mk' }, files, omitEnv: true },
    { name: 'env MAKEFLAGS -f', makefile: 'all:\n\techo hello\n', env: { MAKEFLAGS: '-f evil.mk' }, files },
    { name: 'env MAKEFLAGS -f, env omitted', makefile: 'all:\n\techo hello\n', env: { MAKEFLAGS: '-f evil.mk' }, files, omitEnv: true },
    { name: 'clean env (control)', makefile: 'all:\n\techo hello\n' },
  ]);
});
