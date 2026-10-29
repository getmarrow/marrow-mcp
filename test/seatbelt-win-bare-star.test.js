'use strict';

// 3.9.106 patch round, finding M-3 (MEDIUM, stricter than POSIX): on win32 a last part of exactly `*` was matched against every
// protected pattern and every shim name, as if it could be any file, so `del /q C:\x\*` and `rm C:/x/*` stopped with
// S0.windows_protected_path / windows_shim_write while `rm /x/*` passes on POSIX. A bare `*` under a known folder now names the
// files IN that folder: no shim hit, and a protected hit only when the folder is a protected place or an anchor (a protected folder,
// the profile folder, a system tree). Any other wildcard (`a*`, a wildcard folder, a variable folder) keeps the old reading (`*.*` joined `*` in patch round 3, M-3b: see seatbelt-win-patch3.test.js),
// and the secret check is unchanged. Fixture names only (a synthetic profile C:\Users\fx); in-memory fakes.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const CTX = {
  'win32 Bash': (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'win32', cwd: null })),
  'win32 PowerShell': (cmd) => evaluateSeatbelt({ tool_name: 'PowerShell', tool_input: { command: cmd } }, makeEnv({ platform: 'win32', cwd: null })),
};
const POSIX = {
  linux: (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'linux' })),
  'linux, cwd unknown': (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'linux', cwd: null })),
  darwin: (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'darwin' })),
};
const W1 = ['windows_protected_path', 'windows_shim_write'];
const show = (d) => `${d.decision} ${d.rule} [${d.reasons.join(',')}]`;

test('M-3: a bare * in a plain folder passes on win32, like its POSIX analog (no protected or shim hit)', () => {
  for (const cmd of [
    'rm ./build/*', 'rm C:/x/*', 'del /q C:\\x\\*', 'del C:\\x\\*', 'Remove-Item C:\\x\\*', 'Remove-Item .\\build\\*', 'del build\\*',
    'Remove-Item .\\dist\\* -Force', 'del /q C:\\Users\\fx\\Documents\\*', 'del /q C:\\Users\\fx\\AppData\\Local\\Temp\\*', 'del C:\\*', 'rm *', 'rm C:/Users/fx/proj/*',
    'echo hi; del /q C:\\x\\*', 'del /q C:\\x\\* && del /q C:\\y\\*', 'powershell -c "Remove-Item C:\\x\\*"', 'del /q C:\\x\\*.log',
  ]) {
    for (const [name, run] of Object.entries(CTX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'pass', `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});

test('M-3: `rm -f ./build/*` has no protected or shim hit any more; its remaining stop is the J2 -f rule, the same as `rm -f ./build/a.txt`', () => {
  for (const [name, run] of Object.entries(CTX)) {
    const star = run('rm -f ./build/*');
    const plain = run('rm -f ./build/a.txt');
    for (const r of W1) assert.ok(!star.reasons.includes(r), `${name}: ${show(star)}`);
    assert.equal(star.decision, plain.decision, `${name}: ${show(star)} vs ${show(plain)}`);
    assert.equal(star.rule, plain.rule, `${name}: ${show(star)} vs ${show(plain)}`);
  }
});

test('M-3: POSIX decisions for the analog rows are the 3.9.105 ones (the Windows module never runs there)', () => {
  const same = [['rm ./build/*', 'pass'], ['rm -f ./build/*', 'pass'], ['rm /x/*', 'pass'], ['rm /home/u/proj/*', 'pass'], ['rm ~/.ssh/*', 'stop'], ['rm ~/.marrow/*', 'stop'], ['rm -rf ~/*', 'stop'], ['rm -rf /x/*', 'stop']];
  for (const [cmd, want] of same) {
    for (const [name, run] of Object.entries(POSIX)) {
      const d = run(cmd);
      assert.equal(d.decision, want, `${name}: ${cmd} -> ${show(d)}`);
      for (const r of W1) assert.ok(!d.reasons.includes(r), `${name}: ${cmd}`);
    }
  }
});

test('M-3 abuse: a bare * directly in a protected folder, the profile folder or a system tree still stops, with the protected-path hit', () => {
  for (const cmd of [
    'rm -f C:/Users/fx/.ssh/*', 'del /q C:\\Users\\fx\\.marrow\\*', 'del C:\\Users\\fx\\.claude\\*', 'rm -f ~/.ssh/*', 'rm -f ~/.marrow/*', 'rm -f ~/.claude/*',
    'del /q .claude\\*', 'del /q C:\\Users\\fx\\.ssh\\keys\\*', 'del /q %USERPROFILE%\\.ssh\\*', 'del /q $env:USERPROFILE\\.marrow\\*',
    'del /q C:\\Users\\fx\\AppData\\Roaming\\npm\\*', 'del /q C:\\Users\\fx\\Start Menu\\Programs\\Startup\\*', 'del /q C:\\Windows\\System32\\*', 'del /q C:\\Program Files\\*',
    'del /q C:\\ProgramData\\*', 'del /q C:\\Users\\fx\\.config\\git\\*', 'del /q C:\\Users\\fx\\Documents\\WindowsPowerShell\\*', 'del /q C:\\Users\\fx\\bin\\*',
    'copy a.txt C:\\Users\\fx\\.claude\\*', 'echo x > C:\\Users\\fx\\.claude\\*', 'move C:\\x\\* C:\\Users\\fx\\.claude\\', 'xcopy C:\\x\\* C:\\Users\\fx\\.ssh\\',
    'cmd.exe /c del C:\\Users\\fx\\.marrow\\*', 'powershell.exe -c "Remove-Item C:\\Users\\fx\\.ssh\\*"',
    'echo hi; del C:\\Users\\fx\\.ssh\\*', 'echo hi && del C:\\Users\\fx\\.ssh\\*', 'echo hi | del C:\\Users\\fx\\.ssh\\*',
    // spelling variants of the same folder: case, a trailing dot, a dot part, a .. part, quotes, a doubled star, a switch value
    'del /q C:\\Users\\fx\\.SSH\\*', 'del /q C:\\Users\\fx\\.ssh.\\*', 'del /q C:\\Users\\fx\\.ssh\\.\\*', 'del /q C:\\Users\\fx\\x\\..\\.ssh\\*',
    'del /q "C:\\Users\\fx\\.ssh\\*"', 'del /q C:\\Users\\fx\\.ssh\\**', 'Remove-Item -Path C:\\Users\\fx\\.claude\\* -Force', 'Remove-Item -Path:C:\\Users\\fx\\.marrow\\*',
    'rm ~/.aws/*', 'rm $HOME/.ssh/*', 'rm "$HOME"/*',
  ]) {
    for (const [name, run] of Object.entries(CTX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
      assert.ok(d.reasons.includes('windows_protected_path') || d.reasons.includes('rm_write_protected_path'), `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});

test('M-3 parity: each shape decides on win32 as its linux analog does, or is stricter on win32 only for the Windows-only places', () => {
  // [win32 command, linux analog, true when win32 may stop where linux passes (home or a Windows-only protected place)]
  const rows = [
    ['rm ./build/*', 'rm ./build/*', false], ['rm ../*', 'rm ../*', false], ['rm ../../*', 'rm ../../*', false], ['rm ./*', 'rm ./*', false],
    ['rm ~/Documents/*', 'rm ~/Documents/*', false], ['rm ~/.ssh/*', 'rm ~/.ssh/*', false], ['rm ~/.marrow/*', 'rm ~/.marrow/*', false], ['rm ~/.aws/*', 'rm ~/.aws/*', false],
    ['rm -rf ~/*', 'rm -rf ~/*', false], ['rm -rf ./*', 'rm -rf ./*', false], ['rm -rf C:/x/*', 'rm -rf /x/*', false], ['rm C:/x/*', 'rm /x/*', false],
    ['rm ~/*', 'rm ~/*', true], ['rm ~/.claude/*', 'rm ~/.claude/*', true], ['rm ~/.config/git/*', 'rm ~/.config/git/*', true],
  ];
  for (const [w, l, stricter] of rows) {
    const dw = CTX['win32 Bash'](w);
    const dl = POSIX.linux(l);
    if (stricter) assert.ok(dw.decision === 'stop' || dl.decision === 'pass' || dw.decision === dl.decision, `${w}: ${show(dw)} vs ${show(dl)}`);
    else if (dl.decision === 'stop') assert.equal(dw.decision, 'stop', `${w}: win32 ${show(dw)} vs linux ${l}: ${show(dl)}`);
    else if (!/^rm -f? ?[^ ]*(?:build|\.\.|\.\/)/.test(w)) assert.equal(dw.decision, dl.decision, `${w}: win32 ${show(dw)} vs linux ${l}: ${show(dl)}`);
    else assert.equal(dw.decision, 'pass', `${w}: ${show(dw)}`);
  }
});

test('M-3 abuse: the home wildcard and the recursive variants still stop', () => {
  for (const cmd of [
    'rm -rf ~/*', 'del /s /q C:\\Users\\fx\\*', 'Remove-Item -Recurse C:\\Users\\fx\\*', 'del /q C:\\Users\\fx\\*', 'rm -f C:/Users/fx/*', 'rm -f ~/*',
    'rm -rf C:/x/*', 'rm -rf ~/.marrow/*', 'del /s /q C:\\x\\*', 'Remove-Item -Recurse C:\\x\\*', 'rd /s /q C:\\x\\*',
  ]) {
    for (const [name, run] of Object.entries(CTX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
    }
  }
  for (const cmd of ['rm -rf ~/*', 'del /s /q C:\\Users\\fx\\*', 'del /q C:\\Users\\fx\\*', 'rm -f ~/*']) {
    for (const [name, run] of Object.entries(CTX)) assert.ok(run(cmd).reasons.includes('windows_protected_path'), `${name}: ${cmd}`);
  }
});

test('M-3 abuse: every other wildcard keeps the old reading, and a literal shim name next to a bare * still stops', () => {
  for (const cmd of [
    'del /q C:\\Users\\fx\\.ssh\\*.*', 'del /q C:\\x\\*\\*', 'del /q C:\\Users\\*\\.ssh\\*', 'del /q C:\\Users\\*',
    'del /q C:\\x\\* C:\\y\\node.cmd', 'del /q C:\\x\\node.cmd', 'rm -f C:/x/node.cmd C:/x/*', 'copy node.cmd C:\\x\\*',
  ]) {
    for (const [name, run] of Object.entries(CTX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});

test('M-3: the secret check is unchanged (a bare * may still stand for a key file in a program that reads or copies)', () => {
  for (const cmd of ['type C:\\Users\\fx\\.ssh\\*', 'copy a.txt C:\\x\\*']) {
    for (const [name, run] of Object.entries(CTX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
      assert.ok(d.reasons.includes('windows_secret_path'), `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});
