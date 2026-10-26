'use strict';

// 3.9.106 patch round, finding M-2 (MEDIUM, false owner-only stop): on win32 the word that only STARTS a command (`cmd.exe` of
// `cmd.exe /c npm test`, `powershell.exe`, `pwsh.exe`, the program after `env`) was read as an operand, so it matched the shim
// names (`cmd.exe`, `node.exe` ...) and everyday commands stopped with S0.windows_shim_write. Such a launcher word now skips the
// shim, write-only and ancestor checks; the secret check and the protected-place check still read it, and every word of the
// command it starts is read in full. Fixture names only (C:\fx\..., a synthetic profile); in-memory fakes.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const SHIM = 'windows_shim_write';
const S5 = 'S5.windows_shell_delete_unparsed';
const S1 = 'S1.protected_branch_force';
const CTX = {
  'win32 Bash': (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'win32', cwd: null })),
  'win32 PowerShell': (cmd) => evaluateSeatbelt({ tool_name: 'PowerShell', tool_input: { command: cmd } }, makeEnv({ platform: 'win32', cwd: null })),
};
const POSIX = {
  linux: (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'linux' })),
  darwin: (cmd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, makeEnv({ platform: 'darwin' })),
};
const show = (d) => `${d.decision} ${d.rule} [${d.reasons.join(',')}]`;

function expectPass(cmd) {
  for (const [name, run] of Object.entries(CTX)) {
    const d = run(cmd);
    assert.equal(d.decision, 'pass', `${name}: ${cmd} -> ${show(d)}`);
  }
}
function expectShimStop(cmd) {
  for (const [name, run] of Object.entries(CTX)) {
    const d = run(cmd);
    assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
    assert.ok(d.reasons.includes(SHIM), `${name}: ${cmd} -> ${show(d)}`);
  }
}

test('M-2: everyday commands behind a launcher word pass on win32 (they passed in 3.9.105)', () => {
  for (const cmd of [
    'cmd.exe /c npm run build',
    'powershell.exe -NoProfile -Command npm test',
    'pwsh.exe -c "dotnet build"',
    'C:\\Windows\\System32\\cmd.exe /c npm test',
    'env node.exe x.js',
    'env -i node.exe x.js',
    'cmd.exe /d /s /c npm test',
    'C:\\Windows\\System32\\cmd.exe /c copy a b',
    'cmd.exe /c env node.exe x.js',
    'env git.exe commit -m x',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command npm test',
  ]) expectPass(cmd);
});

test('M-2: POSIX decisions do not change (the Windows module never runs there)', () => {
  for (const cmd of ['cmd.exe /c npm run build', 'env node.exe x.js', 'cmd.exe /c copy x C:\\fx\\node.cmd', 'env git.exe commit -m x']) {
    for (const [name, run] of Object.entries(POSIX)) {
      const d = run(cmd);
      assert.equal(d.decision, 'pass', `${name}: ${cmd} -> ${show(d)}`);
      assert.ok(!d.reasons.includes(SHIM), `${name}: ${cmd}`);
    }
  }
});

test('M-2 abuse: a write of a shim name through a launcher still stops, in the wrapped command\'s own words', () => {
  for (const cmd of [
    'cmd.exe /c copy x C:\\fx\\node.cmd',
    'powershell.exe -Command "Set-Content C:\\fx\\node.cmd x"',
    'pwsh.exe -c "Copy-Item x C:\\fx\\pwsh.exe"',
    'cmd.exe /c cmd.exe /c copy x C:\\fx\\node.cmd',
    'powershell.exe -c "cmd.exe /c copy x node.cmd"',
    'cmd.exe /c powershell.exe -c "Set-Content node.cmd x"',
    'echo hi; cmd.exe /c copy x node.cmd',
    'echo hi && cmd.exe /c copy x node.cmd',
    'echo hi | cmd.exe /c copy x node.cmd',
    'echo hi || cmd.exe /c copy x node.cmd',
    'cmd.exe /x /c copy x node.cmd',
    'powershell.exe -Foo -Bar -Command "Set-Content node.cmd x"',
    'cmd.exe /c echo x > C:\\fx\\node.cmd',
    'cmd.exe /c del C:\\fx\\node.cmd',
    'cmd.exe /c move x C:\\fx\\git.exe',
    'cmd.exe /c ren x.txt node.cmd',
    'powershell.exe -c "Out-File node.cmd"',
    'env cmd.exe /c copy x C:\\fx\\node.cmd',
    'C:\\Windows\\System32\\cmd.exe /c copy x C:\\Windows\\System32\\node.cmd',
    // the launcher word is skipped, never the other words: a shim name among them, a second launcher, an unknown-flag lookalike
    'cmd.exe /c copy x cmd.exe', 'cmd.exe node.cmd /c x', 'cmd.exe cmd.exe /c copy x node.cmd', 'env FOO=1 cmd.exe /c copy x node.cmd', 'env -i cmd.exe /c copy x node.cmd',
    'pwsh.exe -NoProfile -c "Move-Item x C:\\fx\\git.exe"', 'cmd.exe /c "copy x C:\\fx\\node.cmd"', '"C:\\Windows\\System32\\cmd.exe" /c copy x node.cmd',
  ]) expectShimStop(cmd);
});

test('M-2 abuse: a redirect right after the switch is still a write of its target (not taken for the program)', () => {
  expectShimStop('cmd.exe /c > node.cmd');
  expectShimStop('powershell.exe -c > node.cmd');
  for (const [name, run] of Object.entries(CTX)) {
    const d = run('cmd.exe /c > C:\\Users\\fx\\.claude\\settings.json echo {}');
    assert.equal(d.decision, 'stop', `${name}: ${show(d)}`);
    assert.ok(d.reasons.includes('windows_protected_path'), `${name}: ${show(d)}`);
  }
});

test('M-2 abuse: a launcher keeps its secret check and its protected-place check', () => {
  for (const [name, run] of Object.entries(CTX)) {
    for (const cmd of ['env C:\\Users\\fx\\.aws\\credentials', 'cmd.exe /c type C:\\Users\\fx\\.aws\\credentials', 'env node.exe C:\\Users\\fx\\.aws\\credentials', 'powershell.exe -c "Get-Content C:\\Users\\fx\\.aws\\credentials"']) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
      assert.ok(d.reasons.includes('windows_secret_path'), `${name}: ${cmd} -> ${show(d)}`);
    }
    const inPlugins = run('C:\\Users\\fx\\.claude\\plugins\\cmd.exe /c npm test');
    assert.equal(inPlugins.decision, 'stop', `${name}: ${show(inPlugins)}`);
    assert.ok(inPlugins.reasons.includes('windows_protected_path') && !inPlugins.reasons.includes(SHIM), `${name}: ${show(inPlugins)}`);
    const envProtected = run('env python C:\\Users\\fx\\.marrow\\x.py');
    assert.equal(envProtected.decision, 'stop', `${name}: ${show(envProtected)}`);
  }
});

test('M-2: only the program word after env is a launcher; flags with values, assignments and a later shim name still stop', () => {
  expectShimStop('env -u X node.exe x.js');
  expectShimStop('env FOO=1 node.exe x.js');
  expectShimStop('env node.exe node.cmd');
  expectShimStop('env x.js node.cmd');
  expectShimStop('cmd.exe /c env x.js node.cmd');
});

test('M-2: the force push behind env stops on its own rule, not on a shim word', () => {
  for (const [name, run] of Object.entries(CTX)) {
    for (const cmd of ['env git.exe push -f origin main', 'env GIT.EXE push -f origin main']) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${show(d)}`);
      assert.equal(d.rule, S1, `${name}: ${show(d)}`);
      assert.ok(!d.reasons.includes(SHIM), `${name}: ${show(d)}`);
    }
  }
});

test('M-2: AB6f and AB7f stop on the delete rule, not on a shim word; H-31i is the force push; deletes through a launcher still stop', () => {
  for (const [name, run] of Object.entries(CTX)) {
    for (const cmd of ['POWERSHELL.EXE -command "del /s C:\\x"', 'cmd.exe /d /s /c "rd /s /q C:\\x"', 'cmd.exe /c rd /s /q C:\\x', 'C:\\Windows\\System32\\cmd.exe /c rd /s /q C:\\x']) {
      const d = run(cmd);
      assert.equal(d.decision, 'stop', `${name}: ${cmd} -> ${show(d)}`);
      assert.equal(d.rule, S5, `${name}: ${cmd} -> ${show(d)}`);
      assert.ok(!d.reasons.includes(SHIM), `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});
