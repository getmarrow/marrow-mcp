'use strict';

// 3.9.106 patch round 3 (22 Oct 2026): audit findings M-5, M-6, M-3b, M-7 on win32. Every row goes through evaluateSeatbelt, the
// real hold mechanism, and not through a helper. Fixture names only (C:\fx, \\srv\share, C:\Users\fx, a bare a.txt / fxfile);
// in-memory fakes; the platform is a function argument. One section per item; each item has a mutant in RESULT.md.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const REASON = 'windows_odd_path';
const RULE = 'Sx.windows_odd_path';
const b64 = (text) => Buffer.from(text, 'utf16le').toString('base64');
const win = () => makeEnv({ platform: 'win32', cwd: null });
const show = (d) => `${d.decision} ${d.rule} [${d.reasons.join(',')}]`;
const SHELLS = ['Bash', 'PowerShell'];
// POSIX never gets a Windows reason from this module. The one reason that is also on the POSIX PowerShell tool since the J2 work
// (a Remove-Item style delete the shell text cannot show to be safe) is the same at 14f33e51 and is not from these items.
const windowsReasons = (d) => d.reasons.filter((r) => r.startsWith('windows_') && r !== 'windows_shell_delete_unparsed');
const run = (tool, command, env = win()) => evaluateSeatbelt({ tool_name: tool, tool_input: { command } }, env);
// The 12 contexts a command can sit in, for a command written with {c}.
const CONTEXTS = [
  (c) => c, (c) => `echo hi && ${c}`, (c) => `echo hi; ${c}`, (c) => `echo hi || ${c}`, (c) => `echo hi | ${c}`, (c) => `(${c})`, (c) => `echo $(${c})`,
  (c) => `cmd /c ${c}`, (c) => `pwsh -c "${c}"`, (c) => `bash -c '${c}'`, (c) => `echo hi && cmd /c "pwsh -c '${c}'"`, (c) => `powershell -EncodedCommand ${b64(c)}`,
];

function assertHeld(command, label) {
  for (const tool of SHELLS) {
    const d = run(tool, command);
    assert.equal(d.decision, 'stop', `${label || ''} ${tool}: ${command.slice(0, 100)} -> ${show(d)}`);
    assert.ok(d.reasons.includes(REASON), `${label || ''} ${tool}: ${command.slice(0, 100)} -> ${show(d)}`);
  }
}
function assertNotHeld(command, label) {
  for (const tool of SHELLS) {
    const d = run(tool, command);
    assert.ok(!d.reasons.includes(REASON), `${label || ''} ${tool}: ${command.slice(0, 100)} -> ${show(d)}`);
  }
}

// ---------------------------------------------------------------------------------------------
// M-5: a stream spelling on a BARE file name (no drive, no separator) in shell text is held like the spelling with a separator.

const M5_HELD = [
  'type a.txt:s', "type 'a.txt::$DATA'", "type 'a.txt:s:$DATA'", "Get-Content 'a.txt:s'", 'more < a.txt:s', 'echo x > a.txt:s', 'copy x a.txt:s',
  'notepad a.txt:s', 'type fxfile:s', 'Set-Content fxfile:s x',
  // more spellings of the same two shapes
  'echo x > fxfile:s', 'echo x >fxfile:s', 'sort < fxfile:s', 'findstr x < a.txt:s', 'type a.txt:Zone.Identifier', 'Get-Content -LiteralPath a.txt:s',
  "Get-Content -LiteralPath 'a.txt:s:$DATA'", "Get-Content -Path:a.txt:s:$DATA", "Get-Content -Path a.txt:s:$DATA", 'Add-Content fxfile:s x', 'Out-File fxfile:s',
  'New-Item fxfile:s', 'Set-Content -Path fxfile:s -Value x', 'del fxfile:s', 'Remove-Item fxfile:s', 'Copy-Item x fxfile:s', 'ren a.txt fxfile:s', 'type a.txt::$DATA',
  'type fxfile:1', 'type a.txt:80', 'xcopy fxfile:s x', 'attrib fxfile:s', 'tee fxfile:s', 'sort fxfile:s', 'Get-FileHash fxfile:s', 'Get-Acl fxfile:s', 'type $f:s', 'cat $f:s', 'Get-Item fxfile:s', 'dir fxfile:s', 'cat fxfile:s', 'type fxfile:$data', 'type fxfile:', 'node a.txt:s', '7z a x.zip .env:s',
  'echo hi | findstr x a.txt:s',
];

test('M-5: a stream on a bare name is held in the Bash and PowerShell tools (the 10 audit rows and their variants)', () => {
  for (const c of M5_HELD) assertHeld(c, 'M-5');
});

test('M-5: the audit rows get the owner rule Sx.windows_odd_path when nothing else stops them', () => {
  for (const c of M5_HELD.slice(0, 10)) {
    for (const tool of SHELLS) {
      const d = run(tool, c);
      assert.equal(d.rule, RULE, `${tool}: ${c} -> ${show(d)}`);
      assert.equal(d.category, 'Sx');
    }
  }
});

test('M-5: the held bare-name streams stay held in all 12 contexts (&&, ;, ||, |, (), $(), cmd /c, pwsh -c, bash -c, nested, -EncodedCommand)', () => {
  for (const base of ['type a.txt:s', "type 'a.txt:s:$DATA'", 'type fxfile:s', 'Set-Content fxfile:s x', 'type a.txt::$DATA']) {
    for (const [i, wrap] of CONTEXTS.entries()) assertHeld(wrap(base), `M-5 context ${i}`);
  }
});

test('M-5: the same words are held through a file tool and with a separator, as before (no regression)', () => {
  for (const ev of [
    { tool_name: 'Read', tool_input: { file_path: 'a.txt:s' } }, { tool_name: 'Write', tool_input: { file_path: 'fxfile:s', content: 'x' } },
    { tool_name: 'Read', tool_input: { file_path: 'C:\\fx\\a.txt::$DATA' } },
  ]) {
    const d = evaluateSeatbelt(ev, win());
    assert.ok(d.reasons.includes(REASON), `${JSON.stringify(ev.tool_input)} -> ${show(d)}`);
  }
  for (const c of ['type .\\a.txt:s', 'type C:\\fx\\a.txt::$DATA', 'type C:\\fx\\a.txt:s']) assertHeld(c, 'M-5 sep');
});

// Everyday words with a colon. Decided from the existing exclusions: a bare word is only a stream when it carries a stream TYPE, when a
// file program or a redirect names it as a path, or when it is a file-like name with a stream name; host:port, file:line:col,
// `module:app`, `rev:path` under git, PowerShell drives and DOS devices are not.
const M5_NOT_HELD = [
  'git show HEAD:a.txt', 'git show main:src/a.ts', 'git diff HEAD~1 -- a.txt', 'curl localhost:3000', 'curl example.com:443/x', 'ssh user@host', 'ssh -p 22 user@host:/srv',
  'node -e "a?b:c"', 'echo a:b', 'echo 12:30', 'uvicorn app.main:app --reload', 'gunicorn -w 4 myapp.wsgi:application', 'pytest test_a.py::test_x', 'code -g src.ts:12:3',
  'vim a.txt:12', 'Get-Item Env:PATH', 'Test-Path Variable:foo', 'dir /a:d', 'echo Step 1.2: build', 'Write-Host "Server v1.2: started"', 'echo "e.g.: foo"',
  'Add-Content notes.txt "TODO: fix"', 'Set-Content a.txt "k:v"', 'icacls C:\\fx /grant Everyone:F', 'npm run test:unit', 'docker run img:tag', 'echo $data', 'echo "Count:$data"',
  'java -cp a.jar:b.jar Main', 'findstr /c:"a:b" a.txt', 'curl -H "Content-Type: application/json" localhost:3000', 'grep foo <<EOF', 'type nul > nul:', 'sort < a.txt',
  'cd $env:USERPROFILE', 'Test-Path $env:FOO', 'Get-Item $env:APPDATA', 'Set-Location $env:TEMP', 'ls $env:TEMP', 'Get-Content $env:TEMP', 'Set-Content $global:log x',
  'Test-Path variable:foo', 'Get-Item function:prompt', 'Get-Item HKCU:Software', 'Get-ChildItem Cert:LocalMachine', 'cd $HOME', 'Get-ItemProperty HKCU:Software', 'Get-Item ${env:TEMP}',
  'git commit -m "see a.txt:s and a.txt:Zone.Identifier"', 'git tag -a v1 -m "a.txt::DATA and fxfile:s"',
];

test('M-5: everyday commands with a colon are not held (git revisions, host:port, module:app, file:line:col, PowerShell drives, DOS devices, prose)', () => {
  for (const c of M5_NOT_HELD) assertNotHeld(c, 'M-5 control');
});

test('M-5: misleading words: a plain double-quoted git message is data (stripped) as before; a message with $, a backslash or single quotes is read like any text (existing rule)', () => {
  assertNotHeld('git commit -m "see a.txt:s and fxfile:s and a.txt:Zone.Identifier"', 'M-5 message');
  // The existing strip keeps a message only when it is a plain literal in every shell: these are read as text, with a separator or without.
  for (const c of ['git commit -m "see C:\\fx\\a.txt::$DATA"', 'git commit -m "see a.txt::$DATA"', "git commit -m 'see a.txt::$DATA'", 'echo "see a.txt:s"', 'echo "see a.txt::$DATA"']) {
    assertHeld(c, 'M-5 message');
  }
});

test('M-5: POSIX decisions are unchanged: no Windows reason on linux or darwin for any of these words', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const c of [...M5_HELD, ...M5_NOT_HELD]) {
      for (const tool of SHELLS) {
        const d = run(tool, c, makeEnv({ platform }));
        assert.deepEqual(windowsReasons(d), [], `${platform} ${tool}: ${c} -> ${show(d)}`);
      }
    }
  }
});

test('M-5: a forged platform in the event or its input cannot turn the bare-name hold off', () => {
  for (const ev of [
    { tool_name: 'Bash', platform: 'linux', os: 'linux', tool_input: { command: 'type fxfile:s', platform: 'linux', os: 'darwin' } },
    { tool_name: 'PowerShell', platform: 'darwin', tool_input: { command: 'Set-Content fxfile:s x', platform: 'posix' } },
  ]) {
    const d = evaluateSeatbelt(ev, win());
    assert.ok(d.reasons.includes(REASON), show(d));
  }
  const posix = evaluateSeatbelt({ tool_name: 'Bash', platform: 'win32', tool_input: { command: 'type fxfile:s', platform: 'win32', os: 'win32' } }, makeEnv({ platform: 'linux' }));
  assert.ok(!posix.reasons.includes(REASON), show(posix));
});

test('M-5: a stream hold only adds; a stop that was already there keeps its rule and reasons', () => {
  const d = run('Bash', 'rd /s /q a.txt:s');
  assert.equal(d.decision, 'stop');
  assert.equal(d.rule, 'S5.windows_shell_delete_unparsed');
  assert.ok(d.reasons.includes(REASON));
});

// ---------------------------------------------------------------------------------------------
// M-6: an odd path behind a prefix in the same word (a provider, `@`, an attached option letter, an interpreter's string prefix) is held.

const M6_HELD = [
  'tool.exe @\\\\srv\\share\\list.txt', '7z x a.zip -o\\\\srv\\share\\out', 'tool.exe -o\\\\?\\C:\\fx\\a', 'Get-Content FileSystem::\\\\srv\\share\\a',
  'Set-Location FileSystem::\\\\?\\C:\\fx', 'Get-Content Microsoft.PowerShell.Core\\FileSystem::\\\\srv\\share\\a', 'Get-Content FileSystem::C:\\fx\\a.txt:s',
  'python -c "open(r\'\\\\?\\C:\\fx\\a.txt\')"',
  // more of the same shapes
  'tool.exe /o\\\\srv\\share\\out', 'tool.exe -O//srv/share/out', 'tool.exe @//srv/share/list.txt', 'Get-Content FileSystem::\\\\.\\fx\\a', 'Get-Content FileSystem::C:\\fx\\a.txt::$DATA',
  'Get-Content FileSystem::C:\\fx\\PROGRA~1\\a.txt', 'Get-ChildItem Microsoft.PowerShell.Core\\FileSystem::\\\\?\\C:\\fx', 'Get-Content @\\\\?\\C:\\fx\\a',
  'python -c "open(rb\'\\\\?\\C:\\fx\\a.txt\')"', 'python -c "open(f\'\\\\?\\C:\\fx\\a.txt\')"', 'python -c "open(u\'//?/C:/fx/a.txt\')"', 'python -c "open(r\'\\\\srv\\share\\a.txt\')"',
  'node -e "require(\'fs\').readFileSync(r\'\\\\?\\C:\\fx\\a\')"', 'tool.exe -o:\\\\srv\\share\\out',
  // already held before this round: they stay held
  'tool.exe --file=\\\\?\\C:\\fx\\a', 'tool.exe /out:\\\\srv\\share\\x', 'FOO=\\\\srv\\share\\x node', "$p='\\\\?\\C:\\fx\\a.txt'; Get-Content $p", 'type \\\\?\\C:\\fx\\a.txt',
  'type C:\\fx\\a.txt:s', 'python -c "open(\'\\\\\\\\?\\\\C:\\\\fx\\\\a.txt\')"',
];
const M6_NOT_HELD = [
  'tool.exe -o out.txt', 'git log --format=%h', 'echo @user', 'tool.exe -p:8080', 'python -c "print(1)"', 'npm i @types/node', 'gcc -I/usr/include -L/usr/lib x.c',
  'python -c "open(\'src//lib/a.py\')"', 'git log -n5', 'tool.exe -oC:\\fx\\out.txt', 'Get-Content FileSystem::C:\\fx\\a.txt', 'Get-ChildItem Registry::HKEY_CURRENT_USER',
  'Get-ChildItem Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER\\Software', 'Get-Item Env:PATH', 'tool.exe @https://example.com/a',
  'git commit -m "see -o//srv/share/out and FileSystem:://srv/share/a and r//srv/x"', 'curl -o out.txt https://example.com/a', 'echo @everyone', 'ssh -o StrictHostKeyChecking=no user@host',
  'python -c "import os; print(os.sep)"', 'node -e "console.log(\'a//b\')"', 'dir /b /s', 'xcopy /s /e src dst',
];

test('M-6: an odd path behind a prefix in the same word is held (the 8 audit rows, variants, and the forms that were already held)', () => {
  for (const c of M6_HELD) assertHeld(c, 'M-6');
});

test('M-6: the audit rows get the owner rule Sx.windows_odd_path when nothing else stops them', () => {
  for (const c of M6_HELD.slice(0, 8)) {
    for (const tool of SHELLS) {
      const d = run(tool, c);
      assert.equal(d.rule, RULE, `${tool}: ${c} -> ${show(d)}`);
    }
  }
});

test('M-6: the prefix forms stay held in all 12 contexts (&&, ;, ||, |, (), $(), cmd /c, pwsh -c, bash -c, nested, -EncodedCommand)', () => {
  for (const base of ['7z x a.zip -o\\\\srv\\share\\out', 'tool.exe @\\\\srv\\share\\list.txt', 'Get-Content FileSystem::\\\\srv\\share\\a', 'Get-Content FileSystem::C:\\fx\\a.txt:s']) {
    for (const [i, wrap] of CONTEXTS.entries()) assertHeld(wrap(base), `M-6 context ${i}`);
  }
});

test('M-6: plain words with a prefix are not held (options, @, provider drives, URLs, git message text, doubled separators in a relative path)', () => {
  for (const c of M6_NOT_HELD) assertNotHeld(c, 'M-6 control');
});

test('M-6: misleading words: a plain git message is data (stripped); a message with a backslash is read as text, as before this round', () => {
  assertNotHeld('git commit -m "tool.exe -o//srv/share/out @//srv/share/l FileSystem::C:/fx/a.txt:s"', 'M-6 message');
  assertHeld('git commit -m "see C:\\fx\\a -o\\\\srv\\share\\out"', 'M-6 message');
});

test('M-6: a file tool path behind a provider is held; a plain provider path is not', () => {
  for (const [p, held] of [['FileSystem::\\\\srv\\share\\a', true], ['FileSystem::C:\\fx\\a.txt:s', true], ['Microsoft.PowerShell.Core\\FileSystem::\\\\?\\C:\\fx\\a', true], ['FileSystem::C:\\fx\\a.txt', false]]) {
    for (const ev of [{ tool_name: 'Read', tool_input: { file_path: p } }, { tool_name: 'Write', tool_input: { file_path: p, content: 'x' } }]) {
      const d = evaluateSeatbelt(ev, win());
      assert.equal(d.reasons.includes(REASON), held, `${ev.tool_name} ${p} -> ${show(d)}`);
    }
  }
});

test('M-6: POSIX decisions are unchanged: no Windows reason on linux or darwin', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const c of [...M6_HELD, ...M6_NOT_HELD]) {
      for (const tool of SHELLS) {
        const d = run(tool, c, makeEnv({ platform }));
        assert.deepEqual(windowsReasons(d), [], `${platform} ${tool}: ${c} -> ${show(d)}`);
      }
    }
  }
});

test('M-6: one very long word behind a prefix is decided (held), and a padded line of prefixed words is decided', () => {
  const long = run('Bash', `tool.exe -o\\\\srv\\share\\${'a'.repeat(64000)}`);
  assert.equal(long.decision, 'stop', show(long));
  assert.ok(long.reasons.includes(REASON) || long.reasons.some((r) => r.startsWith('budget_')), show(long));
  const padded = run('PowerShell', `${'tool.exe -oout @list.txt FileSystem::C:\\fx\\a.txt '.repeat(1600)}`);
  assert.ok(['pass', 'stop'].includes(padded.decision), show(padded));
});

// ---------------------------------------------------------------------------------------------
// M-3b: cmd's "every file" `*.*` under a known folder is read like a bare `*` (same anchor rule).

const M3B_PASS = ['del C:\\x\\*.*', 'del /q build\\*.*', 'Remove-Item .\\dist\\*.*', 'rm ./build/*.*', 'del /q C:\\Users\\fx\\proj\\out\\*.*'];
// Not an S0 any more; still the S4 secret stop that their bare-* counterparts have (a copy may carry a key file out): Windows stricter than POSIX.
const M3B_COPY = ['copy C:\\x\\*.* C:\\y\\', 'xcopy C:\\x\\*.* C:\\y\\ /s'];
const M3B_STOP = [
  'del /q C:\\Users\\fx\\*.*', 'del C:\\Users\\fx\\*.*', 'del /s /q C:\\Users\\fx\\*.*', 'del /q C:\\Users\\fx\\.ssh\\*.*', 'del /q %USERPROFILE%\\*.*', 'Remove-Item $env:USERPROFILE\\*.*',
  'Remove-Item -Recurse C:\\x\\*.*', 'del /s /q C:\\x\\*.*', 'rd /s /q C:\\x\\*.*', 'del /q C:\\Users\\fx\\.marrow\\*.*', 'del /q C:\\Users\\fx\\.claude\\*.*',
  'del /q C:\\Users\\*\\.ssh\\*.*', 'del /q C:\\Users\\*.*', 'del /q C:\\x\\*\\*.*', 'del /q C:\\x\\*.* C:\\y\\node.cmd', 'copy node.cmd C:\\x\\*.*', 'type C:\\Users\\fx\\.ssh\\*.*',
  'rm -rf C:/x/*.*', 'rm -rf ~/*.*', 'rm ~/.ssh/*.*', 'del /q %TEMP%\\*.*', 'Remove-Item $env:TEMP\\*.*', 'del /q C:\\x\\..\\Users\\fx\\.ssh\\*.*', 'del /q C:\\Users\\fx\\..\\*.*',
];

test('M-3b: `*.*` under a plain folder passes on win32 (the five delete rows), like its POSIX analog', () => {
  for (const c of M3B_PASS) {
    for (const tool of SHELLS) {
      const d = run(tool, c);
      assert.equal(d.decision, 'pass', `${tool}: ${c} -> ${show(d)}`);
    }
  }
  // POSIX analogs on linux and darwin (Bash tool): pass, and unchanged by this round.
  for (const platform of ['linux', 'darwin']) {
    for (const c of ['rm /x/*.*', 'rm ./build/*.*', 'cp /x/*.* /y/', 'rm /home/u/proj/out/*.*']) {
      const d = run('Bash', c, makeEnv({ platform }));
      assert.equal(d.decision, 'pass', `${platform}: ${c} -> ${show(d)}`);
    }
  }
});

test('M-3b: copy and xcopy of `*.*` lose the S0 stop and keep exactly the stop their bare-* counterpart has (S4, secret path): no S4 relaxation', () => {
  for (const c of M3B_COPY) {
    for (const tool of SHELLS) {
      const d = run(tool, c);
      const bare = run(tool, c.replace(/\*\.\*/, '*'));
      assert.equal(d.decision, 'stop', `${tool}: ${c} -> ${show(d)}`);
      assert.ok(!d.reasons.includes('windows_protected_path') && !d.reasons.includes('windows_shim_write'), `${tool}: ${c} -> ${show(d)}`);
      assert.equal(show(d), show(bare), `${tool}: ${c} vs its bare-* form`);
    }
  }
});

test('M-3b: `*.*` in a profile, a protected folder, with a recursive flag, or under a variable or wildcard folder still stops', () => {
  for (const c of M3B_STOP) {
    for (const tool of SHELLS) {
      const d = run(tool, c);
      assert.equal(d.decision, 'stop', `${tool}: ${c} -> ${show(d)}`);
    }
  }
});

test('M-3b: `*.*` is read exactly like `*`: the same decision, rule and reasons in every template (chains, nesting, flags, variables, messages)', () => {
  const templates = [
    'del /q C:\\x\\{S}', 'del C:\\Users\\fx\\{S}', 'del /s /q C:\\Users\\fx\\{S}', 'del /q C:\\Users\\fx\\.ssh\\{S}', 'del /q %USERPROFILE%\\{S}', 'Remove-Item $env:USERPROFILE\\{S}',
    'Remove-Item -Recurse C:\\x\\{S}', 'rm -rf ~/{S}', 'rm ./build/{S}', 'rm C:/x/{S}', 'del /q build\\{S}', 'Remove-Item .\\dist\\{S} -Force', 'copy C:\\x\\{S} C:\\y\\', 'xcopy C:\\x\\{S} C:\\y\\ /s',
    'echo hi; del /q C:\\x\\{S}', 'echo hi && del /q C:\\Users\\fx\\{S}', 'del /q C:\\x\\{S} || echo no', 'echo y | del C:\\x\\{S}', '(del /q C:\\x\\{S})', 'echo $(del /q C:\\x\\{S})',
    'cmd /c del /q C:\\x\\{S}', 'cmd /c "del /q C:\\Users\\fx\\{S}"', 'pwsh -c "Remove-Item C:\\x\\{S}"', 'pwsh -c "Remove-Item C:\\Users\\fx\\{S}"', "bash -c 'rm -f C:/x/{S}'", "bash -c 'rm ~/{S}'",
    'cmd /c "pwsh -c \'Remove-Item C:\\Users\\fx\\{S}\'"', 'del /q /f /zz C:\\Users\\fx\\{S}', 'del /q /q C:\\x\\{S}', 'del /q C:\\x\\{S} C:\\Users\\fx\\{S}', 'del /q %TEMP%\\{S}', 'Remove-Item $env:TEMP\\{S}',
    'del /q C:\\x\\a{S}', 'del /q C:\\x\\{S}\\{S}', 'del /q C:\\x\\{S}\\..\\{S}', 'del /q C:\\Users\\{S}', 'del C:\\{S}', 'del {S}', 'del /q C:\\x\\{S} C:\\y\\node.cmd', 'copy node.cmd C:\\x\\{S}', 'type C:\\Users\\fx\\.ssh\\{S}',
    'echo "del /q C:\\Users\\fx\\{S}"', 'git commit -m "del /q C:\\Users\\fx\\{S}"', 'git commit -m "rm -rf ~/{S}"', 'echo rm -rf C:/Users/fx/{S}', 'Remove-Item -LiteralPath C:\\x\\{S}',
  ];
  for (const tpl of templates) {
    for (const tool of SHELLS) {
      const star = run(tool, tpl.replaceAll('{S}', '*'));
      const all = run(tool, tpl.replaceAll('{S}', '*.*'));
      // a wildcard in a name (`a*` / `a*.*`) keeps the old reading for both; what must hold is: `*.*` is never looser than `*`
      assert.ok(!(star.decision === 'stop' && all.decision === 'pass'), `${tool}: ${tpl} star ${show(star)} vs all ${show(all)}`);
      if (!/a\{S\}|\{S\}\\\{S\}/.test(tpl)) assert.equal(show(all), show(star), `${tool}: ${tpl}`);
    }
  }
});

test('M-3b: a forged platform or cwd cannot loosen it, and POSIX never reports a Windows reason for these commands', () => {
  const forged = evaluateSeatbelt({ tool_name: 'Bash', platform: 'linux', cwd: 'C:\\x', tool_input: { command: 'del /q C:\\Users\\fx\\*.*', platform: 'linux' } }, win());
  assert.equal(forged.decision, 'stop', show(forged));
  for (const platform of ['linux', 'darwin']) {
    for (const c of [...M3B_PASS, ...M3B_COPY, ...M3B_STOP]) {
      for (const tool of SHELLS) {
        const d = run(tool, c, makeEnv({ platform }));
        assert.deepEqual(windowsReasons(d), [], `${platform} ${tool}: ${c} -> ${show(d)}`);
      }
    }
  }
});

// ---------------------------------------------------------------------------------------------
// M-7: a `file:` URL whose path is a drive or a UNC share, and PowerShell's -Stream, are held. (The audit's coverage notes: the
// builder's earlier claim that `file://` URLs were held was wrong for both a shell word and a file tool; mapper.ts takes `file://`
// off a path field before win-protected reads it.)

const M7_URL_HELD = [
  'file:///C:/fx/a.txt', 'file:/C:/fx/a.txt', 'file:C:/fx/a.txt', 'file://C:/fx/a.txt', 'file:///C%3A/fx/a.txt', 'file:///c%3a/fx/a.txt', 'FILE:///C:/fx/a.txt', 'file:///C:\\fx\\a.txt',
  'file://localhost/C:/fx/a.txt', 'file://srv/share/a.txt', 'file:////srv/share/a.txt', 'file://127.0.0.1/C$/fx/a.txt', 'file:///\\\\srv\\share\\a.txt', 'file:///C|/fx/a.txt',
];
const M7_URL_NOT_HELD = ['file:///fx/a.txt', 'file:///tmp/a.txt', 'file:///etc/passwd', 'file://localhost/fx/a.txt', 'file.txt', 'file_notes/a.txt', 'a.txt'];
const M7_SHELL_URL_NOT_HELD = ['https://example.com/a', 'http://localhost:3000/a', 'ftp://example.com/a'];

test('M-7: a file: URL with a drive or a share is held in a shell word (curl, Invoke-WebRequest, Get-Content) in Bash and PowerShell', () => {
  for (const u of M7_URL_HELD) {
    assertHeld(`curl ${u}`, 'M-7');
    assertHeld(`Invoke-WebRequest -Uri ${u}`, 'M-7');
    assertHeld(`Get-Content -Uri:${u}`, 'M-7');
  }
  assertHeld('curl "file:///C|/fx/a.txt"', 'M-7');
});

test('M-7: a file: URL with a drive or a share is held in every file tool field (Read, Write, Edit, MultiEdit, NotebookEdit, Grep, MCP read_file)', () => {
  for (const u of M7_URL_HELD) {
    for (const ev of [
      { tool_name: 'Read', tool_input: { file_path: u } }, { tool_name: 'Write', tool_input: { file_path: u, content: 'x' } },
      { tool_name: 'Edit', tool_input: { file_path: u, old_string: 'a', new_string: 'b' } },
      { tool_name: 'MultiEdit', tool_input: { file_path: 'a.txt', edits: [{ file_path: u, old_string: 'a', new_string: 'b' }] } },
      { tool_name: 'NotebookEdit', tool_input: { notebook_path: u, new_source: 'x' } }, { tool_name: 'Grep', tool_input: { pattern: 'x', path: u } },
      { tool_name: 'mcp__fs__read_file', tool_input: { path: u } }, { tool_name: 'Read', tool_input: { file_path: ` ${u}` } },
    ]) {
      const d = evaluateSeatbelt(ev, win());
      assert.equal(d.decision, 'stop', `${ev.tool_name} ${u}: ${show(d)}`);
      assert.ok(d.reasons.includes(REASON), `${ev.tool_name} ${u}: ${show(d)}`);
    }
  }
});

test('M-7: file: URLs with a plain rooted path, other URLs, and ordinary names are not held, in a shell word or a file tool; a Write body is not a path', () => {
  for (const u of M7_SHELL_URL_NOT_HELD) assertNotHeld(`curl ${u}`, 'M-7 control');
  for (const u of M7_URL_NOT_HELD) {
    assertNotHeld(`curl ${u}`, 'M-7 control');
    for (const ev of [{ tool_name: 'Read', tool_input: { file_path: u } }, { tool_name: 'Grep', tool_input: { pattern: 'x', path: u } }]) {
      const d = evaluateSeatbelt(ev, win());
      assert.ok(!d.reasons.includes(REASON), `${ev.tool_name} ${u}: ${show(d)}`);
    }
  }
  const body = evaluateSeatbelt({ tool_name: 'Write', tool_input: { file_path: 'notes.md', content: 'see file:///C:/fx/a.txt and file://srv/share/a' } }, win());
  assert.ok(!body.reasons.includes(REASON), show(body));
  assertNotHeld('git commit -m "read file:///C:/fx/a.txt first"', 'M-7 message');
});

test('M-7: file: URL holds are held in all 12 contexts', () => {
  for (const base of ['curl file:///C:/fx/a.txt', 'curl file://srv/share/a.txt', 'Invoke-WebRequest file:C:/fx/a.txt']) {
    for (const [i, wrap] of CONTEXTS.entries()) assertHeld(wrap(base), `M-7 context ${i}`);
  }
});

const M7_STREAM_HELD = [
  'Get-Content C:\\fx\\a.txt -Stream s', 'Set-Content C:\\fx\\a.txt -Stream s -Value x', 'Get-Content a.txt -Stream:s', 'gc a.txt -stream s', 'Get-Content a.txt -St s', 'Get-Content a.txt -Str s',
  'Get-Content a.txt -Stre s', 'Get-Content a.txt -Strea s', 'Add-Content a.txt -Stream s -Value x', 'Clear-Content a.txt -Stream s', 'Remove-Item a.txt -Stream s', 'Get-Item a.txt -Stream "*"',
  'Get-Content -Stream s -Path a.txt', 'Get-Content a.txt -STREAM s', 'type a.txt -Stream s',
];
const M7_STREAM_NOT_HELD = ['git status -s', 'ls -s', 'curl -s localhost:3000', 'git log --stat', 'ffmpeg -stream_loop 1 -i a.mp4', 'npm run build --silent', 'git commit -s -m "x"',
  'Get-Content a.txt -Tail 5', 'Select-String -Pattern x a.txt', 'Start-Process notepad', 'docker logs --follow c', 'rg --stats x'];

test('M-7: PowerShell -Stream (and -St, -Str, -Stre, -Strea) is held with any value, in Bash and PowerShell, in all 12 contexts', () => {
  for (const c of M7_STREAM_HELD) assertHeld(c, 'M-7 stream');
  for (const base of ['Get-Content C:\\fx\\a.txt -Stream s', 'Set-Content C:\\fx\\a.txt -Stream s -Value x']) {
    for (const [i, wrap] of CONTEXTS.entries()) assertHeld(wrap(base), `M-7 stream context ${i}`);
  }
});

test('M-7: everyday short options and similar words are not held', () => {
  for (const c of M7_STREAM_NOT_HELD) assertNotHeld(c, 'M-7 stream control');
});

test('M-7: POSIX decisions are unchanged: no Windows reason on linux or darwin, for URLs or -Stream', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const c of [...M7_URL_HELD.map((u) => `curl ${u}`), ...M7_STREAM_HELD, ...M7_STREAM_NOT_HELD]) {
      for (const tool of SHELLS) {
        const d = run(tool, c, makeEnv({ platform }));
        assert.deepEqual(windowsReasons(d), [], `${platform} ${tool}: ${c} -> ${show(d)}`);
      }
    }
    for (const u of M7_URL_HELD) {
      const d = evaluateSeatbelt({ tool_name: 'Read', tool_input: { file_path: u } }, makeEnv({ platform }));
      assert.deepEqual(windowsReasons(d), [], `${platform} Read ${u}: ${show(d)}`);
    }
  }
});

test('M-7: a forged platform in the event cannot turn the URL or -Stream hold off; the field names that count are the path-like ones only', () => {
  for (const ev of [
    { tool_name: 'Read', platform: 'linux', tool_input: { file_path: 'file:///C:/fx/a.txt', platform: 'linux' } },
    { tool_name: 'PowerShell', os: 'linux', tool_input: { command: 'Get-Content a.txt -Stream s', platform: 'darwin' } },
  ]) assert.ok(evaluateSeatbelt(ev, win()).reasons.includes(REASON));
  const content = evaluateSeatbelt({ tool_name: 'Write', tool_input: { file_path: 'a.txt', content: 'file://srv/share/a', old_string: 'file:///C:/x' } }, win());
  assert.ok(!content.reasons.includes(REASON), show(content));
});

// The disclosed gaps (not held, by decision; owner may widen): see RESULT.md. These rows record the actual result so a change shows up.
test('M-7: the disclosed gaps stay as recorded (drive-relative C:fx\\a, \\\\.host\\share, Glob and LS path fields, -S alone)', () => {
  const rows = [
    ['Bash', { command: 'type C:fx\\a.txt' }, false], ['Bash', { command: 'type \\\\.host\\share\\a' }, false],
    ['Glob', { pattern: '*', path: '\\\\srv\\share' }, false], ['LS', { path: '\\\\?\\C:\\fx' }, false], ['PowerShell', { command: 'Get-Content a.txt -S s' }, false],
  ];
  for (const [tool, input, held] of rows) {
    const d = evaluateSeatbelt({ tool_name: tool, tool_input: input }, win());
    assert.equal(d.reasons.includes(REASON), held, `${tool} ${JSON.stringify(input)}: ${show(d)}`);
  }
});

// ---------------------------------------------------------------------------------------------
// R3c: the builder's own adversarial pass on the M-5 and M-7 code (22 Oct, win-patch3c). Two bypasses found and closed (the path given by a
// named parameter after a data parameter; `${x}:s`), and two everyday forms narrowed without loosening a held row (a here-string text,
// `ls -St`). Each row goes through evaluateSeatbelt; fixture names only.

const R3C_HELD = [
  // the path stands behind a data parameter, or is named by a parameter: the first word is data, not the path
  'Set-Content -Value x -Path fxfile:s', 'Set-Content -Value x -Path:fxfile:s', 'Set-Content -Value:x -Path:fxfile:s', 'Set-Content -Encoding UTF8 fxfile:s x', 'Out-File -Encoding ascii -FilePath fxfile:s',
  'Out-File -InputObject x fxfile:s', 'New-Item -ItemType File fxfile:s', 'New-Item -ItemType File -Name fxfile:s', 'New-Item -Type File -Path . -Name fxfile:s', 'Add-Content -Value x -LiteralPath fxfile:s',
  'sc -Value x -Path fxfile:s', 'Set-Content -Force -Value x fxfile:s', 'Set-Content -Val x -Pa fxfile:s', 'ac -v x -lp fxfile:s', 'Clear-Content -Force -Path fxfile:s',
  'Set-Content -Path a.txt -Value x -Path fxfile:s', 'Set-Content -NoNewline -Value x -Path fxfile:s', 'Out-File -Append -Width 80 -FilePath fxfile:s',
  // a braced variable is the variable: `${f}:s` is held like `$f:s`; an environment variable followed by a stream is a path with a stream
  'type ${f}:s', 'cat ${f}:s', 'Set-Content ${f}:s x', 'type ${env:X}:s', 'type $env:X:s',
  // a here-string or a delimiter is text, but whatever else stands on the line is read as before
  'cat <<< x > fxfile:s', 'cat <<< "x" fxfile:s', 'cat <<< a.txt:s', 'cat <<< "x" < fxfile:s', 'cat <<< "$(type a.txt:s)"', 'cat <<< x; type fxfile:s', 'cat <<EOF > a.txt:s',
  'sort <<< x -o fxfile:s', 'tee fxfile:s <<< x', 'cat <<< x | tee a.txt:s',
  'cat <<< > fxfile:s', 'cat <<<>fxfile:s', 'cat <<< < fxfile:s',
  // ls sort flags are no -Stream; every other -St is
  'ls -Stream', 'ls -Stre', 'wsl ls -St', 'ls -ST', 'ls -St; Get-Content a.txt -St s', 'ls a; gc a.txt -St s', 'Get-Content a.txt -St', 'gc -St s a.txt', 'ls | gc -St s', 'echo ls -St', 'cmd /c ls -St',
];
const R3C_NOT_HELD = [
  'Set-Content -Path a.txt -Value "x:y"', 'Set-Content -Value "x:y" -Path a.txt', 'Set-Content a.txt "x:y"', 'Set-Content -Encoding UTF8 a.txt "x:y"', 'Add-Content log.txt "t: now"', 'Out-File -FilePath a.txt -InputObject "x:y"',
  'New-Item -ItemType Directory out', 'Set-Content -Value:"x:y" a.txt', 'cd ${env:USERPROFILE}', 'echo ${env:USERPROFILE}', 'Get-Item $env:PATH', 'cd $env:USERPROFILE', 'echo ${HOME}:/bin', 'docker run -v ${PWD}:/work img',
  'cat <<< "key:value"', 'cat <<< key:value', 'sort <<< "b:1"', 'tee out.txt <<< "a:b"', 'cat <<EOF', 'cat << EOF', 'cat <<-EOF',
  'ls -St', 'ls -Str', 'ls -S -t', 'ls -la', 'cat ${f:-a.txt}', 'cp ${SRC:-a.txt} out', 'type ${USERPROFILE}',
];

test('R3c: a path behind a data parameter, a braced variable with a stream, and the rest of a line after a here-string are held (Bash and PowerShell)', () => {
  for (const c of R3C_HELD) assertHeld(c, 'R3c');
});

test('R3c: the held rows are held in all 12 contexts', () => {
  for (const c of R3C_HELD) for (const ctx of CONTEXTS) for (const tool of SHELLS) {
    const d = run(tool, ctx(c));
    assert.ok(d.decision === 'stop' && d.reasons.includes(REASON), `R3c ${tool}: ${ctx(c).slice(0, 100)} -> ${show(d)}`);
  }
});

test('R3c: everyday forms are not held: data values with a colon, ${env:X}, here-string text, ls -St (in the plain form)', () => {
  for (const c of R3C_NOT_HELD) assertNotHeld(c, 'R3c');
});

test('R3c: POSIX decisions are unchanged: no Windows reason on linux or darwin for any R3c row', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const c of [...R3C_HELD, ...R3C_NOT_HELD]) for (const tool of SHELLS) {
      const d = run(tool, c, makeEnv({ platform }));
      assert.deepEqual(windowsReasons(d), [], `${platform} ${tool}: ${c} -> ${show(d)}`);
    }
  }
});

test('R3c: a forged platform, os or cwd in the event cannot turn the held rows off', () => {
  for (const c of ['Set-Content -Value x -Path fxfile:s', 'type ${f}:s', 'cat <<< x > fxfile:s']) {
    const d = evaluateSeatbelt({ tool_name: 'Bash', platform: 'linux', os: 'linux', cwd: '/home/fx', tool_input: { command: c, platform: 'linux', os: 'darwin' } }, win());
    assert.ok(d.reasons.includes(REASON), `${c} -> ${show(d)}`);
  }
});

test('R3c: padded lines (4, 18 and 64 KB) of the new shapes are decided', () => {
  const shapes = [(n) => 'Set-Content -Value x -Path fxfile:s; '.repeat(n), (n) => 'type ${f}:s '.repeat(n), (n) => 'cat <<< "key:value"; '.repeat(n), (n) => 'ls -St; '.repeat(n)];
  for (const f of shapes) {
    for (const size of [4096, 18432, 65536]) {
      const text = f(Math.ceil(size / f(1).length)).slice(0, size);
      const d = run('Bash', text);
      assert.ok(d.decision === 'stop' || d.decision === 'pass', `size ${size}: ${show(d)}`);
    }
  }
});
