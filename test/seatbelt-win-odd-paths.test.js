'use strict';

// 3.9.106 patch round, item 4 (owner route "hold all odd paths", 22 Oct 2026): on win32 ANY command or file-tool call that uses an
// unusual path spelling is HELD (Sx.windows_odd_path), whatever the path points at. Nothing resolves a path. The forms: 8.3 short
// names, the \\?\ and \\.\ prefixes, alternate data streams (name:stream, ::$DATA), UNC and device paths, a mix of / and \ at the
// start of a path, and a path-like word that cannot be taken apart. POSIX decisions do not change.
// Fixture names only (C:\fx\..., \\srv\share, a synthetic profile); in-memory fakes; the platform is a function argument.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { mapperEnv, seatbeltStopText } = require('../dist/seatbelt/hook.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const REASON = 'windows_odd_path';
const RULE = 'Sx.windows_odd_path';
const CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const b64 = (text) => Buffer.from(text, 'utf16le').toString('base64');
const win = () => makeEnv({ platform: 'win32', cwd: null });
const show = (d) => `${d.decision} ${d.rule} [${d.reasons.join(',')}]`;

// One fixture per form.
const ODD = {
  'short name': 'C:\\fx\\PROGRA~1\\a.txt',
  'long-path prefix': '\\\\?\\C:\\fx\\a.txt',
  'device prefix': '\\\\.\\fx\\a',
  'NT prefix': '\\??\\C:\\fx\\a',
  '::$DATA': 'C:\\fx\\a.txt::$DATA',
  'named stream': 'C:\\fx\\a.txt:s',
  'UNC': '\\\\srv\\share\\a.txt',
  'UNC with slashes': '//srv/share/a.txt',
  'mixed start': 'C:/fx\\a.txt',
  'mixed start, adjacent': 'C:\\/fx\\a.txt',
  'three leading separators': '///srv/x/a',
  'relative short name': '.\\fx\\LONGFI~1.TXT',
};
const PLAIN = ['C:\\Users\\x\\proj\\a.txt', 'C:/Users/x/proj/a.txt', '.\\src\\a.ts', '..\\x', 'src/a.ts', 'a.b.c', 'C:\\Users\\x\\proj/src/a.ts', '/c/Users/x/a.ts', 'C:\\x'];

// Every tool the seatbelt reads paths from, as an event for one path.
const TOOLS = {
  Bash: (p) => ({ tool_name: 'Bash', tool_input: { command: `type ${p}` } }),
  PowerShell: (p) => ({ tool_name: 'PowerShell', tool_input: { command: `Get-Content ${p}` } }),
  Read: (p) => ({ tool_name: 'Read', tool_input: { file_path: p } }),
  Write: (p) => ({ tool_name: 'Write', tool_input: { file_path: p, content: 'x' } }),
  Edit: (p) => ({ tool_name: 'Edit', tool_input: { file_path: p, old_string: 'a', new_string: 'b' } }),
  MultiEdit: (p) => ({ tool_name: 'MultiEdit', tool_input: { file_path: p, edits: [{ old_string: 'a', new_string: 'b' }] } }),
  NotebookEdit: (p) => ({ tool_name: 'NotebookEdit', tool_input: { notebook_path: p, new_source: 'x' } }),
  Grep: (p) => ({ tool_name: 'Grep', tool_input: { pattern: 'x', path: p } }),
  apply_patch: (p) => ({ tool_name: 'apply_patch', tool_input: { input: `*** Begin Patch\n*** Update File: ${p}\n@@\n-a\n+b\n*** End Patch` } }),
  mcp_read: (p) => ({ tool_name: 'mcp__fs__read_file', tool_input: { path: p } }),
};

test('item 4: every form is held in every tool that carries paths (Bash, PowerShell, Read, Write, Edit, MultiEdit, NotebookEdit, Grep, apply_patch, MCP)', () => {
  for (const [tool, make] of Object.entries(TOOLS)) {
    for (const [form, p] of Object.entries(ODD)) {
      const d = evaluateSeatbelt(make(p), win());
      assert.equal(d.decision, 'stop', `${tool} / ${form}: ${show(d)}`);
      assert.ok(d.reasons.includes(REASON), `${tool} / ${form}: ${show(d)}`);
      assert.match(d.rule, CODE);
      for (const r of d.reasons) assert.match(r, CODE);
    }
  }
});

test('item 4: a form that nothing else stops has the rule Sx.windows_odd_path; a path that was already a stop keeps its rule', () => {
  for (const p of Object.values(ODD)) {
    const d = evaluateSeatbelt(TOOLS.Bash(p), win());
    assert.equal(d.rule, RULE, `${p}: ${show(d)}`);
    assert.equal(d.category, 'Sx');
  }
  const stopped = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: 'rd /s /q C:\\fx\\a' } }, win());
  assert.equal(stopped.rule, 'S5.windows_shell_delete_unparsed');
  const both = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: 'rd /s /q C:\\fx\\a.txt:s' } }, win());
  assert.equal(both.decision, 'stop');
  assert.equal(both.rule, 'S5.windows_shell_delete_unparsed', 'a rule that already led keeps leading');
  assert.ok(both.reasons.includes(REASON));
});

test('item 4: chained, nested and encoded commands hold the same forms (&&, ;, ||, |, subshell, cmd /c, pwsh -c, bash -c, -EncodedCommand)', () => {
  for (const [form, p] of Object.entries(ODD)) {
    for (const cmd of [
      `echo hi && type ${p}`, `echo hi; type ${p}`, `echo hi || type ${p}`, `echo hi | findstr x ${p}`, `(type ${p})`, `echo $(type ${p})`,
      `cmd /c type ${p}`, `cmd.exe /d /s /c "type ${p}"`, `pwsh -c "Get-Content ${p}"`, `powershell.exe -NoProfile -Command "Get-Content '${p}'"`,
      `bash -c 'cat ${p}'`, `echo hi && cmd /c "pwsh -c 'Get-Content ${p}'"`, `Get-Content -Path:${p}`, `type "${p}"`,
      `powershell -EncodedCommand ${b64(`Get-Content ${p}`)}`, `pwsh -enc ${b64(`type ${p}`)}`,
    ]) {
      const d = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, win());
      assert.equal(d.decision, 'stop', `${form}: ${cmd.slice(0, 90)} -> ${show(d)}`);
      assert.ok(d.reasons.includes(REASON), `${form}: ${cmd.slice(0, 90)} -> ${show(d)}`);
    }
  }
});

test('item 4: an encoded command that cannot be decoded is still the existing stop', () => {
  for (const cmd of ['powershell -EncodedCommand !!!not-base64!!!', 'pwsh -enc AAAA', `powershell -EncodedCommand ${'QQ'.repeat(20000)}`]) {
    const d = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: cmd } }, win());
    assert.equal(d.decision, 'stop', `${cmd.slice(0, 60)} -> ${show(d)}`);
  }
});

test('item 4: plain everyday paths are not held, in every tool', () => {
  for (const [tool, make] of Object.entries(TOOLS)) {
    for (const p of PLAIN) {
      const d = evaluateSeatbelt(make(p), win());
      assert.ok(!d.reasons.includes(REASON), `${tool}: ${p} -> ${show(d)}`);
    }
  }
});

test('item 4: URLs, git@host:repo, host:port, git revisions, container volumes and PowerShell drives are not paths with a stream or a short name', () => {
  for (const cmd of [
    'git clone https://example.com/x/y.git', 'git clone git@host:repo.git', 'git clone ssh://git@host/x/y.git', 'git fetch origin',
    'git diff HEAD~1', 'git log HEAD~3..HEAD', 'git show HEAD:src/a.ts', 'git log origin/main~2', 'git reset --hard HEAD~1', 'git diff main~1 -- src/a.ts',
    'curl localhost:3000/api', 'curl -o out.txt https://example.com/a?b=c:d', 'ssh -p 22 user@host:/srv', 'echo 12:30', 'node scripts/changed.js HEAD~1',
    'docker run -v ./data:/data:ro img', 'docker pull ghcr.io/x/y:latest', 'uvicorn app.main:app --reload', 'Get-ChildItem HKLM:\\Software', 'Get-Item Env:PATH',
    'npm run build', 'npx tsc --noEmit', 'git commit -m "fix: handle a:b"', 'type C:\\x\\a.txt', 'dir', 'echo hello world', 'node -e "console.log(1)"',
  ]) {
    for (const [name, make] of [['Bash', (c) => ({ tool_name: 'Bash', tool_input: { command: c } })], ['PowerShell', (c) => ({ tool_name: 'PowerShell', tool_input: { command: c } })]]) {
      const d = evaluateSeatbelt(make(cmd), win());
      assert.ok(!d.reasons.includes(REASON), `${name}: ${cmd} -> ${show(d)}`);
    }
  }
});

test('item 4: a path-like word that cannot be taken apart is held (too long, a control character, a look-alike separator)', () => {
  const words = [`C:\\${'a'.repeat(5000)}`, 'C:\\fx\\a\u0001b', 'C:\\fx\uff0fa.txt', 'C:\\fx\u2215a.txt'];
  for (const w of words) {
    for (const make of [TOOLS.Bash, TOOLS.Read, TOOLS.Write]) {
      const d = evaluateSeatbelt(make(w), win());
      assert.equal(d.decision, 'stop', `${w.length}: ${show(d)}`);
      assert.ok(d.reasons.includes(REASON), `${w.length}: ${show(d)}`);
    }
  }
});

test('item 4: POSIX decisions are unchanged (no hold on linux or darwin, in any tool)', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const [tool, make] of Object.entries(TOOLS)) {
      for (const p of Object.values(ODD)) {
        const d = evaluateSeatbelt(make(p), makeEnv({ platform }));
        assert.ok(!d.reasons.includes(REASON), `${platform} ${tool}: ${p} -> ${show(d)}`);
        for (const r of d.reasons) assert.ok(!r.startsWith('windows_'), `${platform} ${tool}: ${r}`);
      }
    }
  }
});

test('item 4: a platform field in the event or its input cannot turn the hold off; the hook takes the platform from the process', () => {
  const forged = [
    { tool_name: 'Bash', platform: 'linux', os: 'linux', tool_input: { command: `type ${ODD['named stream']}`, platform: 'linux', os: 'darwin' } },
    { tool_name: 'Read', platform: 'darwin', tool_input: { file_path: ODD['UNC'], platform: 'posix' } },
    { tool_name: 'Write', tool_input: { file_path: ODD['short name'], content: 'x', platform: 'linux' }, env: { platform: 'linux' } },
  ];
  for (const ev of forged) {
    const d = evaluateSeatbelt(ev, win());
    assert.equal(d.decision, 'stop', show(d));
    assert.ok(d.reasons.includes(REASON), show(d));
  }
  // The hook's env: the platform is the process's, never the event's; a win32 env (a test argument) holds, the real one is POSIX here.
  assert.equal(mapperEnv('/home/u', '/x', 300).platform, process.platform);
  assert.equal(mapperEnv('/home/u', '/x', 300, 'win32').platform, 'win32');
  const hold = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: `type ${ODD['long-path prefix']}`, platform: 'linux' } }, mapperEnv('/home/u', '/x', 300, 'win32'));
  assert.ok(hold.reasons.includes(REASON), show(hold));
  // On win32 an event cwd is never a workspace (3.9.106 A4), so a forged `/`-rooted cwd changes nothing about the hold.
  assert.equal(mapperEnv('/home/u', '/home/u/proj', 300, 'win32').cwd, null);
});

test('item 4: the hold uses the owner stop (fixed codes, no path in the text); the event is not changed; different spellings keep different action keys', () => {
  for (const p of Object.values(ODD)) {
    const ev = TOOLS.Bash(p);
    const before = JSON.stringify(ev);
    const d = evaluateSeatbelt(ev, win());
    assert.equal(JSON.stringify(ev), before, 'the event is left as it was');
    const text = seatbeltStopText(d.category, d.rule, d.reasons[0], 'seatbelt');
    assert.ok(text.includes(RULE) && text.includes('run it yourself in your own terminal'), text); // 3.9.107 stop text: advice sentence plus `Code: rule/reason`
    const blob = JSON.stringify([d.rule, d.reasons, d.flags, d.hits, text]).toLowerCase();
    for (const piece of ['fx', 'srv', 'share', 'progra', 'a.txt']) assert.ok(!blob.includes(piece), `${piece} in ${blob.slice(0, 120)}`);
  }
  const key = (cmd) => JSON.stringify(normalizedHookAction({ tool_name: 'Bash', tool_input: { command: cmd } }));
  const keys = new Set([ODD['named stream'], 'C:\\fx\\a.txt', ODD['UNC'], ODD['short name'], 'C:\\fx\\PROGRA~2\\a.txt', ODD['mixed start'], 'C:/fx/a.txt'].map((p) => key(`type ${p}`)));
  assert.equal(keys.size, 7, 'spellings that differ keep different keys');
});
