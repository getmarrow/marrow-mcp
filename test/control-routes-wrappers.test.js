const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { homedir, tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { controlRoute } = require('../dist/control-routes.js');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { heldLabel } = require('./support/mcp-109-n2-categories.cjs');
const { keyedHarness } = require('./support/first-hour-harness.cjs');

// T1 (MCP 3.9.113): self-disable routes and hook wipes are held locally. Abuse rows A1-A20, the collision rows and the growth and
// time-budget rows of the spec section. A wrapper option that takes an argument consumes it; an installer or marrow-mcp subcommand
// that is not proven safe is a route; a MARROW_AUTO_HOOK assignment is one too; and every marrow-control hold is answered locally.

const SECURITY_LABEL = 'classified Bash action: security on marrow-control';
const DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';
const bash = (command) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: tmpdir() });
const held = (command) => heldLabel(bash(command).action) === SECURITY_LABEL;

const ROUTES = [
  ['A1 the miss: env -u NAME before npx', 'env -u MARROW_API_KEY npx -y @getmarrow/install@0.1.76 control disable --yes'],
  ['A1 env --unset NAME', 'env --unset MARROW_API_KEY npx @getmarrow/install control disable'],
  ['A1 env -u echo (the argument looks like a reader)', 'env -u echo npx @getmarrow/install control disable'],
  ['A2 sudo -u root', 'sudo -u root npx @getmarrow/install control disable'],
  ['A2 sudo -g grp -u echo', 'sudo -g staff -u echo npx @getmarrow/install control disable'],
  ['A2 doas -u root', 'doas -u root npx @getmarrow/install control disable'],
  ['A3 timeout -s KILL 5', 'timeout -s KILL 5 npx @getmarrow/install control disable'],
  ['A3 timeout -k 1 -s TERM 5', 'timeout -k 1 -s TERM 5 npx @getmarrow/install control disable'],
  ['A4 env -C /tmp', 'env -C /tmp npx @getmarrow/install control disable'],
  ['A4 env -S split string', "env -S 'npx @getmarrow/install control disable'"],
  ['A4 env -S with doctor (dynamic text)', "env -S 'npx @getmarrow/install doctor'"],
  ['A5 nice -n 5 xargs -I{} with a here-string', 'nice -n 5 xargs -I{} npx @getmarrow/install control {} <<< disable'],
  ['A5 xargs feeds a subcommand', 'printf disable | xargs npx @getmarrow/install control'],
  ['A5 ionice/stdbuf/chrt/taskset values', 'ionice -c 2 -n 7 stdbuf -o L chrt 5 taskset 3 npx @getmarrow/install control disable'],
  ['A5 exec -a name', 'exec -a echo npx @getmarrow/install control disable'],
  ['A6 the installer name in a variable', 'I=@getmarrow/install; npx $I control disable'],
  ['A6 marrow-mcp from a variable', 'M=marrow-mcp; $M setup'],
  ['A7 bash -c', 'bash -c "npx @getmarrow/install control disable"'],
  ['A7 sh -c', "sh -c 'npx @getmarrow/install control disable'"],
  ['A7 eval', 'eval "npx @getmarrow/install control disable"'],
  ['A7 command substitution', 'echo $(npx @getmarrow/install control disable)'],
  ['A7 subshell', '( npx @getmarrow/install control disable )'],
  ['A8 &&', 'true && env -u A npx @getmarrow/install control disable'],
  ['A8 ;', 'ls; sudo -u root npx @getmarrow/install control disable'],
  ['A8 ||', 'false || timeout -s KILL 5 npx @getmarrow/install control disable'],
  ['A8 pipe', 'yes | env -u A npx @getmarrow/install control disable'],
  ['A9 last word wins', 'npx @getmarrow/install control enable disable'],
  ['A9 unknown flag', 'npx @getmarrow/install control --force disable'],
  ['A9 control off', 'npx @getmarrow/install control off'],
  ['A10 update', 'npx @getmarrow/install@latest update'],
  ['A10 setup', 'npx @getmarrow/install setup'],
  ['A10 repair', 'npx @getmarrow/install repair'],
  ['A10 uninstall', 'npx @getmarrow/install uninstall'],
  ['A10 an unknown word', 'npx @getmarrow/install pause'],
  ['A10 a safe word then an unknown one', 'npx @getmarrow/install doctor reset'],
  ['A10 bare installer run (setup by default)', 'npx -y @getmarrow/install@0.1.76'],
  ['A11 the miss: timeout 240 npx --package marrow-mcp setup', 'timeout 240 npx -y --package=@getmarrow/mcp@3.9.108 marrow-mcp setup'],
  ['A11 marrow-mcp setup', 'marrow-mcp setup'],
  ['A11 npx @getmarrow/mcp uninstall', 'npx @getmarrow/mcp uninstall'],
  ['A11 marrow-mcp --setup flag form', 'marrow-mcp --setup'],
  ['A11 marrow-mcp hooks install', 'marrow-mcp hooks-install'],
  ['A11 marrow-mcp unknown word', 'marrow-mcp frobnicate'],
  ['A11 node on the mcp path', 'node /home/u/.npm/_npx/abc/node_modules/@getmarrow/mcp/dist/cli.js repair'],
  ['A12 node on the npx cache path', 'node /home/u/.npm/_npx/h/node_modules/@getmarrow/install/bin/marrow-install.js control disable'],
  ['A13 MARROW_AUTO_HOOK=false before a program', 'MARROW_AUTO_HOOK=false claude -p "x"'],
  ['A13 env MARROW_AUTO_HOOK=', 'env MARROW_AUTO_HOOK=0 claude -p x'],
  ['A13 export MARROW_AUTO_HOOK', 'export MARROW_AUTO_HOOK=false'],
  ['A13 export then assign', 'export MARROW_AUTO_HOOK; MARROW_AUTO_HOOK=false'],
  ['A13 bare assignment', 'MARROW_AUTO_HOOK=false'],
];

for (const [id, command] of ROUTES) {
  test(`T1 held: ${id}`, () => {
    const result = bash(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, command);
    assert.equal(result.protected, true);
    assert.equal(result.risk, 'high');
  });
}

const NOT_ROUTES = [
  ['A16 commit message', 'git commit -m "control disable"'],
  ['A16 grep', 'grep -rn "control disable" docs'],
  ['A16 echo names the installer', 'echo npx @getmarrow/install control disable'],
  ['A16 printf names marrow-mcp setup', 'printf "%s\\n" "marrow-mcp setup"'],
  ['A16 a path that names it', 'cat docs/control-disable.md'],
  ['A16 git log grep', 'git log --grep="marrow-mcp setup"'],
  ['A16 gh pr create body', 'gh pr create --title t --body "run npx @getmarrow/install setup after merge"'],
  ['A16 echo of an assignment', 'echo MARROW_AUTO_HOOK=false'],
  ['A16 cd into the repo', 'cd ~/repos/marrow-mcp && git status'],
  ['A17 doctor', 'npx @getmarrow/install doctor'],
  ['A17 control status', 'npx @getmarrow/install control status'],
  ['A17 control enable', 'npx @getmarrow/install control enable'],
  ['A17 --version', 'npx @getmarrow/install --version'],
  ['A17 marrow-mcp drain-spool', 'marrow-mcp drain-spool'],
  ['A17 marrow-mcp seatbelt-status', 'npx -y @getmarrow/mcp seatbelt-status'],
  ['A17 marrow-mcp hook entrypoint', 'marrow-mcp claude-pre-action-hook'],
  ['A17 npm install of the installer', 'npm install -g @getmarrow/install'],
  ['A17 npm view', 'npm view @getmarrow/install version'],
];

for (const [id, command] of NOT_ROUTES) {
  test(`T1 not a route: ${id}`, () => {
    assert.notEqual(heldLabel(bash(command).action), SECURITY_LABEL, command);
  });
}

test('T1 A1-A3: the option argument is consumed with its option, so programs[] names the program after it, never the argument', () => {
  for (const [command, argument] of [
    ['env -u MARROW_API_KEY npx -y @getmarrow/install@0.1.76 control disable --yes', 'marrow_api_key'],
    ['sudo -u root npx @getmarrow/install control disable', 'root'],
    ['timeout -s KILL 5 npx @getmarrow/install control disable', 'kill'],
  ]) {
    const { programs } = normalizeShellCommand(command);
    assert.equal(programs.includes(argument), false, `${command}: ${JSON.stringify(programs)}`);
  }
});

test('T1 A14: writes to host hook configs are marrow-control holds (Write, Edit, MultiEdit and shell writers)', () => {
  const home = process.env.HOME || homedir();
  const files = ['.claude/settings.json', '.claude/settings.local.json', '.cursor/hooks.json', '.gemini/settings.json'].map((file) => join(home, file));
  for (const file of files) {
    for (const event of [
      { tool_name: 'Write', tool_input: { file_path: file, content: '{}' } },
      { tool_name: 'Edit', tool_input: { file_path: file, old_string: 'a', new_string: 'b' } },
      { tool_name: 'MultiEdit', tool_input: { file_path: file, edits: [{ old_string: 'a', new_string: 'b' }] } },
    ]) {
      const result = classifyTool({ ...event, cwd: tmpdir() });
      assert.ok(result.surfaces.includes('marrow-control'), `${event.tool_name} ${file}`);
    }
  }
  const settings = files[0];
  for (const command of [
    `echo {} | tee ${settings}`, `echo {} > ${settings}`, `sed -i s/a/b/ ${settings}`, `jq . x.json > ${settings}`,
    `cp /dev/null ${settings}`, `mv x.json ${settings}`, `ln -sf /dev/null ${settings}`, `python3 -c "open('${settings}','w')"`,
  ]) {
    assert.ok(bash(command).surfaces.includes('marrow-control'), command);
  }
});

test('T1 TMO: an overrun budget and a thrown reader error hold installer text; text without it stays unheld', () => {
  assert.equal(controlRoute('npx @getmarrow/install doctor', 0, 0), true, 'a spent budget holds');
  assert.equal(controlRoute('ls -la', 0, 0), false);
  const policy = require('../dist/hook-tool-policy.js');
  const original = policy.parseShellSegments;
  policy.parseShellSegments = () => { throw new Error('reader failure'); };
  try {
    assert.equal(controlRoute('npx @getmarrow/install doctor'), true, 'a thrown reader error holds');
    assert.equal(controlRoute('marrow-mcp drain-spool'), true);
  } finally { policy.parseShellSegments = original; }
  assert.equal(controlRoute(`npx @getmarrow/install doctor ${'x'.repeat(9000)}`), true, 'text past the parser bound holds');
});

test('T1 GROW: 8k, 16k, 32k and 1 MB inputs answer within 50 ms each, near-linear', (t) => {
  const times = [];
  for (const size of [8 * 1024, 16 * 1024, 32 * 1024, 1024 * 1024]) {
    for (const unit of ['env -u A ', 'timeout -s KILL 5 ', 'sudo -u root ', 'x ']) {
      const command = `${unit.repeat(Math.ceil(size / unit.length))}npx @getmarrow/install control disable`;
      const start = process.hrtime.bigint();
      const route = controlRoute(command);
      normalizeShellCommand(command);
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      times.push([size, unit.trim(), ms]);
      assert.equal(route, true, `${size} ${unit}`);
      assert.ok(ms <= 50, `${size} ${unit} took ${ms} ms`);
    }
  }
  t.diagnostic(`GROW ${times.map(([size, unit, ms]) => `${size}:${unit}:${ms.toFixed(2)}ms`).join(' ')}`);
});

// ---- collision rows: programs[] and the exact action key -------------------------------------------------------------------------

const salt = randomBytes(32);
const key = (command) => JSON.stringify(normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt }));
// A dummy value of a secret's shape, made at run time: never a live key prefix.
function dummySecret() {
  for (;;) {
    const value = `Qz${randomBytes(30).toString('base64').replace(/[^A-Za-z0-9]/g, '')}`;
    if (/[0-9]/.test(value) && /[a-z]/.test(value) && /[A-Z]/.test(value) && !/^(?:sk|pk|rk)_|^gh[pousr]_|^xox|^AKIA|^AIza/i.test(value)) return value;
  }
}

test('T1 COLL: a wrapper argument changes the key; the program after it is the one in programs[]', () => {
  assert.notEqual(key('env -u A npx X'), key('env -u B npx X'));
  assert.notEqual(key('env -u A npx X'), key('env -u A npx Y'));
  assert.notEqual(key('sudo -u root rm -rf build'), key('sudo -u root rm -rf dist'));
  assert.notEqual(key('timeout -s KILL 5 make a'), key('timeout -s KILL 6 make a'));
  assert.deepEqual(normalizeShellCommand('env -u A npm publish').programs, ['npm']);
  assert.deepEqual(normalizeShellCommand('sudo -u root -g staff rm -rf build').programs, ['rm']);
  assert.deepEqual(normalizeShellCommand('timeout -s KILL 5 git push').programs, ['git']);
  assert.deepEqual(normalizeShellCommand('nice -n 5 ionice -c 2 stdbuf -o L git push').programs, ['git']);
});

test('T1 COLL: a secret-shaped wrapper argument is redacted and never named in programs[]; text after it still keys', () => {
  const secret = dummySecret();
  const other = dummySecret();
  const one = normalizeShellCommand(`env -u ${secret} npm publish`);
  assert.equal(JSON.stringify(one).includes(secret), false, 'no secret in the action');
  assert.equal(JSON.stringify(one).toLowerCase().includes(secret.toLowerCase()), false, 'no secret in programs[]');
  assert.deepEqual(one.programs, ['npm']);
  assert.equal(key(`env -u ${secret} npm publish`).includes(secret), false);
  assert.notEqual(key(`env -u ${secret} npm publish`), key(`env -u ${secret} npm publish --tag next`), 'text after the secret keys');
  assert.notEqual(key(`env -u ${secret} npm publish`), key(`env -u ${other} npm publish --dry-run`));
});

// ---- process-level rows: the built hook, scratch HOME, no network ----------------------------------------------------------------

const dummyKey = () => `mcp-test-dummy-${randomBytes(12).toString('hex')}`;
const CAPTURE = join(__dirname, 'support', 'fetch-capture.cjs');

function makeHome(directory, control = 'on') {
  const home = join(directory, 'home');
  mkdirSync(join(home, '.marrow'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
    version: 1, enabled: control !== 'off', changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
  })}\n`, { mode: 0o600 });
  return home;
}

function run(directory, home, input, env = {}, preload = CAPTURE) {
  const capture = join(directory, `capture-${randomBytes(4).toString('hex')}.ndjson`);
  const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'claude-pre-action-hook'], {
    cwd: home,
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true',
      MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json'), NODE_OPTIONS: `--require ${preload}`, CAPTURE_FILE: capture, ...env,
    },
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: 20_000,
  });
  const lines = existsSync(capture) ? readFileSync(capture, 'utf8').split('\n').filter(Boolean) : [];
  return { result, lines };
}

const A1 = 'env -u MARROW_API_KEY npx -y @getmarrow/install@0.1.76 control disable --yes';
const bashEvent = (command, mode) => ({ session_id: 's-t1', tool_use_id: 't-t1', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, permission_mode: mode });

function withDirectory(body) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-t1-'));
  try { body(directory); } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('T1 A1/A11/A13: auto, bypassPermissions, dontAsk and headless runs deny locally with the owner text, before any network', () => {
  withDirectory((directory) => {
    const home = makeHome(directory);
    for (const [mode, env] of [['auto', {}], ['bypassPermissions', {}], ['dontAsk', {}], ['default', { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' }]]) {
      for (const command of [A1, 'timeout 240 npx -y --package=@getmarrow/mcp@3.9.108 marrow-mcp setup', 'MARROW_AUTO_HOOK=false claude -p "x"']) {
        const key = dummyKey();
        const { result, lines } = run(directory, home, bashEvent(command, mode), { MARROW_API_KEY: key, ...env });
        assert.equal(result.status, 0, result.stderr);
        const output = JSON.parse(result.stdout);
        assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', `${mode} ${command}`);
        assert.equal(output.hookSpecificOutput.permissionDecisionReason, DENY_TEXT);
        assert.equal(lines.length, 0, 'no network call');
        assert.equal(`${result.stdout}${result.stderr}`.includes(key), false);
      }
    }
  });
});

// A18: a backend that ALLOWS (loopback fetch double, no network): the hold is never lifted.
const ALLOW_RUNTIME = { response_mode: 'slim', decision: 'allow', risk_level: 'low', gate_required: false, proof_required: false, proof_complete: true, gate_receipt_id: 'gate-t1' };
const decision = (out) => out.json?.hookSpecificOutput?.permissionDecision;
const hookEvent = (over) => ({ session_id: 's-t1h', hook_event_name: 'PreToolUse', cwd: tmpdir(), ...over });

test('T1 A18: a backend allow never lifts a marrow-control hold: a dialog in default and acceptEdits, a denial in plan, auto and headless', () => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime: ALLOW_RUNTIME });
    const settings = join(h.home, '.claude', 'settings.json');
    const events = [
      { tool_name: 'Bash', tool_input: { command: A1 } },
      { tool_name: 'Bash', tool_input: { command: 'npx @getmarrow/install control disable --yes' } },
      { tool_name: 'Bash', tool_input: { command: 'timeout 240 npx -y --package=@getmarrow/mcp@3.9.108 marrow-mcp setup' } },
      { tool_name: 'Write', tool_input: { file_path: settings, content: '{}' } },
      { tool_name: 'Bash', tool_input: { command: `printf '{}' > ${settings}` } },
    ];
    for (const [index, event] of events.entries()) {
      for (const [mode, env, expected] of [['default', {}, 'ask'], ['acceptEdits', {}, 'ask'], ['plan', {}, 'deny'], ['auto', {}, 'deny'], ['default', { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' }, 'deny']]) {
        const out = h.run('claude-pre-action-hook', hookEvent({ ...event, permission_mode: mode, tool_use_id: `toolu_t1_${index}_${mode}` }), env);
        assert.equal(decision(out), expected, `${mode} ${JSON.stringify(env)} ${event.tool_name} ${index}: ${out.stdout.slice(0, 200)}`);
      }
    }
    // An ordinary action keeps the backend allow.
    const plain = h.run('claude-pre-action-hook', hookEvent({ tool_name: 'Bash', tool_input: { command: 'npm run build' }, permission_mode: 'default', tool_use_id: 'toolu_t1_plain' }));
    assert.notEqual(decision(plain), 'ask');
    assert.notEqual(decision(plain), 'deny');
  } finally { h.cleanup(); }
});

test('T1 A19: with the backend unreachable a marrow-control hold stays held (auto: local denial before any network)', () => {
  withDirectory((directory) => {
    const home = makeHome(directory);
    const preload = join(directory, 'fetch-down.cjs');
    writeFileSync(preload, "'use strict';\nconst fs = require('node:fs');\nglobalThis.fetch = async (url) => { fs.appendFileSync(process.env.CAPTURE_FILE, `${String(url)}\\n`); throw new TypeError('fetch failed'); };\n");
    for (const mode of ['default', 'acceptEdits', 'auto']) {
      const { result, lines } = run(directory, home, bashEvent(A1, mode), { MARROW_API_KEY: dummyKey() }, preload);
      assert.ok(['ask', 'deny'].includes(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision), `${mode}: ${result.stdout}`);
      if (mode === 'auto') assert.equal(lines.length, 0);
    }
  });
});

test('T1 A20: control switched off by the owner still allows (owner opt-out unchanged)', () => {
  withDirectory((directory) => {
    const home = makeHome(directory, 'off');
    const { result } = run(directory, home, bashEvent(A1, 'auto'));
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /"deny"|"ask"/);
  });
});

test('T1 A14/A15: a hook-config write and a link to it are held in every mode, keyless and keyed', () => {
  withDirectory((directory) => {
    const home = makeHome(directory);
    mkdirSync(join(home, '.claude'), { recursive: true });
    const settings = join(home, '.claude', 'settings.json');
    writeFileSync(settings, '{}\n');
    symlinkSync(settings, join(home, 'cfg.json'));
    for (const file of [settings, join(home, 'cfg.json')]) {
      for (const mode of ['auto', 'default']) {
        for (const env of [{}, { MARROW_API_KEY: dummyKey() }]) {
          const event = { session_id: 's-t1w', tool_use_id: 't-t1w', hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: file, content: '{}' }, permission_mode: mode, cwd: home };
          const { result } = run(directory, home, event, env);
          const answer = JSON.parse(result.stdout).hookSpecificOutput.permissionDecision;
          assert.equal(answer, mode === 'auto' ? 'deny' : answer === 'ask' ? 'ask' : 'deny', `${mode} ${file}`);
        }
      }
    }
  });
});

// ---- F3 (patch-t1selfoff-r1): a wrapper command that never bound an approval before T1 still never binds ------------------------
// Before T1 the option argument was read as the program (`sudo -u smbpasswd ls` ran `smbpasswd`), and such a command was withheld
// (truncated). T1 reads `ls`; truncated is the union of both readings, so no command goes from never-binds to bindable.
const NEVER_BINDS_BEFORE = [
  ['F3a env -u smbpasswd', 'env -u smbpasswd ls'],
  ['F3a sudo -u smbpasswd', 'sudo -u smbpasswd ls'],
  ['F3a timeout -s smbpasswd', 'timeout -s smbpasswd 5 ls'],
  ['F3a nice -n smbpasswd', 'nice -n smbpasswd ls'],
  ['F3a sudo --user smbpasswd', 'sudo --user smbpasswd git push origin main'],
  ['F3a doas -u password', 'doas -u password npm test'],
  ['F3a ionice -c token', 'ionice -c token rm -rf build'],
  ['F3a stdbuf -o secret', 'stdbuf -o secret ls'],
  ['F3a xargs -I password', 'xargs -I password ls'],
  ['F3a exec -a token', 'exec -a token ls'],
  ['F3a env -C token', 'env -C token ls'],
  ['F3c ; sudo -u smbpasswd b', 'a; sudo -u smbpasswd b'],
  ['F3c && env -u token npm test', 'ls && env -u token npm test'],
  ['F3c || sudo -u password', 'a || sudo -u password ls'],
  ['F3c pipe into sudo -u vault', 'x | sudo -u vault cat'],
  ['F3c subshell', '( env -u smbpasswd ls )'],
  ['F3c bash -c', 'bash -c "sudo -u smbpasswd ls"'],
  ['F3d repeated option, the secret-named argument first', 'sudo -u smbpasswd -u root ls'],
  ['F3d repeated option, env, the secret-named argument first', 'env -u token -u A ls'],
  ['F3h production deploy', 'sudo -u smbpasswd wrangler deploy --env production'],
];
for (const [id, command] of NEVER_BINDS_BEFORE) {
  test(`T1 F3 never-binds stays never-binds: ${id}`, () => {
    assert.equal(normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt }).truncated, true, command);
  });
}

test('T1 F3: the union keeps T1 programs[] and keys; a benign argument stays bindable; a fed or valued secret stays out of every key', () => {
  assert.deepEqual(normalizeShellCommand('sudo -u smbpasswd ls').programs, ['ls']);
  assert.equal(normalizeShellCommand('sudo -u alice ls').truncated, false);
  assert.equal(normalizeShellCommand('env -u A npm test').truncated, false);
  assert.equal(normalizeShellCommand('git commit -m "env -u smbpasswd ls"').truncated, false, 'F3g a message is as before');
  assert.equal(normalizeShellCommand('env -u A -u token ls').truncated, false, 'F3d last-named argument: bindable before T1 too (the program was A)');
  const secret = dummySecret();
  const other = dummySecret();
  for (const command of [`echo ${secret} | sudo -u root vault kv put secret/app`, `env -u A smbpasswd -a u1 ${secret}`, `echo ${secret} | sudo -u smbpasswd passwd`]) {
    const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt });
    assert.equal(action.truncated, true, 'F3b withheld');
    assert.equal(JSON.stringify(action).toLowerCase().includes(secret.toLowerCase()), false, 'F3b no value in the action');
  }
  // COLLF3: text after the secret keys; only a different secret may match.
  assert.notEqual(key(`env -u A smbpasswd -a u1 ${secret} --tag next`), key(`env -u A smbpasswd -a u1 ${secret} --tag latest`));
  assert.notEqual(key(`sudo -u smbpasswd npm publish --tag next`), key(`sudo -u smbpasswd npm publish --tag latest`));
  assert.notEqual(key(`sudo -u smbpasswd ls`), key(`sudo -u smbpasswdx ls`));
  assert.equal(key(`sudo -u smbpasswd ls ${secret}`).includes(secret), false);
  assert.equal(key(`sudo -u smbpasswd ls ${other}`).includes(other), false);
});

test('T1 F3R: the wrapper forms of the new routes are no more reusable than the plain master route under a backend allow', () => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime: ALLOW_RUNTIME });
    const forms = [
      'npx @getmarrow/install control disable --yes',
      A1,
      'sudo -u root npx @getmarrow/install control disable',
      'timeout -s KILL 5 npx @getmarrow/install control disable',
      'timeout 240 npx -y --package=@getmarrow/mcp@3.9.108 marrow-mcp setup',
      'MARROW_AUTO_HOOK=false claude -p "x"',
    ];
    for (const [mode, env] of [['default', {}], ['plan', {}], ['auto', {}], ['default', { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' }]]) {
      const answers = forms.map((command, index) => {
        assert.equal(held(command), true, command);
        const out = h.run('claude-pre-action-hook', hookEvent({ tool_name: 'Bash', tool_input: { command }, permission_mode: mode, tool_use_id: `toolu_t1_f3r_${index}_${mode}_${Object.keys(env).length}` }), env);
        return decision(out);
      });
      assert.ok(['ask', 'deny'].includes(answers[0]), `${mode} plain`);
      assert.deepEqual(answers, forms.map(() => answers[0]), `${mode} ${JSON.stringify(env)}: every wrapper form answers as the plain route`);
    }
  } finally { h.cleanup(); }
});
