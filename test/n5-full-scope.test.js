'use strict';

// N5 hotfix, build 2 (SPEC section 10): the shared normalize/hash path covers EVERY hooked tool and unknown tool names.
// Rule U: every text hash is the per-install keyed MAC (the clear deploy text is the one plain exception).
// Rule P: a program word of a tool that does not run shell text is listed only when it is a known program.
// Rule T: a hold's target is keyed. Dummy values are generated at runtime; nothing here prints one.
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { exactHookTarget, stableToolCorrelation } = require('../dist/hook-contract.js');
const tables = require('../dist/seatbelt/tables.js');
const { BASELINE_POLICY } = require('../vendor/classifier/policy-baseline.js');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { projectCwd } = require('./support/hermetic-project.cjs');
const keyed = require('./support/keyed-text-hash.cjs');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const MOCK = path.join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const FAKE = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const FIXTURES = path.join(__dirname, 'fixtures', 'host-approvals');
const SALT_A = randomBytes(32);
const SALT_B = randomBytes(32);
const sha256 = (text) => createHash('sha256').update(text).digest('hex');

const ALPHA = { hex: '0123456789abcdef', lower: 'abcdefghijklmnopqrstuvwxyz', alnum: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' };
const dummy = (kind, length) => Array.from(randomBytes(length), (byte) => ALPHA[kind][byte % ALPHA[kind].length]).join('');
const SHAPES = [['hex', 16], ['lower', 24]];

/** True when the value, its case-folded form or any 8-char window of it is in the text. */
function reaches(value, secret) {
  const text = JSON.stringify(value);
  const low = text.toLowerCase();
  const s = secret.toLowerCase();
  if (text.includes(secret) || low.includes(s)) return true;
  for (let i = 0; i + 8 <= s.length; i += 1) if (low.includes(s.slice(i, i + 8))) return true;
  return false;
}
const act = (tool, input, options = {}) => normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: SALT_A, ...options });
const hashOf = (action) => action.tool_input.command_sha256 ?? action.tool_input.input_sha256;

// The 11 G-1 tools, the unknown name, and the controls: [tool, input builder (S = the free-text secret)].
const TOOLS = [
  ['WebFetch', (S) => ({ url: 'https://example.com/a', prompt: `summarize and note ${S}` })],
  ['Workflow', (S) => ({ script: `run ${S}` })],
  ['KillShell', (S) => ({ shell_id: S })],
  ['SendMessage', (S) => ({ to: 'agent-b', message: S })],
  ['CronCreate', (S) => ({ cron: '0 * * * *', prompt: S })],
  ['PushNotification', (S) => ({ message: S })],
  ['ExitPlanMode', (S) => ({ plan: `step one then ${S}` })],
  ['SlashCommand', (S) => ({ command: S })],
  ['RemoteTrigger', (S) => ({ prompt: S })],
  ['BashOutput', (S) => ({ bash_id: 'shell_1', filter: S })],
  ['ToolSearch', (S) => ({ query: S })],
  ['FooTool', (S) => ({ command: S })],
  ['FooTool', (S) => ({ cmd: S })],
  ['FooTool', (S) => ({ query: S })],
  ['FooTool', (S) => ({ options: { note: S } })],
  ['NotebookEdit', (S) => ({ notebook_path: '/tmp/x.ipynb', new_source: S })],
  ['Skill', (S) => ({ skill: 'review', args: S })],
  ['TodoWrite', (S) => ({ todos: [{ content: S, status: 'pending' }] })],
  ['TaskOutput', (S) => ({ task_id: S })],
  ['Agent', (S) => ({ description: 'explore', prompt: `use ${S}`, subagent_type: 'general' })],
  ['Task', (S) => ({ description: S, prompt: 'p', subagent_type: 'general' })],
  ['Edit', (S) => ({ file_path: '/tmp/a.txt', old_string: 'x', new_string: `P=${S}` })],
  ['Write', (S) => ({ file_path: '/tmp/a.txt', content: S })],
  ['WebSearch', (S) => ({ query: S })],
  ['mcp__srv__tool', (S) => ({ note: S })],
];

test('rule U: every tool: the text hash is keyed (never the plain hash), per install, and a free-text secret reaches no field', () => {
  for (const [tool, build] of TOOLS) {
    for (const [kind, length] of SHAPES) {
      const secret = dummy(kind, length);
      const twin = dummy(kind, length);
      const a = act(tool, build(secret));
      assert.equal(reaches(a, secret), false, `${tool}: no clear, case-folded or 8-char value in the normalized action`);
      assert.match(hashOf(a), /^[0-9a-f]{64}$/, tool);
      assert.equal(JSON.stringify(a), JSON.stringify(act(tool, build(secret))), `${tool}: stable on one install`);
      assert.notEqual(JSON.stringify(a), JSON.stringify(act(tool, build(twin))), `${tool}: a different free-text value is a different action`);
      assert.notEqual(hashOf(a), hashOf(act(tool, build(secret), { salt: SALT_B })), `${tool}: differs per install`);
      const none = act(tool, build(secret), { salt: null });
      assert.match(hashOf(none), /^[0-9a-f]{64}$/, tool);
      assert.notEqual(hashOf(none), hashOf(act(tool, build(secret), { salt: null })), `${tool}: no key -> a nonce per call (matches nothing)`);
      // The plain hash of any text this action could have been hashed over is never the value sent.
      const text = JSON.stringify(Object.fromEntries(Object.entries(build(secret)).sort()));
      for (const domain of ['input', 'shell']) assert.notEqual(hashOf(a), sha256(`marrow-normalized-action-v3\n${domain}\n${text}`), `${tool}: not the plain ${domain} hash`);
    }
  }
});

test('rule U: pinned formula on representatives of every kind (shell text, other, edit, mcp)', () => {
  const S = dummy('lower', 24);
  const shellText = (command) => normalizeShellCommand(command).text;
  // shell kind: an unknown tool's `command` and ToolSearch's `query` are read as shell text; the tool name is inside the MAC
  assert.equal(act('FooTool', { command: S }).tool_input.command_sha256, keyed.shellMac(SALT_A, 'FooTool', shellText(S)));
  assert.equal(act('ToolSearch', { query: S }).tool_input.command_sha256, keyed.shellMac(SALT_A, 'ToolSearch', shellText(S)));
  // other / edit / mcp: the sorted redacted JSON of the whole input
  const json = (input) => JSON.stringify(Object.fromEntries(Object.entries(input).sort()));
  const agent = { description: 'explore', prompt: `use ${S}`, subagent_type: 'general' };
  assert.equal(act('Agent', agent).tool_input.input_sha256, keyed.inputMac(SALT_A, 'other', 'Agent', json(agent)));
  const edit = { file_path: '/tmp/a.txt', old_string: 'x', new_string: `P=${S}` };
  assert.equal(act('Edit', edit).tool_input.input_sha256, keyed.inputMac(SALT_A, 'edit', 'Edit', json(edit)));
  const mcp = { note: S };
  assert.equal(act('mcp__srv__tool', mcp).tool_input.input_sha256, keyed.inputMac(SALT_A, 'mcp', 'mcp__srv__tool', json(mcp)));
});

test('rule U: the same text under different tool names, or different kinds, never shares a key', () => {
  const S = dummy('lower', 24);
  const hashes = new Set();
  const calls = [['ToolSearch', { query: S }], ['FooTool', { command: S }], ['Bash', { command: S }], ['Monitor', { command: S }], ['PowerShell', { command: S }],
    ['Agent', { prompt: S }], ['Task', { prompt: S }], ['WebFetch', { prompt: S }], ['Workflow', { prompt: S }], ['SlashCommand', { command: S }], ['toolsearch', { query: S }], ['TOOLSEARCH', { query: S }], ['ToolSearch ', { query: S }]];
  for (const [tool, input] of calls) hashes.add(hashOf(act(tool, input)));
  assert.equal(hashes.size, calls.length, 'every call keeps its own key');
  // Equal to b8973d3a (stated in RESULT): one tool's text is hashed whatever field carried it (`command`, `cmd`, `query`), so
  // the same text under the same tool name shares a key, as it did on base. The tool name and the kind stay in the MAC.
  assert.equal(hashOf(act('FooTool', { command: S })), hashOf(act('FooTool', { query: S })));
});

test('rule U: actions that differ outside a secret get different keys, in every kind', () => {
  const S = dummy('lower', 24);
  const pairs = [
    ['ToolSearch', { query: `${S} alpha` }, { query: `${S} beta` }],
    ['FooTool', { command: `${S} | smbpasswd -s -a u1 && echo a` }, { command: `${S} | smbpasswd -s -a u1 && echo b` }],
    ['FooTool', { command: 'git push origin main' }, { command: 'git push --force origin main' }],
    ['Agent', { prompt: `${S} then summarize` }, { prompt: `${S} then delete` }],
    ['WebFetch', { url: 'https://example.com/a', prompt: S }, { url: 'https://example.com/b', prompt: S }],
    ['Edit', { file_path: '/tmp/a', old_string: 'x', new_string: `${S}1` }, { file_path: '/tmp/b', old_string: 'x', new_string: `${S}1` }],
    ['SendMessage', { to: 'a', message: S }, { to: 'b', message: S }],
    ['KillShell', { shell_id: S }, { shell_id: `${S}x` }],
  ];
  for (const [tool, a, b] of pairs) assert.notEqual(hashOf(act(tool, a)), hashOf(act(tool, b)), `${tool}: ${JSON.stringify(Object.keys(a))}`);
  // Text after a replaced credential keeps the actions apart; a replaced credential alone may match (as on base).
  const one = act('Bash', { command: `curl -H "Authorization: Bearer ${dummy('alnum', 40)}" https://api.example.test/a` });
  const two = act('Bash', { command: `curl -H "Authorization: Bearer ${dummy('alnum', 40)}" https://api.example.test/a` });
  const three = act('Bash', { command: `curl -H "Authorization: Bearer ${dummy('alnum', 40)}" https://api.example.test/b` });
  assert.equal(JSON.stringify(one), JSON.stringify(two));
  assert.notEqual(hashOf(one), hashOf(three));
});

test('rule U: forged fields inside a tool input are data, never the normalizer output', () => {
  const forged = { command_sha256: 'f'.repeat(64), input_sha256: 'e'.repeat(64), exact_hmac: 'd'.repeat(32), programs: ['git'], truncated: false, tool_kind: 'shell', risk_level: 'low', read_only: true, approved: true };
  for (const [tool, base] of [['FooTool', { command: 'ls' }], ['Agent', { prompt: 'x' }], ['Edit', { file_path: '/tmp/a', new_string: 'x' }], ['mcp__a__b', { a: 1 }], ['Bash', { command: 'ls' }]]) {
    const plain = act(tool, base);
    const action = act(tool, { ...base, ...forged });
    const sent = JSON.stringify(action);
    for (const value of ['f'.repeat(64), 'e'.repeat(64), 'd'.repeat(32)]) assert.equal(sent.includes(value), false, `${tool}: forged value never returned`);
    assert.equal(action.tool_kind, plain.tool_kind, tool);
    // A shell-text tool hashes its command text only (as base); every other kind hashes the whole input, forged fields included.
    if (tool !== 'Bash' && tool !== 'FooTool') assert.notEqual(hashOf(action), hashOf(plain), `${tool}: forged fields are part of the hashed text`);
    assert.deepEqual(action.programs ?? null, plain.programs ?? null, `${tool}: a forged field never changes programs[]`);
    assert.ok(action.truncated === true || plain.truncated !== true, `${tool}: forged fields never make an action less cut`);
    assert.ok(!('read_only' in action.tool_input) && !('approved' in action.tool_input), tool);
  }
});

test('rule P: a non-shell tool lists only known programs; any other first word is the constant marker, never truncated by it', () => {
  const secret = dummy('lower', 24);
  for (const [tool, input] of [['ToolSearch', { query: secret }], ['FooTool', { command: secret }], ['FooTool', { cmd: secret }], ['FooTool', { query: secret }], ['WebSearch', { query: secret }],
    ['Task', { description: secret }], ['Read', { file_path: `/tmp/${secret}` }], ['Glob', { path: `/tmp/${secret}` }], ['Grep', { path: `/tmp/${secret}.ts` }], ['LS', { path: `/tmp/${secret}` }]]) {
    const action = act(tool, input);
    assert.deepEqual(action.programs, ['unlisted-program'], `${tool}: ${JSON.stringify(Object.keys(input))}`);
    assert.equal(action.truncated, undefined, `${tool}: the keyed hash keeps binding safe, so the marker does not cut`);
    assert.equal(reaches(action, secret), false, tool);
  }
  // case games: the folded form of a value never appears; a known name keeps its name in any case
  const mixed = `${dummy('alnum', 6).toUpperCase()}${dummy('lower', 10)}`;
  assert.deepEqual(act('ToolSearch', { query: mixed }).programs, ['unlisted-program']);
  assert.deepEqual(act('FooTool', { command: 'GIT push --force' }).programs, ['git']);
  assert.deepEqual(act('FooTool', { command: 'git.exe push' }).programs, ['git.exe']);
  // chained stages: every stage is judged
  assert.deepEqual(act('FooTool', { command: `ls && ${secret} | cat` }).programs, ['ls', 'unlisted-program', 'cat']);
  // a feeder stage keeps build 1's rule (marker + cut); the 40-hex word is still never listed
  const feeder = act('FooTool', { command: `${secret} x | smbpasswd -s` });
  assert.deepEqual(feeder.programs, ['unlisted-feeder', 'unlisted-program']); // smbpasswd is no classifier name: a free-text field lists only known programs
  assert.equal(feeder.truncated, true);
  assert.deepEqual(act('FooTool', { command: dummy('hex', 40) }).programs, []);
});

test('rule P: genuine shell tools are unchanged (Bash, Monitor, PowerShell, Codex exec, Cursor Shell keep every program word as on base)', () => {
  for (const tool of ['Bash', 'bash', 'Monitor', 'PowerShell', 'exec_command', 'Shell', 'run_shell_command', 'run_terminal_command', 'execute_command']) {
    const input = tool === 'exec_command' ? { cmd: 'mytool deploy' } : { command: 'mytool deploy' };
    assert.deepEqual(act(tool, input).programs, ['mytool'].map((p) => (tool === 'PowerShell' ? p : p)), tool);
  }
});

test('rule P: dangerous programs keep their names in an unknown tool (the vendored classifier vocabulary and the seatbelt tables are all known)', () => {
  const names = new Set([...tables.KNOWN_COMMANDS, ...tables.INERT_PROGRAMS, ...Object.keys(BASELINE_POLICY.programs)]);
  let checked = 0;
  for (const name of names) {
    if (!/^[a-z0-9][a-z0-9._+-]{0,63}$/.test(name)) continue;
    // Whatever a genuine shell tool lists for the name (a wrapper such as env or sudo lists none itself), an unknown tool lists too.
    const shell = act('Bash', { command: `${name} --flag` });
    const action = act('FooTool', { command: `${name} --flag` });
    assert.deepEqual(action.programs, shell.programs, `${name} keeps its name`);
    if (shell.programs.length) checked += 1;
  }
  assert.ok(checked > 300, `checked ${checked} names`);
  for (const command of ['psql prod -c "drop table x"', 'crontab -r', 'systemctl stop nginx', 'iptables -F', 'mysql -e "drop database a"', 'wrangler deploy --env production', 'terraform destroy', 'rm -rf /']) {
    const programs = act('FooTool', { command }).programs;
    assert.ok(!programs.includes('unlisted-program'), command);
  }
});

test('rule U exception E1: only the grammar-bound deploy text sent in clear keeps the plain hash', () => {
  const plain = (text, domain = 'shell') => sha256(`marrow-normalized-action-v3\n${domain}\n${text}`);
  const deploy = act('Bash', { command: 'sst deploy --stage production' });
  assert.equal(deploy.tool_input.command, 'sst deploy --stage production');
  assert.equal(deploy.tool_input.command_sha256, plain('sst deploy --stage production'), 'the hash of text sent in clear stays plain (the service binds a deploy word for word)');
  // numbers and booleans in the run options keep it plain; any other value takes the keyed form
  const monitor = act('Monitor', { command: 'sst deploy --stage production', timeout: 5 });
  assert.equal(monitor.tool_input.command_sha256, sha256(`marrow-normalized-action-v3\nshell-tool+run\n"Monitor"\n${sha256('marrow-normalized-action-v3\ninput\n{"timeout":5}')}\nsst deploy --stage production`));
  const odd = act('Monitor', { command: 'sst deploy --stage production', timeout: dummy('lower', 24) });
  assert.notEqual(odd.tool_input.command_sha256, plain('sst deploy --stage production'));
  assert.match(odd.tool_input.command_sha256, /^[0-9a-f]{64}$/);
  // a deploy the service cannot judge word for word is keyed like every other command
  const wrangler = act('Bash', { command: 'wrangler deploy --env production' });
  assert.equal(wrangler.tool_input.command, undefined);
  assert.equal(wrangler.tool_input.command_sha256, keyed.shellMac(SALT_A, 'Bash', 'wrangler deploy --env production'));
});

test('rule T: the hold target is a keyed hash over the same parts (never the plain hash)', () => {
  const event = { tool_name: 'Bash', tool_input: { command: 'ls' } };
  const salt = keyed.deviceSalt();
  const target = exactHookTarget(event);
  assert.equal(target, keyed.targetMac(salt, ['Bash', 'host-name', [null, null, null, null], null]));
  assert.notEqual(target, sha256(JSON.stringify(['marrow-hook-target-v1', 'Bash', 'host-name', [null, null, null, null], null])));
  assert.equal(target, exactHookTarget(event));
  // nested server/tool names are tool input: a free-text value there never reaches the target in clear or plain
  const value = dummy('lower', 24);
  const nested = exactHookTarget({ tool_name: 'FooTool', tool_input: { toolName: value } });
  assert.equal(nested, keyed.targetMac(salt, ['FooTool', 'host-name', [null, null, value, null], null]));
  assert.equal(nested.includes(value), false);
  assert.notEqual(nested, sha256(JSON.stringify(['marrow-hook-target-v1', 'FooTool', 'host-name', [null, null, value, null], null])));
  assert.notEqual(nested, exactHookTarget({ tool_name: 'FooTool', tool_input: { toolName: dummy('lower', 24) } }));
});

test('migration: the correlation of a call never equals the one the old plain formula gave; a deploy sent in clear keeps its plain value', () => {
  const session = 'session-n5';
  for (const [tool, input] of [['ToolSearch', { query: 'select:Read' }], ['FooTool', { command: 'ls -la' }], ['Agent', { prompt: 'hello' }], ['Bash', { command: 'npm test' }]]) {
    const action = normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: keyed.deviceSalt() });
    const oldPlainHash = action.tool_input.command_sha256 !== undefined
      ? { command_sha256: sha256(`marrow-normalized-action-v3\nshell\n${normalizeShellCommand(typeof input.command === 'string' ? input.command : input.query ?? '').text}`) }
      : { input_sha256: sha256(`marrow-normalized-action-v3\ninput\n${JSON.stringify(Object.fromEntries(Object.entries(input).sort()))}`) };
    assert.notEqual(Object.values(action.tool_input)[0], Object.values(oldPlainHash)[0], `${tool}: an old key never matches`);
    const sorted = (value) => (Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sorted(value[k])])) : value);
    const stable = (identityInput) => createHash('sha256').update(JSON.stringify(sorted([session, tool, { kind: action.tool_kind, programs: action.programs ?? null, paths: action.paths ?? null, input: identityInput }]))).digest('hex').slice(0, 32);
    assert.equal(stableToolCorrelation({ session_id: session, tool_name: tool, tool_input: input }), stable(action.tool_input), `${tool}: the correlation is over the keyed action`);
    assert.notEqual(stableToolCorrelation({ session_id: session, tool_name: tool, tool_input: input }), stable(oldPlainHash), `${tool}: an old hold's correlation is never claimed`);
  }
});

// ---- key store states for a BINDABLE action: a child process per state (the device key is cached per process) ----

const CHILD = `
const { normalizedHookAction } = require(${JSON.stringify(path.join(ROOT, 'dist/normalized-action.js'))});
const event = { tool_name: 'FooTool', tool_input: { command: process.argv[1] } };
const a = normalizedHookAction(event, {});
const b = normalizedHookAction(event, {});
process.stdout.write(JSON.stringify({ sha: a.tool_input.command_sha256, sha2: b.tool_input.command_sha256, truncated: a.truncated === true }));
`;
function runChild(passwdHome, command) {
  const result = spawnSync(process.execPath, ['-e', CHILD, command], {
    env: { PATH: process.env.PATH, HOME: passwdHome, SBT_PASSWD_HOME: passwdHome }, encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(result.status, 0, 'child exit');
  return { out: JSON.parse(result.stdout), stderr: result.stderr };
}
function freshHome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-n5b2-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}
function seatbeltDir(home) {
  const marrow = path.join(home, '.marrow');
  const dir = path.join(marrow, 'seatbelt');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(marrow, 0o700);
  fs.chmodSync(dir, 0o700);
  return dir;
}

test('key store (bindable action): created once, stable across processes, per install, never printed', () => {
  const command = `ls ${dummy('lower', 12)}`;
  const home = freshHome();
  const first = runChild(home, command);
  const second = runChild(home, command);
  assert.equal(first.out.sha, second.out.sha);
  assert.equal(first.out.sha, first.out.sha2);
  assert.equal(first.out.truncated, false);
  assert.notEqual(first.out.sha, sha256(`marrow-normalized-action-v3\nshell\n${normalizeShellCommand(command).text}`));
  assert.equal(first.out.sha, keyed.shellMac(fs.readFileSync(path.join(home, '.marrow', 'seatbelt', 'salt')), 'FooTool', normalizeShellCommand(command).text));
  const other = runChild(freshHome(), command);
  assert.notEqual(other.out.sha, first.out.sha, 'a second install has its own key');
  const key = fs.readFileSync(path.join(home, '.marrow', 'seatbelt', 'salt'));
  for (const text of [JSON.stringify(first.out), first.stderr]) assert.equal(text.includes(key.toString('hex')) || text.includes(key.toString('base64')), false);
  // Rotation: the next start makes a new key and every keyed value changes (an old hold or approval is asked again).
  fs.unlinkSync(path.join(home, '.marrow', 'seatbelt', 'salt'));
  assert.notEqual(runChild(home, command).out.sha, first.out.sha);
});

test('key store (bindable action): unsafe, corrupt, unreadable or unwritable key -> a nonce per call, one note, no plain hash', () => {
  const command = `ls ${dummy('lower', 12)}`;
  const states = {
    'wrong mode (group-readable)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o644 }); fs.chmodSync(path.join(dir, 'salt'), 0o644); },
    'corrupt (short)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(16), { mode: 0o600 }); },
    'symlink': (dir) => { const target = path.join(dir, '..', 'real-salt'); fs.writeFileSync(target, randomBytes(32), { mode: 0o600 }); fs.symlinkSync(target, path.join(dir, 'salt')); },
    'unreadable': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o000 }); fs.chmodSync(path.join(dir, 'salt'), 0o000); },
    'directory unsafe (group-writable)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o600 }); fs.chmodSync(dir, 0o770); },
  };
  for (const [name, make] of Object.entries(states)) {
    const home = freshHome();
    make(seatbeltDir(home));
    const { out, stderr } = runChild(home, command);
    assert.match(out.sha, /^[0-9a-f]{64}$/, name);
    assert.notEqual(out.sha, sha256(`marrow-normalized-action-v3\nshell\n${normalizeShellCommand(command).text}`), `${name}: never the plain hash`);
    assert.notEqual(out.sha, out.sha2, `${name}: a nonce per call`);
    assert.notEqual(runChild(home, command).out.sha, out.sha, `${name}: nothing matches across processes`);
    const notes = stderr.split('\n').filter((line) => line.includes('private device key'));
    assert.equal(notes.length, 1, `${name}: one note per process`);
    assert.equal(/\/|salt/.test(notes[0]), false, `${name}: no path in the note`);
  }
  const home = freshHome();
  fs.chmodSync(home, 0o500);
  try {
    const { out } = runChild(home, command);
    assert.notEqual(out.sha, out.sha2, 'read-only home: nonce');
    assert.equal(fs.existsSync(path.join(home, '.marrow')), false, 'nothing was created');
  } finally {
    fs.chmodSync(home, 0o700);
  }
});

test('key store (bindable action): concurrent first starts agree on one key', () => {
  const command = `ls ${dummy('lower', 12)}`;
  const home = freshHome();
  const results = Array.from({ length: 6 }, () => runChild(home, command).out.sha);
  assert.equal(new Set(results).size, 1);
});

// ---- the real hook: wire body and local state, per tool ----

function wireRun(entry, event, tool) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-n5b2-wire-'));
  const homeDir = path.join(dir, 'home');
  const passwd = path.join(dir, 'passwd');
  const mock = path.join(dir, 'mock');
  for (const d of [homeDir, passwd, mock]) fs.mkdirSync(d, { mode: 0o700 });
  writeOfficialHostConfigs(homeDir);
  const receipt = 'gate-n5b2';
  fs.writeFileSync(path.join(mock, 'config.json'), JSON.stringify({
    runtime: {
      ok: true, action: 'classified action', decision_id: `decision-${receipt}`,
      runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: `decision-${receipt}` },
      gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
      proof_pack: { required: false, fields: [], complete: true },
      completion_contract: { decision_id: `decision-${receipt}`, decision_creation_required: false, decision_state: 'created', owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true, required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'], owner_approval: { mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false, trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id', approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner', approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000, host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true, host_approval_trust: 'client_attested', approval_categories: ['production_deploy'], verified_approval_required: false, verified_approval_categories: [] } },
      risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
      gate_receipt_id: receipt, exact_next_action: 'Obtain explicit owner approval before this action runs.',
    },
    status: { [receipt]: 'pending' },
  }));
  const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  const result = spawnSync(process.execPath, [CLI, entry], {
    input: JSON.stringify(event), cwd: projectCwd(), encoding: 'utf8', timeout: 30_000,
    env: {
      PATH: process.env.PATH, HOME: homeDir, SBT_PASSWD_HOME: passwd, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one',
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false', MARROW_TEST_MOCK_DIR: mock, NODE_OPTIONS: `--require=${FAKE} --require=${MOCK}`,
    },
  });
  assert.equal(result.error, undefined);
  const lines = fs.existsSync(path.join(mock, 'requests.jsonl')) ? fs.readFileSync(path.join(mock, 'requests.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  const statePath = path.join(homeDir, '.marrow', 'host-approvals', 'state.json');
  const state = fs.existsSync(statePath) ? fs.readFileSync(statePath, 'utf8') : '';
  const out = { requests: lines, state, stdio: `${result.stdout}${result.stderr}`, salt: fs.existsSync(path.join(passwd, '.marrow', 'seatbelt', 'salt')) ? fs.readFileSync(path.join(passwd, '.marrow', 'seatbelt', 'salt')) : null, tool };
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

test('real hook (Claude PreToolUse): a free-text secret reaches no request body, no state.json and no output; the hash is keyed; programs[] holds no value', () => {
  const pre = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'claude-pre-tool-use.json'), 'utf8'));
  for (const [tool, build] of TOOLS.filter(([tool]) => ['WebFetch', 'KillShell', 'SendMessage', 'RemoteTrigger', 'BashOutput', 'ToolSearch', 'FooTool', 'Agent', 'Edit'].includes(tool))) {
    const secret = dummy('lower', 24);
    const run = wireRun('claude-pre-action-hook', { ...pre, tool_name: tool, tool_input: build(secret) }, tool);
    const runtime = run.requests.filter((r) => r.path === '/v1/agent/runtime');
    assert.equal(runtime.length, 1, `${tool}: one gate request`);
    for (const [label, text] of [['bodies', JSON.stringify(run.requests)], ['state', run.state], ['stdio', run.stdio]]) assert.equal(reaches(text, secret), false, `${tool}: no value, case-folded value or 8-char window in ${label}`);
    const action = runtime[0].body.normalized_action;
    assert.match(action.tool_input.command_sha256 ?? action.tool_input.input_sha256, /^[0-9a-f]{64}$/, tool);
    assert.ok(run.salt && run.salt.length === 32, 'the install made its key');
    const keyHex = [run.salt.toString('hex'), run.salt.toString('base64'), run.salt.toString('base64url')];
    for (const text of [JSON.stringify(run.requests), run.state, run.stdio]) assert.equal(keyHex.some((k) => text.includes(k)), false, `${tool}: the key is in no output`);
    assert.ok((action.programs || []).every((p) => ['unlisted-program', 'unlisted-feeder'].includes(p)), `${tool}: programs[] holds markers only`);
  }
});

test('real hook (Codex and Cursor): a feeder secret and an unknown-tool secret reach nothing, and the same hash rules hold', () => {
  const secret = dummy('lower', 24);
  const codex = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'codex-pre-tool-use.json'), 'utf8'));
  const cursorBefore = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'cursor-before-shell.json'), 'utf8'));
  const cursorPre = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'cursor-pre-tool-use.json'), 'utf8'));
  const command = `"${secret}" | smbpasswd -s -a u1`;
  for (const [entry, event] of [
    ['codex-pre-action-hook', { ...codex, tool_input: { command } }],
    ['cursor-pre-action-hook', { ...cursorBefore, command }],
    ['cursor-pre-action-hook', { ...cursorPre, tool_input: { command, working_directory: '/home/operator/project' } }],
  ]) {
    const run = wireRun(entry, event, 'Shell');
    for (const [label, text] of [['bodies', JSON.stringify(run.requests)], ['state', run.state], ['stdio', run.stdio]]) assert.equal(reaches(text, secret), false, `${entry}: nothing in ${label}`);
  }
});
