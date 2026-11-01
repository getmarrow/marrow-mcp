const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { controlRoute } = require('../dist/control-routes.js');
const { selfProtectKind } = require('../dist/self-protect.js');
const { heldLabel, backendCategories, missing } = require('./support/mcp-109-n2-categories.cjs');
const { OFF, UN, GAP1, COMPOUND, DECODE, DATA_MENTIONS } = require('./support/mcp0-shapes.cjs');
const BASE = require('./fixtures-mcp0-base.json');

// MCP-0 (spec-nslow F0, premortem GAP-1/GAP-2/GAP-20): a control-off route wrapped in a loop, an if/case, eval, a function, an alias, a wrapper, an
// inline script, a decoded form or a look-alike character is `security on marrow-control`, protected, and denied outright where no person can answer.
// Tightening only: every command keeps at least its 3.9.109 answer (fixtures-mcp0-base.json holds those answers, recorded by running that build).

const SECURITY_LABEL = 'classified Bash action: security on marrow-control';
const DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';
const bash = (command) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: tmpdir() });
const isRoute = (c) => c.surfaces.includes('marrow-control');
const ROUTE_SHAPES = [...GAP1.map((r) => ['GAP1', ...r]), ...COMPOUND.map((r) => ['COMPOUND', ...r]), ...DECODE.map((r) => ['DECODE', ...r])];

// The shapes only the seatbelt mapper (FC5 / M2) can read: the walk cannot see the installer name without running the code or a shell's variable
// and alias resolution. Every other shape is also a text-layer route, proved on controlRoute alone (the mutants below drop one clause each).
const MAPPER_ONLY = new Set(['split name over two variables', 'package removed globally (mapper S0 uninstall_marrow_package)']);

// ---- M0-1 / M1 (GAP-1): the label ------------------------------------------------------------------------------------------------------

for (const [group, id, command] of ROUTE_SHAPES) {
  test(`M0-1 ${group} held as marrow-control: ${id}`, () => {
    const result = bash(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, JSON.stringify(command));
    assert.equal(result.type, 'security');
    assert.equal(result.protected, true);
    assert.equal(result.risk, 'high');
    assert.equal(result.readOnly, false);
    assert.ok(localApprovalCategories(result).includes('secrets_security'), 'a local outage keeps it held as secrets_security');
  });
}

for (const [group, id, command] of ROUTE_SHAPES) {
  if (MAPPER_ONLY.has(id)) continue;
  test(`M0-1 text layer (no mapper) sees ${group}: ${id}`, () => {
    assert.equal(controlRoute(command), true, JSON.stringify(command));
  });
}

// 3.9.109 read the first non-option word after a wrapper as the program, so a wrapper option that takes a value did not hide a following installer
// word from it. The wrapper tables here model those values, and would clear these (nonsense) shapes on their own; the 3.9.109 walk is kept beside them.
test('M0-1: a shape the 3.9.109 walk held stays held when the wrapper tables read its option value differently', () => {
  for (const command of [
    'nice -n npx @getmarrow/install control disable',
    'timeout -s npx @getmarrow/install control disable',
    'sudo -u npx @getmarrow/install control disable',
  ]) assert.equal(controlRoute(command), true, command);
});

test('M0-1: the twins are never lower than 3.9.109 (type rank, risk, protection, risk categories, surfaces)', () => {
  const rank = (type) => ['security', 'publish', 'deploy', 'review', 'migration', 'audit', 'financial', 'process'].indexOf(type);
  const risk = (value) => ['low', 'medium', 'high'].indexOf(value);
  for (const [group, id, command] of [...ROUTE_SHAPES, ...DATA_MENTIONS.map((r) => ['DATA_MENTIONS', ...r])]) {
    const before = BASE[`${group}|${id}`];
    const now = bash(command);
    assert.ok(before, id);
    assert.ok(rank(now.type) <= rank(before.type), `type ${id}: ${before.type} -> ${now.type}`);
    assert.ok(risk(now.risk) >= risk(before.risk), `risk ${id}`);
    assert.ok(now.protected || !before.protected, `protected ${id}`);
    assert.ok(!now.readOnly || before.readOnly, `readOnly ${id}`);
    assert.deepEqual(missing(backendCategories(before.action, before.type, before.surfaces), backendCategories(now.action, now.type, now.surfaces)), [], `categories ${id}`);
    for (const surface of before.surfaces.filter((name) => name !== 'workspace')) assert.ok(now.surfaces.includes(surface), `surface ${surface} kept: ${id}`);
  }
});

// ---- M0-2: the MCP-10 rows are untouched (test/mcp-10-control-routes.test.js is not edited by this change; the install corpus is its own file) ----

// ---- M3 (GAP-20): self-protect and the other consumers keep their 3.9.109 answers on every twin ---------------------------------------------

test('M3: self-protect shellKind answers for every twin are the 3.9.109 answers', () => {
  for (const [group, id, command] of [...ROUTE_SHAPES, ...DATA_MENTIONS.map((r) => ['DATA_MENTIONS', ...r])]) {
    assert.equal(selfProtectKind({ tool_name: 'Bash', tool_input: { command } }, tmpdir()), BASE[`${group}|${id}`].selfKind, id);
  }
});

test('M3: a twin never routes a read of a protected file past self-protect (an effect-read of the control file stays held, in a loop too)', () => {
  for (const command of ['cat ~/.marrow/control.json > /dev/null; rm ~/.marrow/control.json', 'for f in ~/.marrow/control.json; do rm "$f"; done', 'if true; then rm ~/.marrow/control.json; fi']) {
    const result = bash(command);
    assert.equal(result.protected, true, command);
    assert.ok(result.surfaces.includes('marrow-control') || result.surfaces.includes('persistence'), command);
  }
});

// ---- M0-3 / M2 (FC5, GAP-2): the seatbelt mapper, in account mode ---------------------------------------------------------------------------

// Each is an S0 hit of the mapper with a reason that is not an installer text the walk reads: it is a control-off route all the same.
const MAPPER_S0 = [
  ['S0 tripwire: python3 -c subcommand from the environment', `D=disable python3 -c "import os; os.system('npx @getmarrow/install control '+os.environ['D'])"`],
  ['S0 npx_marrow_installer: name split over two variables', 'A=@getmarrow; npx $A/install control disable --yes'],
  ['S0 claude_mcp_remove_marrow', 'claude mcp remove marrow'],
  ['S0 claude_plugin_uninstall_marrow', 'claude plugin uninstall marrow'],
];
for (const [id, command] of MAPPER_S0) {
  test(`M0-3 mapper S0 on a shell call is a control-off route: ${id}`, () => {
    const result = bash(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, command);
    assert.equal(result.protected, true);
  });
}

test('M0-3: an S0 hit that only names a protected path is not a control-off route: a held write keeps its 3.9.109 label, a read stays open', () => {
  assert.equal(heldLabel(bash("echo 'export MARROW_AUTO_HOOK=false' >> ~/.zshrc").action), 'classified Bash action: security on persistence');
  assert.equal(bash("printf '{}' >> ~/.claude/settings.json").protected, true);
  for (const command of ['shellcheck ~/.bashrc', 'jq . ~/.claude/settings.json', 'cat ~/.marrow/control.json']) assert.notEqual(heldLabel(bash(command).action), SECURITY_LABEL, command);
});

test('M0-3: a mapper S0 on a command the walk reads as a safe installer call (doctor, setup, control status/enable, another package) is not a route', () => {
  for (const command of ['npx @getmarrow/install doctor', 'npx @getmarrow/install control status', 'npx -y @getmarrow/install@0.1.76 setup', 'npx @getmarrow/mcp --version',
    'for i in 1 2; do npx @getmarrow/install doctor; done', `node -e "console.log(require('@getmarrow/install/package.json').version)"`]) {
    assert.notEqual(heldLabel(bash(command).action), SECURITY_LABEL, command);
  }
});

test('M0-3: a mapper that exhausts its budget on a call naming a control word is a hold (never a pass)', () => {
  const padding = ': ; '.repeat(6000);
  for (const tail of ['npx $PKG control disable --yes', 'bash -c "$X" disable', 'sudo $INSTALL uninstall']) {
    const command = `${padding}${tail}`;
    const result = bash(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, tail);
  }
  // The same padding with nothing that names the installer or a control word stays what it was.
  assert.notEqual(heldLabel(bash(`${padding}ls`).action), SECURITY_LABEL);
});

const FAIL_MAPPER = join(__dirname, 'support', 'mcp0-fail-mapper.cjs');
function classifyWithBrokenMapper(command) {
  const result = spawnSync(process.execPath, ['-e', `const { classifyTool } = require(${JSON.stringify(join(__dirname, '..', 'dist', 'hook-pre-action.js'))});
const c = classifyTool({ tool_name: 'Bash', tool_input: { command: ${JSON.stringify(command)} }, cwd: '/tmp' });
process.stdout.write(JSON.stringify(c));`], { env: { PATH: process.env.PATH, HOME: tmpdir(), NODE_OPTIONS: `--require ${FAIL_MAPPER}` }, encoding: 'utf8', timeout: 20_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
test('M0-3: a mapper that fails to load, on a call naming the installer or a control word, is a hold; on any other call it changes nothing', () => {
  for (const command of ['npx $PKG control disable --yes', 'A=@getmarrow; npx $A/install control disable --yes', 'node -e "run(\'npx @getmarrow/inst\'+\'all\', \'control disable\')"']) {
    const result = classifyWithBrokenMapper(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, command);
  }
  for (const command of ['ls -la', 'git status', 'npx @getmarrow/install doctor', 'grep -rn marrow src']) {
    assert.notEqual(heldLabel(classifyWithBrokenMapper(command).action), SECURITY_LABEL, command);
  }
});

// ---- M2 decode rule: look-alikes and invisible characters are a hold, never a pass --------------------------------------------------------------

test('M2: the installer pre-check reads the decoded text, never the raw text only', () => {
  for (const command of [
    "npx $'@getmarrow/\\x69nstall' control disable --yes",
    "npx @getmarrow/inst'all' control disable",
    'npx @getmarrow/inst\\all control disable',
    'npx @getmarrow/inst​all control disable --yes',
    'npx @getmarrow/instаll control disable --yes',
    'npx @getmarrow/ｉｎｓｔａｌｌ control disable --yes',
  ]) assert.equal(controlRoute(command), true, JSON.stringify(command));
});

test('M2: a non-ASCII look-alike in a command word is never read-only and never a pass', () => {
  for (const command of ['git pуsh origin master', 'git pu​sh origin master', 'npx @getmarrow/instаll control disable --yes']) {
    assert.equal(bash(command).readOnly, false, command);
  }
  // A look-alike of some other word is data: not a control-off route.
  assert.notEqual(heldLabel(bash('echo café аbc').action), SECURITY_LABEL);
});

// ---- PRESENCE_PARITY: an empty, blank or unparseable command is UNKNOWN (the 3.9.109 label), a hold only where it names the installer and a control word ----------

test('PRESENCE_PARITY: an empty, blank or unparseable command keeps its 3.9.109 label; one that names the installer and a control word is a hold', () => {
  const same = bash('ls').action;
  for (const command of ['', '   ', '\n\t', 'echo "unterminated', "echo 'unterminated", 'echo `unterminated']) {
    const result = bash(command);
    assert.notEqual(heldLabel(result.action), SECURITY_LABEL, JSON.stringify(command));
    assert.equal(result.protected, false, JSON.stringify(command));
    assert.equal(result.readOnly, bash(command).readOnly);
  }
  assert.equal(same, bash('ls').action);
  for (const command of [`echo "${OFF}`, `echo '${OFF}`, `${OFF} \``, `echo "$(${OFF}`, `eval "${OFF}`]) {
    assert.equal(heldLabel(bash(command).action), SECURITY_LABEL, JSON.stringify(command));
  }
  // Naming the installer without a control word, or a control word without the installer, is not enough.
  for (const command of ['echo "marrow-install is great', 'echo "npx other-tool control disable']) assert.notEqual(heldLabel(bash(command).action), SECURITY_LABEL, command);
});

// ---- M6: a read-only data mention is not a NEW refusal --------------------------------------------------------------------------------------

const BASE_REFUSED = new Set();
for (const [id] of DATA_MENTIONS) if (BASE[`DATA_MENTIONS|${id}`].surfaces.includes('marrow-control')) BASE_REFUSED.add(id);

test('M6: the recorded 3.9.109 answers are the five known over-refusals and nothing else (MCP-1 lowers them; this change adds none)', () => {
  assert.deepEqual([...BASE_REFUSED].sort(), [
    'E1a F1 compound read',
    'E1b heredoc writing the F1 text to a fixture',
    'E1c rev-parse loop over the installer and MCP repo names',
    'E1d echo install gh=$(git rev-parse)',
    'case on a repo name',
  ]);
});

for (const [id, command] of DATA_MENTIONS) {
  test(`M6 data mention keeps its 3.9.109 answer (${BASE_REFUSED.has(id) ? 'refused on both' : 'not a route on both'}): ${id}`, () => {
    assert.equal(isRoute(bash(command)), BASE_REFUSED.has(id), JSON.stringify(command));
  });
}

// ---- SHORTCUT rows: an early return never lets a control-off shape through ----------------------------------------------------------------

const plain = bash(OFF);
const SAME_AS_PLAIN = [...GAP1.map((r) => ['GAP1', ...r]), ...COMPOUND.map((r) => ['COMPOUND', ...r]), ...DECODE.map((r) => ['DECODE', ...r])]
  .filter(([, id]) => !/alias runs it|^A15 function|^A15 find|command substitution in a loop|backticks|uninstall|marrow-install|perl|ruby|php|deno|node -p|python/.test(id));

test('X3xP1 (read fast path): no control-off shape is read-only, and none gets an answer other than the plain route\'s', () => {
  for (const [group, id, command] of ROUTE_SHAPES) assert.equal(bash(command).readOnly, false, id);
  for (const [, id, command] of SAME_AS_PLAIN) {
    const result = bash(command);
    // The hold label is the plain route's; the rest of the command (an npm word, a secret read) may add surfaces, never remove the hold.
    assert.equal(heldLabel(result.action), heldLabel(plain.action), id);
    for (const field of ['type', 'risk', 'protected']) assert.deepEqual(result[field], plain[field], `${field}: ${id}`);
    assert.ok(result.surfaces.includes('marrow-control'), id);
  }
});

test('X3xP1: the loop of the spec (F0 A13) never reaches the read fast path, by effect or by word, in every host mode', () => {
  const loop = `for r in marrow-install marrow-mcp; do ${OFF}; done`;
  const result = bash(loop);
  assert.equal(result.readOnly, false);
  assert.equal(result.protected, true);
  assert.equal(isRoute(result), true);
});

test('X2xP1 (own MCP tool): a Marrow tool that carries a control-off shape in a command field is classified like the plain route', () => {
  const own = (command) => classifyTool({ tool_name: 'mcp__marrow__marrow_think', tool_input: { command }, cwd: tmpdir() });
  const base = own(OFF);
  for (const [, id, command] of GAP1.map((r) => ['GAP1', ...r]).concat([['COMPOUND', 'A13', `for r in a; do ${OFF}; done`], ['COMPOUND', 'A15 eval', `eval "${OFF}"`]])) {
    const result = own(command);
    assert.equal(result.protected, base.protected, id);
    assert.equal(isRoute(result), isRoute(base), id);
    assert.ok(!result.readOnly || base.readOnly, id);
  }
  // Other tools that carry a command text: the stricter reading of the text applies, as for the plain route.
  for (const tool_name of ['Monitor', 'PowerShell', 'mcp__other__run']) {
    const result = classifyTool({ tool_name, tool_input: { command: `for r in a; do ${OFF}; done` }, cwd: tmpdir() });
    assert.equal(result.protected, true, tool_name);
  }
});

test('X1/X4-X8 x P1 (cached guidance, outage policy, resumed hold, interactive allow, legacy ask): the held label of a shape is the plain route\'s, so every path keyed on it holds it', () => {
  for (const [, id, command] of SAME_AS_PLAIN) {
    const result = bash(command);
    assert.deepEqual(missing(localApprovalCategories(plain), localApprovalCategories(result)), [], id);
    assert.equal(result.protected && result.risk === 'high' && isRoute(result), true, id);
  }
});

// ---- process rows: the hook ----------------------------------------------------------------------------------------------------------------

const dummyKey = () => {
  const key = `nslowdummy_${randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(?:sk|pk|rk)_|ghp_|gho_|xox[a-z]-|AKIA/, 'a dummy key is never live-shaped');
  return key;
};
const CAPTURE = join(__dirname, 'support', 'fetch-capture.cjs');

function makeHome(directory, control) {
  const home = join(directory, 'home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  if (control !== undefined) {
    mkdirSync(join(home, '.marrow'), { recursive: true, mode: 0o700 });
    writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled: control !== 'off', changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: 0o600 });
  }
  return home;
}

function run(directory, home, input, env = {}) {
  const capture = join(directory, `capture-${randomBytes(4).toString('hex')}.ndjson`);
  const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'claude-pre-action-hook'], {
    cwd: home,
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true',
      MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json'), NODE_OPTIONS: `--require ${CAPTURE}`, CAPTURE_FILE: capture, ...env,
    },
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: 20_000,
  });
  const lines = existsSync(capture) ? readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  return { result, lines };
}
const toolEvent = (session, command, extra = {}) => ({ session_id: session, tool_use_id: `t-${session}`, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, ...extra });

function expectDenied(directory, home, command, extra, env) {
  const { result, lines } = run(directory, home, toolEvent(`s-${randomBytes(3).toString('hex')}`, command, extra), env);
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', `${JSON.stringify(extra)} ${JSON.stringify(command)}`);
  assert.equal(output.hookSpecificOutput.permissionDecisionReason, DENY_TEXT);
  assert.equal(lines.length, 0, 'no network call');
}

test('M0-1: in auto mode the hook denies every shape with the plain owner text, locally (keyless)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    for (const [, , command] of ROUTE_SHAPES) expectDenied(directory, home, command, { permission_mode: 'auto' });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('M0-1: bypassPermissions, dontAsk and a headless entrypoint deny the GAP-1 shapes and the loop, eval and wrapper forms too', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    const some = [...GAP1, ...COMPOUND.filter(([id]) => /^(?:A13|A15 if|A15 eval|while loop|sh -c|nohup|sudo wrapper|heredoc into bash)/.test(id))];
    for (const [, command] of some) {
      for (const mode of ['bypassPermissions', 'dontAsk']) expectDenied(directory, home, command, { permission_mode: mode });
      expectDenied(directory, home, command, { permission_mode: 'default' }, { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' });
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('M0-1: an account-mode session (a key resolves) is denied the same way, with no network call', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    const key = dummyKey();
    for (const [, command] of [...GAP1, ['loop', `for r in a; do ${OFF}; done`], ['eval', `eval "${OFF}"`]]) {
      expectDenied(directory, home, command, { permission_mode: 'auto' }, { MARROW_API_KEY: key });
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('M0-1: in default mode a shape is held like any protected action (deny or ask, never a silent allow)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    for (const command of [`for r in a; do ${OFF}; done`, `eval "${OFF}"`, `sudo -u root ${OFF}`]) {
      const { result } = run(directory, home, toolEvent('s-default', command, { permission_mode: 'default' }));
      assert.equal(result.status, 0, result.stderr);
      assert.ok(['deny', 'ask'].includes(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision), result.stdout);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('X1xP1 (control OFF early return): the owner\'s own switch-off keeps its answer, the same for a shape as for the plain route (no new deny, no new record)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'off');
    const answer = (command) => {
      const { result, lines } = run(directory, home, toolEvent('s-off', command, { permission_mode: 'auto' }), { MARROW_API_KEY: dummyKey() });
      assert.equal(result.status, 0, result.stderr);
      return { stdout: result.stdout, records: lines.length };
    };
    const reference = answer(OFF);
    assert.doesNotMatch(reference.stdout, /needs the account owner/);
    for (const command of [`for r in a; do ${OFF}; done`, `eval "${OFF}"`]) assert.deepEqual(answer(command), reference, command);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('M0-1: a loop, eval and wrapper around control status, enable or doctor is not stopped by this rule', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    for (const command of ['npx @getmarrow/install control status', 'for i in 1; do npx @getmarrow/install control status; done', 'eval "npx @getmarrow/install doctor"', 'sudo -u root npx @getmarrow/install control enable']) {
      const { result } = run(directory, home, toolEvent('s-ok', command, { permission_mode: 'auto' }));
      assert.doesNotMatch(result.stdout, /needs the account owner/, command);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('a dummy-key row asserts the key never reaches output', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0-'));
  try {
    const home = makeHome(directory, 'on');
    const key = dummyKey();
    const { result } = run(directory, home, toolEvent('s-secret', `for r in a; do ${UN}; done`, { permission_mode: 'auto' }), { MARROW_API_KEY: key });
    assert.equal(`${result.stdout}${result.stderr}`.includes(key), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
