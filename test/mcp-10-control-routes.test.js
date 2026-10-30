const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { heldLabel } = require('./support/mcp-109-n2-categories.cjs');

// MCP-10 (spec friction r3 §5, abuse rows C1-C12): while local control is ON the visible control-off routes are held for the owner;
// while it is OFF (or the hooks are switched off) the backend is told, once per host session. (An unsafe control file switches nothing off since the control-state fail-closed fix, so it is not reported.)

const SECURITY_LABEL = 'classified Bash action: security on marrow-control';
const bash = (command) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: tmpdir() });

const ROUTES = [
  ['C1 npx control disable --yes', 'npx @getmarrow/install control disable --yes'],
  ['C2 npx -y pinned version', 'npx -y @getmarrow/install@0.1.76 control disable --yes'],
  ['C3 node on the npx cache path', 'node /home/u/.npm/_npx/abc123/node_modules/@getmarrow/install/bin/marrow-install.js control disable --yes'],
  ['C4 bash -c', "bash -c 'npx @getmarrow/install control disable --yes'"],
  ['C5 variable argument', 'X=control; npx @getmarrow/install $X disable --yes'],
  ['C9 uninstall', 'npx @getmarrow/install uninstall --yes'],
  ['repeated flags, last one wins', 'npx -y --yes -y --yes @getmarrow/install@0.1.76 control disable'],
  ['--package form', 'npx --package=@getmarrow/install@0.1.76 marrow-install control disable --yes'],
  ['-p form', 'npx -p @getmarrow/install marrow-install control disable'],
  ['bare marrow-install', 'marrow-install control disable --yes'],
  ['marrow-install by path', '/usr/local/bin/marrow-install uninstall'],
  ['pnpm dlx', 'pnpm dlx @getmarrow/install control disable --yes'],
  ['bunx', 'bunx @getmarrow/install control disable'],
  ['npm exec', 'npm exec -y -- @getmarrow/install control disable'],
  ['chained with &&', 'echo ok && npx @getmarrow/install control disable --yes'],
  ['chained with ;', 'ls; npx @getmarrow/install control disable'],
  ['chained with ||', 'false || npx @getmarrow/install control disable'],
  ['in a pipe', 'yes | npx @getmarrow/install control disable'],
  ['in a subshell', '(npx @getmarrow/install control disable)'],
  ['command substitution', 'echo $(npx @getmarrow/install control disable)'],
  ['nested bash -c', `bash -c "sh -c 'npx @getmarrow/install control disable'"`],
  ['env prefix', 'env X=1 npx @getmarrow/install control disable'],
  ['sudo wrapper', 'sudo npx @getmarrow/install uninstall'],
  ['program from a variable', 'P=npx; $P @getmarrow/install control disable'],
  ['unknown control subcommand', 'npx @getmarrow/install control off'],
  ['bare control', 'npx @getmarrow/install control'],
  ['mixed case', 'npx @getmarrow/install Control Disable'],
  ['flag spelling', 'npx @getmarrow/install control --disable'],
  ['quoted words', 'npx @getmarrow/install "control" \'disable\''],
  ['split quotes', "npx @getmarrow/install con''trol dis''able"],
  ['glob argument', 'npx @getmarrow/install control dis*'],
  ['heredoc the parser cannot read', "cat <<'EOF' | npx @getmarrow/install control disable\nx\nEOF"],
];

for (const [id, command] of ROUTES) {
  test(`MCP-10 held: ${id}`, () => {
    const result = bash(command);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, command);
    assert.equal(result.protected, true);
    assert.equal(result.risk, 'high');
    assert.ok(localApprovalCategories(result).includes('secrets_security'), 'a local outage keeps it held as secrets_security');
  });
}

const NOT_ROUTES = [
  ['C10 control enable', 'npx @getmarrow/install control enable'],
  ['C10 control status', 'npx @getmarrow/install control status'],
  ['setup', 'npx -y @getmarrow/install@0.1.76 setup'],
  ['doctor', 'npx @getmarrow/install doctor'],
  ['an echo that only names it', 'echo "npx @getmarrow/install control disable"'],
  ['a commit message that names it', 'git commit -m "docs: marrow-install uninstall"'],
  ['a grep that names the file', 'grep -n uninstall marrow-install.js'],
  ['npm install of the installer', 'npm install -g @getmarrow/install'],
  ['control and disable in an unrelated command', 'npx other-tool control disable'],
];

for (const [id, command] of NOT_ROUTES) {
  test(`MCP-10 not a control-off route: ${id}`, () => {
    assert.notEqual(bash(command).action, SECURITY_LABEL, command);
  });
}

test('MCP-10: a non-shell tool, a PowerShell dialect text and Monitor carrying the route are held too', () => {
  const command = 'npx @getmarrow/install control disable --yes';
  for (const event of [
    { tool_name: 'Monitor', tool_input: { command } },
    { tool_name: 'PowerShell', tool_input: { command } },
    { tool_name: 'mcp__other__run', tool_input: { command } },
    { tool_name: 'Bash', tool_input: { command: 'ls', cmd: command } },
  ]) {
    const result = classifyTool({ ...event, cwd: tmpdir() });
    assert.equal(result.protected, true, JSON.stringify(event));
  }
  assert.equal(classifyTool({ tool_name: 'Read', tool_input: { file_path: join(__dirname, 'marrow-install.js') }, cwd: tmpdir() }).protected, false);
});

// ---- process-level rows -------------------------------------------------------------------------------------------------------------

const dummyKey = () => `mcp-test-dummy-${randomBytes(12).toString('hex')}`;
const CAPTURE = join(__dirname, 'support', 'fetch-capture.cjs');

function makeHome(directory, control) {
  const home = join(directory, 'home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  if (control !== undefined) {
    mkdirSync(join(home, '.marrow'), { recursive: true, mode: 0o700 });
    writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled: control === 'off' ? false : true, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: control === 'unsafe' ? 0o644 : 0o600 });
  }
  return home;
}

function run(entry, directory, home, input, env = {}) {
  const capture = join(directory, 'capture.ndjson');
  const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), entry], {
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
  return { result, bypass: lines.filter((line) => /owner-bypass/.test(line.body)), lines };
}

const toolEvent = (session, command, extra = {}) => ({ session_id: session, tool_use_id: `t-${session}`, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, ...extra });

test('MCP-10 C1/C4: in auto, bypassPermissions and dontAsk modes the hook denies a control-off route with the plain owner text, locally', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
  try {
    const home = makeHome(directory, 'on');
    for (const mode of ['auto', 'bypassPermissions', 'dontAsk']) {
      for (const command of ['npx @getmarrow/install control disable --yes', "bash -c 'npx @getmarrow/install uninstall --yes'", 'X=control; npx @getmarrow/install $X disable --yes']) {
        const { result, lines } = run('claude-pre-action-hook', directory, home, toolEvent('s-auto', command, { permission_mode: mode }));
        assert.equal(result.status, 0, result.stderr);
        const output = JSON.parse(result.stdout);
        assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', `${mode} ${command}`);
        assert.equal(output.hookSpecificOutput.permissionDecisionReason, 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.');
        assert.equal(lines.length, 0, 'no network call');
      }
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-10 C1: in default mode the route is held like any protected action (deny or ask, never an allow), keyless too', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
  try {
    const home = makeHome(directory, 'on');
    const { result } = run('claude-pre-action-hook', directory, home, toolEvent('s-default', 'npx @getmarrow/install control disable --yes', { permission_mode: 'default' }));
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.ok(['deny', 'ask'].includes(output.hookSpecificOutput.permissionDecision), result.stdout);
    assert.doesNotMatch(result.stdout, /^$/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-10 C10/C11: control enable and status, and the owner with control off, are not stopped by this rule', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
  try {
    const on = makeHome(directory, 'on');
    const { result } = run('claude-pre-action-hook', directory, on, toolEvent('s-status', 'npx @getmarrow/install control status', { permission_mode: 'auto' }));
    assert.doesNotMatch(result.stdout, /needs the account owner/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-10 visible: control OFF tells the backend on a protected action (the 3.9.108 owner-bypass event stays)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
  try {
    const home = makeHome(directory, 'off');
    const { result, bypass } = run('claude-pre-action-hook', directory, home, toolEvent('s-off', 'npm publish'), { MARROW_API_KEY: dummyKey() });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(bypass.length >= 1, true);
    assert.match(bypass[0].body, /protected action bypassed while local control disabled/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

const HOOKS = [
  ['claude-pre-action-hook', (s) => toolEvent(s, 'ls')],
  ['claude-hook', (s) => ({ session_id: s, tool_use_id: `t-${s}`, hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: { stdout: 'x' } })],
  ['claude-context-hook', (s) => ({ session_id: s, hook_event_name: 'UserPromptSubmit', prompt: 'hello' })],
  ['claude-session-hook', (s) => ({ session_id: s, hook_event_name: 'SessionEnd' })],
  ['claude-permission-request-hook', (s) => ({ session_id: s, hook_event_name: 'PermissionRequest', tool_name: 'Bash', tool_input: { command: 'ls' } })],
];

for (const [entry, payload] of HOOKS) {
  test(`MCP-10 visible: ${entry} with MARROW_AUTO_HOOK=false tells the backend once per session, names only`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
    try {
      const home = makeHome(directory);
      const key = dummyKey();
      const env = { MARROW_API_KEY: key, MARROW_AUTO_HOOK: 'false' };
      const first = run(entry, directory, home, payload('s-quiet-1'), env);
      assert.equal(first.result.status, 0, first.result.stderr);
      assert.equal(first.bypass.length, 1, JSON.stringify(first.lines));
      assert.match(first.bypass[0].body, /protected action bypassed while local control disabled/);
      assert.match(first.bypass[0].body, /marrow:hooks-switched-off/);
      assert.equal(first.bypass[0].body.includes(key), false);
      assert.equal(`${first.result.stdout}${first.result.stderr}`.includes(key), false);
      const again = run(entry, directory, home, payload('s-quiet-1'), env);
      assert.equal(again.bypass.length, 1, 'the same session adds no second event');
      const other = run(entry, directory, home, payload('s-quiet-2'), env);
      assert.equal(other.bypass.length, 2, 'a new session adds one');
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  // Integrated with the control-state fail-closed fix: an unreadable or invalid control file no longer switches any hook off, so no hook
  // goes quiet and there is no bypass to report. The hook behaves exactly as with control ON (pinned by test/hook-control-state-failclosed.test.js).
  test(`MCP-10 visible: ${entry} with an unsafe control.json sends no bypass record (the hook keeps running as if control were on)`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
    try {
      const home = makeHome(directory, 'unsafe');
      const env = { MARROW_API_KEY: dummyKey() };
      const first = run(entry, directory, home, payload('s-unsafe-1'), env);
      assert.equal(first.result.status, 0, first.result.stderr);
      assert.equal(first.bypass.length, 0, JSON.stringify(first.lines));
      const again = run(entry, directory, home, payload('s-unsafe-1'), env);
      assert.equal(again.bypass.length, 0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  test(`MCP-10 visible: ${entry} keyless and switched off sends nothing`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m10-'));
    try {
      const home = makeHome(directory);
      const { result, lines } = run(entry, directory, home, payload('s-keyless'), { MARROW_AUTO_HOOK: 'false' });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(lines.length, 0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}
