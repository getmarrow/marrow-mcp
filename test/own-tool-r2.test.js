const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { MARROW_OWN_TOOL_NAMES, nativeHookMatcher } = require('../dist/own-tool.js');
const { isMcpHookTool } = require('../dist/hook-tool-policy.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const {
  LEGACY_NATIVE_HOOK_MATCHERS,
  NATIVE_HOOK_MATCHER,
  ACTION_RESULT_HOOK_COMMAND,
  PERMISSION_REQUEST_HOOK_COMMAND,
  PRE_ACTION_HOOK_COMMAND,
  localHookConfigurationFingerprint,
  localHookRepairStatus,
  stableToolCorrelation,
} = require('../dist/hook-contract.js');
const { installPostToolUseHook, installPermissionRequestHook } = require('../dist/hook.js');
const { installUserPromptSubmitHook } = require('../dist/hook-context.js');
const { installSessionEndHook } = require('../dist/hook-session.js');
const { classifyTool, installPreActionHook, runPreActionHookCommand } = require('../dist/hook-pre-action.js');

// The list marrow-install writes from: the 58 registered names, in file order.
const FIXTURE = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'marrow-own-tool-names.json'), 'utf8'));
const OWN = FIXTURE.names;
const LEGACY = 'Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|functions\\.(?!mcp__marrow__marrow_).*|mcp__(?!marrow__marrow_).*';

// Hosts full-match the matcher (test/hook-install.test.js). Search is checked too, so a host
// that does not anchor it still never skips anything but an exact own name.
const full = new RegExp(`^(?:${NATIVE_HOOK_MATCHER})$`);
const search = new RegExp(NATIVE_HOOK_MATCHER);
const legacyFull = new RegExp(`^(?:${LEGACY})$`);
// r3 (shared policy, marrow-install host-label-research.md): only Claude Code's label proves server
// `marrow`, so the matcher skips only `mcp__marrow__<own>`; `functions.mcp__marrow__<own>` reaches the hook
// (which still allows it: no lockout).
const OWN_FORMS = new Set(OWN.map((name) => `mcp__marrow__${name}`));

function variantsOf(name) {
  return [
    `${name} `, ` ${name}`, `${name}\n`, `${name}\t`, `${name}\0`, `${name}x`, `${name}_`, name.slice(0, -1),
    name.toUpperCase(), `${name[0].toUpperCase()}${name.slice(1)}`, `${name}​`, `${name}$`,
  ];
}

function corpus() {
  const names = new Set(['Bash', 'Edit', 'Write', 'MultiEdit', 'Read', 'Glob', 'Grep', 'Search', 'WebSearch', 'Task',
    'functions.exec', 'functions.apply_patch', 'mcp__payments__refund', 'mcp__marrow_evil__delete', 'mcp__evil__x',
    'mcp__marrow__marrow_delete_all', 'mcp__MARROW__marrow_commit', 'mcp__marrow__marrow_commit ', 'mcp__marrow__',
    'mcp__marrow__marrow', 'mcp__marrow__marrow_', 'functions.mcp__marrow__marrow_exec', 'functions.mcp__evil__x',
    'mcp__marrow__marrow_commit|marrow_ask', 'mcp__marrow__marrow_commit)$', 'mcp__marrow__marrow_commit__mcp__github__push',
    'mcp__marrow__mcp__marrow__marrow_commit', 'functions.functions.mcp__marrow__marrow_commit']);
  for (const name of OWN) {
    names.add(`mcp__marrow__${name}`);
    names.add(`functions.mcp__marrow__${name}`);
    for (const variant of variantsOf(name)) {
      names.add(`mcp__marrow__${variant}`);
      names.add(`functions.mcp__marrow__${variant}`);
    }
    for (const server of ['MARROW', 'Marrow', 'marrow2', 'marrow_', 'evil', 'marrow ']) {
      names.add(`mcp__${server}__${name}`);
      names.add(`functions.mcp__${server}__${name}`);
    }
  }
  return [...names];
}

test('M1: the native matcher is generated from the registered names and matches the shared rule byte for byte', () => {
  assert.equal(FIXTURE.count, 58);
  assert.equal(OWN.length, 58);
  assert.deepEqual(OWN, [...MARROW_OWN_TOOL_NAMES].sort(), 'the fixture is the registry in sorted (file) order');
  const joined = OWN.join('|');
  // r3: the shared string marrow-install writes (byte-identical): start-anchored, `[\\s\\S]*` in every consuming part.
  const expected = `Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|^(?!mcp__marrow__(?:${joined})$)[\\s\\S]*(?:functions\\.|mcp__)[\\s\\S]*`;
  const r2 = `Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|functions\\.(?!mcp__marrow__(?:${joined})$).*|mcp__(?!marrow__(?:${joined})$).*`;
  assert.equal(NATIVE_HOOK_MATCHER, expected);
  assert.equal(nativeHookMatcher(), expected);
  assert.equal(nativeHookMatcher([...OWN].reverse()), expected, 'order of the input never changes the string');
  assert.equal(require('../dist/hook.js').AUTO_HOOK_MATCHER, expected);
  // The r2 string with `.*` (never released) is legacy too, so a hook written with it is repaired.
  assert.deepEqual(LEGACY_NATIVE_HOOK_MATCHERS, [LEGACY, r2]);
  // A regex character in a name is escaped, never interpreted.
  assert.match(nativeHookMatcher(['a.b|c']), /\(\?:a\\\.b\\\|c\)\$/);
});

test('M1: the matcher skips exactly the 58 own names on server marrow and nothing else', () => {
  for (const name of ['mcp__marrow__marrow_delete_all', 'mcp__MARROW__marrow_commit', 'mcp__marrow__marrow_commit ', 'mcp__evil__x']) {
    assert.equal(full.test(name), true, name);
    assert.equal(search.test(name), true, name);
  }
  const names = corpus();
  assert.ok(names.length > 2000, `corpus ${names.length}`);
  let skipped = 0;
  // r3 closes the r2 gap: `[\s\S]*` crosses line terminators, so a full-matching host no longer
  // skips a name that contains one (the old matcher did; never looser than it).
  const LINE = /[\n\r\u2028\u2029]/;
  assert.ok(names.filter((n) => LINE.test(n)).length > 100);
  for (const name of names.filter((n) => LINE.test(n))) {
    assert.equal(full.test(name), true, JSON.stringify(name));
    assert.equal(legacyFull.test(name), false, `the old matcher skipped it ${JSON.stringify(name)}`);
    assert.equal(search.test(name), !OWN_FORMS.has(name), JSON.stringify(name));
  }
  for (const name of names.filter((n) => !LINE.test(n))) {
    const own = OWN_FORMS.has(name);
    assert.equal(full.test(name), !own, `full ${JSON.stringify(name)}`);
    assert.equal(search.test(name), !own, `search ${JSON.stringify(name)}`);
    // Never looser than the old matcher: whatever it sent to the hook still goes there.
    if (legacyFull.test(name)) assert.equal(full.test(name), true, `legacy covered ${JSON.stringify(name)}`);
    if (!full.test(name)) skipped += 1;
  }
  assert.equal(skipped, 58, '58 names, Claude Code form only');
  // The unregistered names the old matcher skipped now reach the hook.
  for (const name of ['mcp__marrow__marrow_delete_all', 'mcp__marrow__marrow_x', 'functions.mcp__marrow__marrow_exec', 'mcp__marrow__marrow_commitx']) {
    assert.equal(legacyFull.test(name), false, name);
    assert.equal(full.test(name), true, name);
  }
});

function withSettings(value, callback) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-r2-hooks-'));
  const settingsDir = join(directory, '.claude');
  const settingsPath = join(settingsDir, 'settings.json');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(value, null, 2));
  try {
    return callback({ directory, settingsPath });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function installAll(directory) {
  installPostToolUseHook(directory);
  installUserPromptSubmitHook(directory);
  installPreActionHook(directory);
  installPermissionRequestHook(directory);
  installSessionEndHook(directory);
}

function freshFingerprint() {
  return withSettings({}, ({ directory }) => {
    installAll(directory);
    return localHookConfigurationFingerprint(directory);
  });
}

function oldInstall(matcher) {
  const entry = (command, extra = {}) => [{ ...(matcher === undefined ? {} : { matcher }), hooks: [{ type: 'command', command, ...extra }] }];
  return {
    hooks: {
      PreToolUse: entry(PRE_ACTION_HOOK_COMMAND),
      PostToolUse: entry(ACTION_RESULT_HOOK_COMMAND),
      PostToolUseFailure: entry(ACTION_RESULT_HOOK_COMMAND),
      PermissionRequest: entry(PERMISSION_REQUEST_HOOK_COMMAND, { async: true }),
    },
  };
}

test('M1: hooks written with the old matcher are reported as needing repair, and setup rewrites them', () => {
  const healthy = freshFingerprint();
  withSettings({}, ({ directory }) => {
    installAll(directory);
    assert.deepEqual(localHookRepairStatus(directory), { needs_repair: false, stale_matchers: [] });
  });
  for (const matcher of [LEGACY, undefined, 'Bash|mcp__.*', `${NATIVE_HOOK_MATCHER} `]) {
    withSettings(oldInstall(matcher), ({ directory, settingsPath }) => {
      const status = localHookRepairStatus(directory);
      assert.equal(status.needs_repair, true, String(matcher));
      assert.deepEqual(status.stale_matchers.map((entry) => entry.event), ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest']);
      for (const entry of status.stale_matchers) {
        assert.equal(entry.matcher, matcher ?? null);
        assert.equal(entry.legacy, matcher === LEGACY);
      }
      const stale = localHookConfigurationFingerprint(directory);
      assert.notEqual(stale, healthy, 'an old-matcher install never fingerprints as healthy');

      installAll(directory);
      assert.deepEqual(localHookRepairStatus(directory), { needs_repair: false, stale_matchers: [] });
      const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
      for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest']) {
        assert.equal(settings.hooks[event].length, 1, event);
        assert.equal(settings.hooks[event][0].matcher, NATIVE_HOOK_MATCHER, event);
      }
      assert.equal(localHookConfigurationFingerprint(directory), healthy, 'repaired install fingerprints as a fresh one');
    });
  }
  // A stale handler beside a current one is still reported (the host runs both).
  withSettings({}, ({ directory, settingsPath }) => {
    installAll(directory);
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    settings.hooks.PreToolUse.push(oldInstall(LEGACY).hooks.PreToolUse[0]);
    writeFileSync(settingsPath, JSON.stringify(settings));
    assert.equal(localHookRepairStatus(directory).needs_repair, true);
    assert.notEqual(localHookConfigurationFingerprint(directory), healthy);
    installPreActionHook(directory);
    assert.equal(localHookRepairStatus(directory).needs_repair, false);
  });
  // A stale matcher on PermissionRequest alone (not in the active-handler list) still changes the fingerprint.
  withSettings({}, ({ directory, settingsPath }) => {
    installAll(directory);
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    settings.hooks.PermissionRequest[0].matcher = LEGACY;
    writeFileSync(settingsPath, JSON.stringify(settings));
    assert.deepEqual(localHookRepairStatus(directory).stale_matchers.map((entry) => entry.event), ['PermissionRequest']);
    assert.notEqual(localHookConfigurationFingerprint(directory), healthy);
  });
  // Non-Marrow hooks with any matcher are not Marrow's to repair.
  withSettings({ hooks: { PreToolUse: [{ matcher: LEGACY, hooks: [{ type: 'command', command: 'echo other' }] }] } }, ({ directory }) => {
    assert.equal(localHookRepairStatus(directory).needs_repair, false);
  });
});

const ENV_KEYS = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID'];

async function runPre(entrypoint, payload) {
  const previous = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  const originalArg = process.argv[2];
  const originalWrite = process.stdout.write;
  const originalError = process.stderr.write;
  const originalExitCode = process.exitCode;
  let stdout = '';
  process.argv[2] = entrypoint;
  for (const key of ENV_KEYS) delete process.env[key];
  process.exitCode = undefined;
  process.stdout.write = (chunk) => { stdout += String(chunk); return true; };
  process.stderr.write = () => true;
  try {
    await runPreActionHookCommand(payload);
    return `${stdout}|${process.exitCode ?? 0}`;
  } finally {
    process.stdout.write = originalWrite;
    process.stderr.write = originalError;
    process.exitCode = originalExitCode;
    process.argv[2] = originalArg;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

const G1_FORMS = ['mcp__evil__delete_all', 'mcp_evil_delete_all', 'MCP:evil:delete_all', 'MCP:delete_all', 'MCP__evil__delete_all', 'Mcp_evil_delete_all'];
const G1_PREFIXES = ['functions.', 'FUNCTIONS.', 'Functions.', 'functions.functions.', 'functions. ', ' functions.'];

test('G1: functions.-prefixed MCP tools are MCP tools in every host form', () => {
  for (const form of G1_FORMS) {
    assert.equal(isMcpHookTool(form), true, form);
    for (const prefix of G1_PREFIXES) assert.equal(isMcpHookTool(`${prefix}${form}`), true, `${prefix}${form}`);
  }
  for (const name of ['functions.exec', 'functions.apply_patch', 'functions.', 'functions.mcp', 'Bash', 'functionsXmcp__evil__x', 'xfunctions.mcp__evil__x']) {
    assert.equal(isMcpHookTool(name), false, name);
  }
  for (const form of G1_FORMS) {
    for (const prefix of G1_PREFIXES) {
      const prefixed = classifyTool({ tool_name: `${prefix}${form}`, tool_input: {} });
      const bare = classifyTool({ tool_name: form, tool_input: {} });
      assert.equal(prefixed.risk, 'high', `${prefix}${form}`);
      assert.equal(prefixed.risk, bare.risk);
    }
  }
  const official = classifyTool({ tool_name: 'functions.mcp__marrow__marrow_commit', tool_input: {} });
  assert.equal(official.risk, classifyTool({ tool_name: 'mcp__marrow__marrow_commit', tool_input: {} }).risk);
});

test('G1: functions.mcp__evil__delete_all gets the same answer as mcp__evil__delete_all (held with no key); own stays allowed', async () => {
  for (const entry of ['codex-pre-action-hook', 'claude-pre-action-hook']) {
    const bare = await runPre(entry, { hook_event_name: 'PreToolUse', tool_name: 'mcp__evil__delete_all', tool_input: {} });
    assert.notEqual(bare, '{}|0', `${entry} bare foreign must be held`);
    for (const prefix of G1_PREFIXES) {
      for (const form of ['mcp__evil__delete_all', 'mcp__MARROW__marrow_delete_all', 'mcp__marrow__marrow_delete_all']) {
        const out = await runPre(entry, { hook_event_name: 'PreToolUse', tool_name: `${prefix}${form}`, tool_input: {} });
        assert.equal(out, bare, `${entry} ${prefix}${form}`);
      }
    }
    for (const name of [...MARROW_OWN_TOOL_NAMES]) {
      assert.equal(await runPre(entry, { hook_event_name: 'PreToolUse', tool_name: `functions.mcp__marrow__${name}`, tool_input: {} }), '{}|0', name);
    }
  }
});

const KEY_NAMES = ['Bash', 'Edit', 'Write', 'Read', 'functions.exec', 'functions.apply_patch', 'mcp__evil__delete_all',
  'mcp__marrow__marrow_commit', 'functions.mcp__marrow__marrow_commit', 'MCP:marrow:marrow_commit', 'MCP:delete_all',
  'mcp_marrow_marrow_commit', 'use_mcp_tool', 'run_terminal_command', 'exec_command'];
const PADS = [(n) => `${n} `, (n) => ` ${n}`, (n) => `${n}\n`, (n) => `${n}\t`, (n) => `\t${n}`, (n) => `${n} `, (n) => `${n}  `];

function keyOf(name, input) {
  const action = normalizedHookAction({ tool_name: name, tool_input: input }, { deadlineAt: Number.POSITIVE_INFINITY });
  return JSON.stringify(action);
}

test('N1: whitespace-padded tool names get different normalized actions and keys from their unpadded twins', () => {
  const inputs = [{ command: 'git push origin master' }, { file_path: '/tmp/x', content: 'y' }, {}, { serverName: 'marrow', toolName: 'marrow_commit' }];
  for (const name of KEY_NAMES) {
    for (const input of inputs) {
      const plain = keyOf(name, input);
      assert.equal(JSON.parse(plain).tool_name, name, 'an unpadded name is kept exactly');
      const seen = new Set([plain]);
      for (const pad of PADS) {
        const padded = keyOf(pad(name), input);
        assert.equal(JSON.parse(padded).tool_name, pad(name));
        assert.ok(!seen.has(padded), `${JSON.stringify(pad(name))} collides`);
        seen.add(padded);
        assert.notEqual(
          stableToolCorrelation({ session_id: 's', tool_name: pad(name), tool_input: input }),
          stableToolCorrelation({ session_id: 's', tool_name: name, tool_input: input }),
        );
      }
    }
  }
  // Whitespace-only names stay distinct from each other and from a missing name.
  const blanks = [' ', '  ', '\t', '\n', undefined].map((name) => keyOf(name, { command: 'ls' }));
  assert.equal(new Set(blanks).size, blanks.length);
});

test('N1: a tool name over 128 characters is never bound (truncated), so two such names never share a bound key', () => {
  const long = `mcp__evil__${'a'.repeat(130)}`;
  const a = normalizedHookAction({ tool_name: `${long}A`, tool_input: {} });
  const b = normalizedHookAction({ tool_name: `${long}B`, tool_input: {} });
  assert.equal(a.truncated, true);
  assert.equal(b.truncated, true);
  const exact = normalizedHookAction({ tool_name: `mcp__evil__${'a'.repeat(117)}`, tool_input: {} });
  assert.equal(exact.tool_name.length, 128);
  assert.equal(exact.truncated, undefined, 'a 128-character name is still exact');
});

test('M1: marrow-mcp setup repairs an old-matcher install and says so; a second setup reports nothing to repair', () => {
  const { spawnSync } = require('node:child_process');
  const root = mkdtempSync(join(tmpdir(), 'marrow-mcp-r2-setup-'));
  const home = join(root, 'home');
  const work = join(root, 'work');
  try {
    mkdirSync(home, { mode: 0o700 });
    mkdirSync(join(work, '.claude'), { recursive: true });
    const settingsPath = join(work, '.claude', 'settings.json');
    writeFileSync(settingsPath, JSON.stringify(oldInstall(LEGACY), null, 2));
    const setup = () => spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'setup'], {
      cwd: work, encoding: 'utf8', timeout: 30_000,
      env: { PATH: process.env.PATH, HOME: home, MARROW_API_KEY: 'fixture-dummy-key', MARROW_BASE_URL: 'http://127.0.0.1:9', MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
    });
    const first = setup();
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /Repaired Marrow PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest hooks that used an outdated tool matcher/);
    assert.deepEqual(localHookRepairStatus(work), { needs_repair: false, stale_matchers: [] });
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest']) {
      assert.deepEqual(settings.hooks[event].map((entry) => entry.matcher), [NATIVE_HOOK_MATCHER], event);
    }
    assert.ok(!readFileSync(settingsPath, 'utf8').includes('marrow__marrow_).*'), 'no old matcher left');
    const second = setup();
    assert.equal(second.status, 0, second.stderr);
    assert.doesNotMatch(second.stdout, /outdated tool matcher/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('N1: host adapters that trim, cut or replace a tool name mark the action never bound; exact names are unchanged', () => {
  const { normalizeHookEventPayload } = require('../dist/hook-contract.js');
  // Hooks normalize on read and again on use.
  const actionOf = (payload) => normalizedHookAction(normalizeHookEventPayload(normalizeHookEventPayload(payload)), { deadlineAt: Number.POSITIVE_INFINITY });
  const forms = {
    cursor: (s, t) => ({ hook_event_name: 'beforeMCPExecution', conversation_id: 'c1', mcp_server_name: s, tool_name: t, tool_input: '{"a":1}' }),
    grok: (s, t) => ({ hookEventName: 'PreToolUse', sessionId: 's1', toolName: 'use_tool', toolInput: { serverName: s, toolName: t, a: 1 } }),
    gemini: (s, t) => ({ hook_event_name: 'BeforeTool', session_id: 's1', tool_name: `mcp_${s}_${t}`, tool_input: { a: 1 } }),
  };
  for (const [host, form] of Object.entries(forms)) {
    const exact = actionOf(form('evil', 'delete'));
    assert.equal(exact.truncated, undefined, `${host} exact name is bindable`);
    const pads = host === 'gemini'
      ? [['evil', 'delete '], ['evil', 'delete\t'], ['evil', 'delete\n']]
      : [['evil', 'delete '], [' evil', 'delete'], ['evil ', 'delete'], ['evil', 'delete\n'], ['ev il', 'delete'], ['evil', 'del ete'], ['evil', `d${'e'.repeat(200)}`]];
    for (const [server, tool] of pads) {
      const padded = actionOf(form(server, tool));
      assert.equal(padded.truncated, true, `${host} ${JSON.stringify([server, tool])} is never bound`);
      assert.notEqual(JSON.stringify(padded), JSON.stringify(exact));
    }
  }
  // Gemini: an inner space leaves the tool unclassified (no tool_name), so the hook denies it.
  assert.equal(normalizeHookEventPayload(forms.gemini(' evil', 'delete')).tool_name, undefined);
  // Grok's own wrapper padded: never bound.
  const grok = actionOf({ hookEventName: 'PreToolUse', sessionId: 's1', toolName: 'run_terminal_command ', toolInput: { command: 'ls' } });
  assert.equal(grok.truncated, true);
  assert.equal(actionOf({ hookEventName: 'PreToolUse', sessionId: 's1', toolName: 'run_terminal_command', toolInput: { command: 'ls' } }).truncated, undefined);
});
