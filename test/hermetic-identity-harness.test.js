// The hermetic harness for the own-server identity tests (test/support/hermetic-project.cjs) changes where a test's hook
// starts its upward walk, never what the product decides. These rows pin the product side of that: a checkout that sits
// under a home holding a non-inert npm config is still checked (not proven) when HOME points elsewhere, and the folder
// the harness hands out is clean. Nothing here touches the product walk.
const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, sep } = require('node:path');

const { codexOfficialMarrowServer, cursorOfficialMarrowServer, resetOwnServerIdentityCache } = require('../dist/own-server-identity.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');
const { enterProjectCwd, projectCwd } = require('./support/hermetic-project.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const OWN = [...MARROW_OWN_TOOL_NAMES];
const OFFICIAL_TOML = '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n';
const CURSOR_NPX = { mcpServers: { marrow: { command: 'npx', args: ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp'] } } };
const CODEX_HOME = '/virtual/codex-home';

const files = (table) => (path) => (Object.prototype.hasOwnProperty.call(table, path) ? { state: 'ok', text: table[path] } : { state: 'missing' });
const codex = (extra) => codexOfficialMarrowServer({ env: { CODEX_HOME }, processArgs: null, read: files({ [`${CODEX_HOME}/config.toml`]: OFFICIAL_TOML }), ...extra });

/** A checkout laid out like the release kit's (<home>/agents/.../worktrees/release), with HOME somewhere else. */
function kit(fn) {
  const root = mkdtempSync(join(tmpdir(), 'hermetic-kit-'));
  const home = join(root, 'home');
  const elsewhere = join(root, 'elsewhere');
  const repo = join(home, 'agents', 'builds', 'getmarrow', 'marrow-mcp', 'tasks', 'release', 'worktrees', 'release');
  mkdirSync(repo, { recursive: true });
  mkdirSync(elsewhere);
  try { return fn({ home, elsewhere, repo }); } finally { rmSync(root, { recursive: true, force: true }); }
}
const userNpmConfig = (home, text) => writeFileSync(join(home, '.npmrc'), text);

test('hermetic harness: the project folder is fresh, empty and outside this checkout, and the cwd helper restores the old cwd even when the body throws', () => {
  const dir = projectCwd();
  assert.equal(projectCwd(), dir, 'one folder per process');
  assert.deepEqual(readdirSync(dir), [], 'empty: no config of any kind in it');
  assert.equal(realpathSync(dir).startsWith(`${realpathSync(join(__dirname, '..'))}${sep}`), false, 'not inside the checkout');
  const before = process.cwd();
  const leave = enterProjectCwd();
  assert.equal(process.cwd(), realpathSync(dir));
  leave();
  assert.equal(process.cwd(), before);
  assert.throws(() => {
    const leaveAgain = enterProjectCwd();
    try { throw new Error('body failed'); } finally { leaveAgain(); }
  }, /body failed/);
  assert.equal(process.cwd(), before, 'restored after a throw');
});

test('hermetic harness: a checkout under a home with a non-inert npm config is checked when HOME is elsewhere; as the user home, or with an inert config, it stays proven', () => {
  const redirecting = [
    ['prefix', (home) => `prefix=${join(home, '.npm-global')}\n`],
    ['registry (never contacted)', () => 'registry=http://127.0.0.1:9/\n'],
    ['scoped registry', () => '@getmarrow:registry=http://127.0.0.1:9/\n'],
    ['cache', (home) => `cache=${join(home, '.cache')}\n`],
    ['a harmless key beside a redirecting one', () => 'save-exact=true\nregistry=http://127.0.0.1:9/\n'],
  ];
  for (const [label, text] of redirecting) {
    kit(({ home, elsewhere, repo }) => {
      userNpmConfig(home, text(home));
      assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: elsewhere }).official, false, `${label}: HOME elsewhere`);
      assert.equal(codex({ processCwd: repo, cwds: [], userHome: elsewhere }).official, false, `${label}: process folder only`);
      assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: home }).official, true, `${label}: that home is the user home (user config, not project content)`);
      const cursor = (cursorHome) => cursorOfficialMarrowServer({
        home: cursorHome, processCwd: repo, cwds: [repo], onlyServer: false, env: {},
        read: files({ [join(cursorHome, '.cursor', 'mcp.json')]: JSON.stringify(CURSOR_NPX) }),
      }).official;
      assert.equal(cursor(elsewhere), false, `${label}: Cursor npx form, HOME elsewhere`);
      assert.equal(cursor(home), true, `${label}: Cursor npx form, that home is the user home`);
    });
  }
  for (const [label, text] of [['inert', 'save-exact=true\n'], ['comment only', '# nothing\n'], ['empty', '']]) {
    kit(({ home, elsewhere, repo }) => {
      userNpmConfig(home, text);
      assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: elsewhere }).official, true, `${label}: stays proven with HOME elsewhere`);
    });
  }
});

test('hermetic harness: a planted @getmarrow/mcp copy above the checkout, an empty or unset HOME and a symlinked checkout path are all checked, never proven', () => {
  kit(({ home, elsewhere, repo }) => {
    mkdirSync(join(home, 'node_modules', '@getmarrow', 'mcp'), { recursive: true });
    assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: elsewhere }).official, false, 'planted copy in the home above the checkout');
    assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: home }).official, false, 'planted copy: the user-home exemption is for the npm config only');
    rmSync(join(home, 'node_modules'), { recursive: true });
    userNpmConfig(home, `prefix=${join(home, '.npm-global')}\n`);
    assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: '' }).official, false, 'an empty user home exempts nothing');
    assert.equal(codex({ processCwd: repo, cwds: [repo], userHome: undefined, env: { CODEX_HOME } }).official, false, 'no user home given');
    const saved = process.env.HOME;
    try {
      for (const value of ['', undefined, elsewhere]) {
        if (value === undefined) delete process.env.HOME; else process.env.HOME = value;
        resetOwnServerIdentityCache();
        assert.equal(codex({ processCwd: repo, cwds: [repo] }).official, false, `HOME ${value === undefined ? 'unset' : JSON.stringify(value === elsewhere ? 'elsewhere' : value)}`);
      }
    } finally {
      if (saved === undefined) delete process.env.HOME; else process.env.HOME = saved;
      resetOwnServerIdentityCache();
    }
    // A checkout reached through a link: the process cwd is the physical path, so the walk meets the config above the target.
    const link = join(elsewhere, 'link');
    symlinkSync(repo, link);
    const before = process.cwd();
    process.chdir(link);
    try {
      assert.equal(realpathSync(process.cwd()), process.cwd(), 'the process cwd is the physical path');
      assert.equal(codex({ cwds: [], userHome: elsewhere }).official, false, 'symlinked checkout, process cwd');
    } finally {
      process.chdir(before);
    }
  });
});

test('hermetic harness: the built hook run from inside such a checkout holds the own tools, and run from the project folder it passes them', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hermetic-e2e-'));
  try {
    const home = join(dir, 'home');
    const checkout = join(home, 'agents', 'builds', 'getmarrow', 'marrow-mcp', 'tasks', 'release', 'worktrees', 'release');
    const elsewhere = join(dir, 'elsewhere');
    const codexHome = join(elsewhere, '.codex');
    mkdirSync(checkout, { recursive: true });
    mkdirSync(codexHome, { recursive: true });
    mkdirSync(join(elsewhere, '.cursor'), { recursive: true });
    writeFileSync(join(codexHome, 'config.toml'), OFFICIAL_TOML);
    writeFileSync(join(elsewhere, '.cursor', 'mcp.json'), JSON.stringify(CURSOR_NPX));
    const run = (entry, payload, cwd) => spawnSync(process.execPath, [CLI, entry], {
      input: JSON.stringify(payload),
      cwd,
      env: { PATH: process.env.PATH, HOME: elsewhere, CODEX_HOME: codexHome, MARROW_PASSIVE_TOKEN_USAGE: 'false' },
      encoding: 'utf8',
      timeout: 30_000,
    }).stdout;
    const codexEvent = (tool, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 's', cwd, tool_name: `mcp__marrow__${tool}`, tool_input: {} });
    const cursorEvent = (tool) => ({ hook_event_name: 'preToolUse', conversation_id: 'c', tool_name: `MCP:${tool}`, tool_input: {} });
    const tools = OWN.slice(0, 3);
    for (const tool of tools) {
      assert.equal(run('codex-pre-action-hook', codexEvent(tool, checkout), checkout), '{}', `${tool}: no config above the checkout`);
      assert.equal(run('cursor-pre-action-hook', cursorEvent(tool), checkout), '{"permission":"allow"}', `cursor ${tool}: no config above the checkout`);
    }
    userNpmConfig(home, `prefix=${join(home, '.npm-global')}\n`);
    for (const tool of tools) {
      assert.match(run('codex-pre-action-hook', codexEvent(tool, checkout), checkout), /"permissionDecision":"deny"/, `${tool}: the home's npm config above the checkout holds it`);
      assert.notEqual(run('cursor-pre-action-hook', cursorEvent(tool), checkout), '{"permission":"allow"}', `cursor ${tool}: held`);
      assert.equal(run('codex-pre-action-hook', codexEvent(tool, projectCwd()), projectCwd()), '{}', `${tool}: from the project folder`);
      assert.equal(run('cursor-pre-action-hook', cursorEvent(tool), projectCwd()), '{"permission":"allow"}', `cursor ${tool}: from the project folder`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('hermetic harness: the test process starts with no npm_config_* of its own (the identity check treats those as a possible npx redirect)', () => {
  assert.deepEqual(Object.keys(process.env).filter((key) => /^npm_config_/i.test(key)), []);
});
