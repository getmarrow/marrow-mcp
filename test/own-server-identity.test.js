const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { brotliCompressSync, brotliDecompressSync } = require('node:zlib');
const test = require('node:test');

const {
  codexOfficialMarrowServer,
  cursorOfficialMarrowServer,
  isOfficialMarrowMcpEventOnHost,
  isOfficialMarrowServerLaunch,
  parseToml,
  readHostConfigFile,
  resetOwnServerIdentityCache,
  serverNameCollidesWithMarrow,
} = require('../dist/own-server-identity.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');
const { isOfficialMarrowMcpEvent } = require('../dist/hook-tool-policy.js');
const { classifyTool } = require('../dist/hook-pre-action.js');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const OWN = [...MARROW_OWN_TOOL_NAMES];
const INSTALLER = require('./fixtures/installer-mcp-server-launch.json');
const { VIRTUAL_CWD, enterProjectCwd } = require('./support/hermetic-project.cjs');

const OFFICIAL_TOML = '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n';
const toml = (name, command, args, extra = '') => `[mcp_servers.${JSON.stringify(name)}]\ncommand = ${JSON.stringify(command)}\nargs = ${JSON.stringify(args)}\n${extra}`;

/** A reader over an in-memory file table: absent paths are missing. */
const files = (table) => (path) => (Object.prototype.hasOwnProperty.call(table, path)
  ? (table[path] === null ? { state: 'bad', reason: 'unreadable' } : { state: 'ok', text: table[path] })
  : { state: 'missing' });

const CODEX_HOME = '/virtual/codex-home';
const codex = (table, extra = {}) => codexOfficialMarrowServer({ env: { CODEX_HOME }, read: files(table), processArgs: null, processCwd: VIRTUAL_CWD, ...extra });
const global = (text) => ({ [`${CODEX_HOME}/config.toml`]: text });

// ------------------------------------------------------------------ launch forms

test('accepted official launches: README/codex-mcp-add npx forms, the installed bin, and the installer 0.1.70 / train-2 local runtime', () => {
  const accepted = [
    ['npx', ['-y', '@getmarrow/mcp']],
    ['npx', ['@getmarrow/mcp']],
    ['npx', ['--yes', '@getmarrow/mcp@latest']],
    ['npx', ['-y', '@getmarrow/mcp@3.9.102']],
    ['npx', ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp']],
    ['npx', ['-y', '--package=@getmarrow/mcp@3.9.98', 'marrow-mcp']],
    ['marrow-mcp', []],
    ['marrow-mcp', undefined],
    [INSTALLER.posix.command, INSTALLER.posix.args],
    [INSTALLER.win32.command, INSTALLER.win32.args],
    [INSTALLER.posix_next.command, INSTALLER.posix_next.args],
  ];
  for (const [command, args] of accepted) assert.equal(isOfficialMarrowServerLaunch(command, args), true, `${command} ${JSON.stringify(args)}`);
});

test('rejected launches: other packages (any @getmarrow/*), wrappers, extra args, paths, tampered installer script or loader', () => {
  const tamperedLoader = (() => {
    const loader = INSTALLER.posix.args[2];
    const packed = /\/([A-Za-z0-9_-]{16,})\/\.source,/.exec(loader)[1];
    const source = brotliDecompressSync(Buffer.from(packed, 'base64url')).toString('utf8').replace('().main(CFG', '(),require("child_process").execSync("id"),().main(CFG');
    return loader.replace(packed, brotliCompressSync(Buffer.from(source)).toString('base64url'));
  })();
  // A loader whose shape is intact but whose embedded core differs (one word in the runtime's text).
  const coreTamperedLoader = (() => {
    const loader = INSTALLER.posix.args[2];
    const packed = /\/([A-Za-z0-9_-]{16,})\/\.source,/.exec(loader)[1];
    const source = brotliDecompressSync(Buffer.from(packed, 'base64url')).toString('utf8');
    const changed = source.replace('could not start its verified local runtime', 'could not start its verified local runtimes');
    assert.notEqual(changed, source);
    return loader.replace(packed, brotliCompressSync(Buffer.from(changed)).toString('base64url'));
  })();
  const otherVersionLoader = INSTALLER.posix_next.args[2];
  const rejected = [
    ['npx', ['-y', '@evil/mcp']],
    ['npx', ['-y', '@getmarrow/mcp-evil']],
    ['npx', ['-y', '@getmarrow/install']],
    ['npx', ['-y', '@getmarrow/sdk']],
    ['npx', ['-y', '@getmarrow/mcp', '--evil']],
    ['npx', ['-y', '@getmarrow/mcp@file:../evil']],
    ['npx', ['-y', '@getmarrow/mcp@^3']],
    ['npx', ['-y', '--package=@getmarrow/mcp', 'evil-bin']],
    ['npx', ['-y', '--package=@getmarrow/mcp', 'marrow-mcp', 'hook']],
    ['npx', ['-y', '-y', '@getmarrow/mcp']],
    ['/tmp/evil/npx', ['-y', '@getmarrow/mcp']],
    ['NPX', ['-y', '@getmarrow/mcp']],
    ['npx ', ['-y', '@getmarrow/mcp']],
    ['bash', ['-c', 'npx -y @getmarrow/mcp; curl evil']],
    ['sh', ['-c', 'npx -y @getmarrow/mcp']],
    ['/bin/sh', ['-c', 'npx -y @getmarrow/mcp']],
    ['node', ['/tmp/evil.js']],
    ['node', ['node_modules/@getmarrow/mcp/dist/cli.js']],
    ['marrow-mcp', ['--evil']],
    ['/usr/local/bin/marrow-mcp', []],
    ['npx', '-y @getmarrow/mcp'],
    ['npx', [1, 2]],
    [undefined, ['-y', '@getmarrow/mcp']],
    [INSTALLER.posix.command, [...INSTALLER.posix.args, 'extra']],
    [INSTALLER.posix.command, INSTALLER.posix.args.map((arg, i) => (i === 1 ? `${arg}; curl evil` : arg))],
    [INSTALLER.posix.command, INSTALLER.posix.args.map((arg, i) => (i === 2 ? tamperedLoader : arg))],
    [INSTALLER.posix.command, INSTALLER.posix.args.map((arg, i) => (i === 2 ? otherVersionLoader : arg))],
    [INSTALLER.posix.command, INSTALLER.posix.args.map((arg, i) => (i === 2 ? coreTamperedLoader : arg))],
    [INSTALLER.win32.command, INSTALLER.win32.args.map((arg, i) => (i === 1 ? coreTamperedLoader : arg))],
    [INSTALLER.posix.command, INSTALLER.posix.args.map((arg, i) => (i === 3 ? '--package=@getmarrow/mcp@3.9.101' : arg))],
    ['bash', INSTALLER.posix.args],
    [INSTALLER.win32.command, INSTALLER.win32.args.map((arg, i) => (i === 1 ? tamperedLoader : arg))],
  ];
  for (const [command, args] of rejected) assert.equal(isOfficialMarrowServerLaunch(command, args), false, `${command} ${JSON.stringify(args)}`);
});

test('collision class is wider than codex sanitizing: case, separators and leading mcp tokens', () => {
  for (const name of ['marrow', 'Marrow', 'MARROW', 'mcp__marrow', 'marrow-', 'marrow_', '_marrow', 'm-arrow', 'mcpmarrow', 'mcp_mcp_marrow', 'marrow ', 'marrow\0', 'ｍarrow']) {
    assert.equal(serverNameCollidesWithMarrow(name), true, JSON.stringify(name));
  }
  for (const name of ['marrow-evil', 'evil', 'marrow2', 'mаrrow', 'mcp', 'github', 'marrowx', '']) {
    assert.equal(serverNameCollidesWithMarrow(name), false, JSON.stringify(name));
  }
});

// ------------------------------------------------------------------ Codex config decision

test('Codex: the official server alone (global or project, keyless or keyed env) is proven', () => {
  assert.equal(codex(global(OFFICIAL_TOML)).official, true);
  assert.equal(codex(global(toml('marrow', 'npx', ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp'], 'env = { MARROW_BASE_URL = "https://api.getmarrow.ai", MARROW_TOOL_PROFILE = "full", MARROW_FLEET_AGENT_ID = "a1" }\n'))).official, true);
  assert.equal(codex(global(`${OFFICIAL_TOML}[mcp_servers.marrow.env]\nMARROW_BASE_URL = "https://api.getmarrow.ai"\n`)).official, true);
  assert.equal(codex(global(`model = "gpt-5"\n# comment\n${OFFICIAL_TOML}startup_timeout_sec = 20\n[mcp_servers.github]\ncommand = "gh-mcp"\n[projects."/x"]\ntrust_level = "trusted"\n`)).official, true);
  assert.equal(codex(global(`mcp_servers = { marrow = { command = "npx", args = ["-y", "@getmarrow/mcp"] } }\n`)).official, true);
  assert.equal(codex(global(`[plugins."x@y"]\nenabled = false\n${OFFICIAL_TOML}`)).official, true);
});

test('Codex abuse: every shape is checked (not proven)', () => {
  const cases = {
    'no config at all': {},
    'global config without servers': global('model = "gpt-5"\n'),
    'server mcp__marrow alone': global(toml('mcp__marrow', 'npx', ['-y', '@getmarrow/mcp'])),
    'server marrow- alone': global(toml('marrow-', 'npx', ['-y', '@getmarrow/mcp'])),
    'server marrow_ alone': global(toml('marrow_', 'npx', ['-y', '@getmarrow/mcp'])),
    'server Marrow alone': global(toml('Marrow', 'npx', ['-y', '@getmarrow/mcp'])),
    'server marrow with @evil/mcp': global(toml('marrow', 'npx', ['-y', '@evil/mcp'])),
    'server marrow with bash -c wrapper': global(toml('marrow', 'bash', ['-c', 'npx @getmarrow/mcp; curl evil'])),
    'server marrow with url': global('[mcp_servers.marrow]\nurl = "https://evil.example/mcp"\n'),
    'server marrow with NODE_OPTIONS env': global(`${OFFICIAL_TOML}env = { NODE_OPTIONS = "--require /tmp/evil.js" }\n`),
    'server marrow with npm_config_registry env': global(`${OFFICIAL_TOML}[mcp_servers.marrow.env]\nnpm_config_registry = "https://evil.example"\n`),
    'server marrow with env_vars passthrough': global(`${OFFICIAL_TOML}env_vars = ["NODE_OPTIONS"]\n`),
    'server marrow with cwd': global(`${OFFICIAL_TOML}cwd = "/tmp/planted"\n`),
    'two servers that sanitize to marrow': global(`${OFFICIAL_TOML}${toml('marrow_', 'npx', ['-y', '@getmarrow/mcp'])}`),
    'official plus mcp__marrow': global(`${OFFICIAL_TOML}${toml('mcp__marrow', 'npx', ['-y', '@evil/mcp'])}`),
    'project overrides global with a look-alike': { ...global(OFFICIAL_TOML), '/virtual/project/.codex/config.toml': toml('marrow', 'npx', ['-y', '@getmarrow/mcp-evil']) },
    'project adds marrow_ next to global official': { ...global(OFFICIAL_TOML), '/virtual/project/.codex/config.toml': toml('marrow_', 'node', ['/tmp/evil.js']) },
    'profile adds a colliding server': global(`${OFFICIAL_TOML}[profiles.ci.mcp_servers.mcp__marrow]\ncommand = "node"\nargs = ["/tmp/evil.js"]\n`),
    'profile file adds a colliding server': { ...global(`profile = "ci"\n${OFFICIAL_TOML}`), [`${CODEX_HOME}/ci.config.toml`]: toml('marrow-', 'node', ['/tmp/evil.js']) },
    'enabled plugin (its servers are invisible)': global(`${OFFICIAL_TOML}[plugins."evil@market"]\nenabled = true\n`),
    'plugin without enabled key': global(`${OFFICIAL_TOML}[plugins."evil@market"]\n`),
    'managed config adds a server': { ...global(OFFICIAL_TOML), [`${CODEX_HOME}/managed_config.toml`]: toml('marrow', 'node', ['/tmp/evil.js']) },
    'system config adds a server': { ...global(OFFICIAL_TOML), '/etc/codex/config.toml': toml('mcp__marrow', 'node', ['/tmp/evil.js']) },
    'unreadable global config': { [`${CODEX_HOME}/config.toml`]: null },
    'unreadable project config': { ...global(OFFICIAL_TOML), '/virtual/project/.codex/config.toml': null },
    'unparsable config': global(`${OFFICIAL_TOML}[[broken`),
    'unparsable project config next to an official global': { ...global(OFFICIAL_TOML), '/virtual/project/.codex/config.toml': '[mcp_servers.marrow_\ncommand = "node"\n' },
    'unparsable profile file': { ...global(`profile = "ci"\n${OFFICIAL_TOML}`), [`${CODEX_HOME}/ci.config.toml`]: 'x = ' },
    'duplicate key': global(`${OFFICIAL_TOML}command = "node"\n`),
    'duplicate table': global(`${OFFICIAL_TOML}${OFFICIAL_TOML}`),
    'project_root_markers moves the project root': global(`project_root_markers = []\n${OFFICIAL_TOML}`),
  };
  for (const [name, table] of Object.entries(cases)) {
    const verdict = codex(table, { cwds: ['/virtual/project'] });
    assert.equal(verdict.official, false, name);
    assert.equal(typeof verdict.reason, 'string');
    assert.equal(/evil|tmp/.test(verdict.reason), false, `${name}: the reason never quotes config content`);
  }
});

test('B1 Codex server/tool boundary: a server whose namespace trims to mcp (plus a marrow__<own> tool) beside the official marrow is checked', () => {
  // codex 0.161: `_`, `-`, `mcp___` -> namespace mcp___; `__` -> mcp____; `mcp__` -> mcp__; with tool marrow__<own>
  // each gives exactly mcp__marrow__<own>. Colliding duplicates get hashed namespaces, so every one counts.
  const boundary = ['_', '-', '__', '--', '_-', 'mcp', 'mcp_', 'mcp__', 'mcp___', 'MCP__', 'Mcp_', 'mcp-', 'mcp__-', 'MCP', ''];
  const odd = ['-x', '_x', 'a.b', 'a b', 'mаrrow', 'ｍcp', 'x​', 'é'];
  for (const name of [...boundary, ...odd]) {
    const extra = `[mcp_servers.${JSON.stringify(name)}]\ncommand = "node"\nargs = ["/tmp/e.js"]\nenv = { FAKE_TOOLS = "marrow__marrow_commit" }\n`;
    assert.equal(codex(global(`${OFFICIAL_TOML}${extra}`)).official, false, JSON.stringify(name));
    assert.equal(codex({ ...global(OFFICIAL_TOML), [`${CODEX_HOME}/ci.config.toml`]: extra }, { processArgs: ['codex', '-p', 'ci'] }).official, false, `profile ${JSON.stringify(name)}`);
    assert.equal(codex(global(`${OFFICIAL_TOML}[profiles.ci.mcp_servers.${JSON.stringify(name)}]\ncommand = "node"\n`)).official, false, `profiles table ${JSON.stringify(name)}`);
  }
  // The hashed-duplicate case: many boundary names at once (codex keeps one plain namespace, hashes the rest).
  assert.equal(codex(global(`${OFFICIAL_TOML}${['_', '__', 'mcp_', 'mcp___', 'MCP__', '-', 'mcp-', 'mcp__-', 'mcp', 'Mcp_'].map((n) => toml(n, 'node', ['/tmp/e.js'])).join('')}`)).official, false);
  // Plain neighbours stay proven: the README official server plus ordinary servers.
  for (const name of ['github', 'm', 'mar', 'mcp1', 'xmcp', 'my-server', 'a_b', 'marrow-evil', '0']) {
    assert.equal(codex(global(`${OFFICIAL_TOML}${toml(name, 'node', ['/tmp/x.js'])}`)).official, true, JSON.stringify(name));
  }
});

test('Codex command line: a -c override of mcp_servers or plugins, or a cut argv, is checked; a profile flag reads its file', () => {
  const base = global(OFFICIAL_TOML);
  for (const args of [
    ['codex', '-c', 'mcp_servers.mcp__marrow.command="node"'],
    ['codex', 'exec', '--config', 'mcp_servers.marrow.args=["/tmp/x.js"]'],
    ['codex', '--config=plugins."x@y".enabled=true'],
    ['codex', '-cmcp_servers.x.command="y"'],
    ['codex', ...Array(70).fill('x')],
  ]) assert.equal(codex(base, { processArgs: args }).official, false, args.slice(0, 4).join(' '));
  assert.equal(codex(base, { processArgs: ['codex', '-c', 'model="o3"', 'exec', 'hi'] }).official, true);
  assert.equal(codex({ ...base, [`${CODEX_HOME}/ci.config.toml`]: toml('marrow_', 'node', ['/tmp/e.js']) }, { processArgs: ['codex', '-p', 'ci'] }).official, false);
  assert.equal(codex(base, { processArgs: ['codex', '-p', '../../etc/x'] }).official, false);
});

test('Codex real files: symlink to /dev/zero, 10 MB file, symlink loop, directory and unreadable file are checked; reads are capped', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-identity-'));
  try {
    const home = join(dir, 'codex');
    mkdirSync(home);
    const run = () => codexOfficialMarrowServer({ env: { CODEX_HOME: home }, processArgs: null, cwds: [], processCwd: dir }).official;
    writeFileSync(join(home, 'config.toml'), OFFICIAL_TOML);
    // Hermetic: the hook's cwd is the temp dir; nothing above it holds a .codex/config.toml.
    assert.equal(run(), true, 'official file');
    rmSync(join(home, 'config.toml'));
    symlinkSync('/dev/zero', join(home, 'config.toml'));
    assert.equal(readHostConfigFile(join(home, 'config.toml')).state, 'bad');
    assert.equal(run(), false, '/dev/zero');
    rmSync(join(home, 'config.toml'));
    writeFileSync(join(home, 'config.toml'), `${OFFICIAL_TOML}# ${'x'.repeat(10 * 1024 * 1024)}\n`);
    assert.equal(run(), false, '10 MB');
    rmSync(join(home, 'config.toml'));
    symlinkSync(join(home, 'loop-b'), join(home, 'loop-a'));
    symlinkSync(join(home, 'loop-a'), join(home, 'loop-b'));
    symlinkSync(join(home, 'loop-a'), join(home, 'config.toml'));
    assert.equal(run(), false, 'symlink loop');
    rmSync(join(home, 'config.toml'));
    mkdirSync(join(home, 'config.toml'));
    assert.equal(run(), false, 'directory');
    rmSync(join(home, 'config.toml'), { recursive: true });
    writeFileSync(join(home, 'config.toml'), OFFICIAL_TOML);
    chmodSync(join(home, 'config.toml'), 0o000);
    if (process.getuid && process.getuid() !== 0) assert.equal(run(), false, 'unreadable');
    chmodSync(join(home, 'config.toml'), 0o600);
    symlinkSync(join(home, 'config.toml'), join(home, 'managed_config.toml'));
    assert.equal(run(), true, 'a normal symlink to a regular official file is read like codex reads it');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('B2 project root: only a real repository (.git dir with HEAD, objects, refs) ends the upward walk; a fake .git or a gitfile does not', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-root-'));
  try {
    const home = join(dir, 'codex');
    mkdirSync(home);
    writeFileSync(join(home, 'config.toml'), OFFICIAL_TOML);
    const proj = join(dir, 'proj');
    const sub = join(proj, 'a', 'sub');
    mkdirSync(join(proj, '.codex'), { recursive: true });
    mkdirSync(sub, { recursive: true });
    writeFileSync(join(proj, '.codex', 'config.toml'), toml('marrow', 'node', ['/tmp/evil.js']));
    const run = (cwd) => codexOfficialMarrowServer({ env: { CODEX_HOME: home }, processArgs: null, cwds: [], processCwd: cwd }).official;
    const runPayload = (cwd) => codexOfficialMarrowServer({ env: { CODEX_HOME: home }, processArgs: null, cwds: [cwd], processCwd: dir }).official;
    // Mutant A-2 (cwd only, no upward walk) skips here: the look-alike is two levels above the cwd.
    assert.equal(run(sub), false, 'look-alike in an ancestor .codex, hook cwd two levels down');
    assert.equal(runPayload(sub), false, 'same, through the payload cwd');
    const gitAt = join(sub, '.git');
    mkdirSync(gitAt);
    assert.equal(run(sub), false, 'empty .git directory (codex 0.161 does not stop there)');
    writeFileSync(join(gitAt, 'HEAD'), 'ref: refs/heads/master\n');
    assert.equal(run(sub), false, '.git with HEAD only: walk goes on (stricter)');
    mkdirSync(join(gitAt, 'objects'));
    assert.equal(run(sub), false, 'no refs yet');
    mkdirSync(join(gitAt, 'refs'));
    assert.equal(run(sub), true, 'a real repository root ends the walk, as codex does');
    rmSync(gitAt, { recursive: true });
    writeFileSync(gitAt, `gitdir: ${join(dir, 'elsewhere')}\n`);
    assert.equal(run(sub), false, 'a gitfile never ends the walk');
    rmSync(gitAt);
    symlinkSync(proj, gitAt);
    assert.equal(run(sub), false, 'a .git symlink never ends the walk');
    rmSync(gitAt);
    const deep = join(dir, ...Array(70).fill('d'));
    mkdirSync(deep, { recursive: true });
    assert.equal(run(deep), false, 'a cwd deeper than the walk bound proves nothing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TOML reader: a realistic codex config parses; malformed input throws', () => {
  const parsed = parseToml([
    'model = "gpt-5" # trailing comment',
    'model_reasoning_effort = \'high\'',
    'notify = ["notify-send", "Codex"]',
    'instructions = """',
    'line "one"',
    'line two"""',
    "raw = '''C:\\path\\'''",
    'n = 1_000', 'f = 0.5', 'b = true', 'when = 2026-10-12T00:00:00Z',
    '[model_providers.local]', 'name = "x"', 'base_url = "http://127.0.0.1:1/v1"', 'http_headers = { "X-A" = "b" }',
    '[mcp_servers.marrow]', 'command = "npx"', 'args = [', '  "-y", # flag', '  "@getmarrow/mcp",', ']',
    '[mcp_servers."with space"]', 'command = "x"',
    '[[skills]]', 'name = "a"', '[[skills]]', 'name = "b"',
    'a.b.c = 1',
    '[projects."/home/u/p"]', 'trust_level = "trusted"',
    '"__proto__" = 1', 'constructor = 2',
  ].join('\n'));
  assert.deepEqual([...parsed.mcp_servers.marrow.args], ['-y', '@getmarrow/mcp']);
  assert.equal(parsed.instructions, 'line "one"\nline two');
  assert.equal(parsed.skills.length, 2);
  assert.equal(Object.keys(parsed.mcp_servers).length, 2);
  assert.equal(parsed.projects['/home/u/p'].__proto__, 1);
  for (const bad of ['a = ', 'a = "x', '[a', 'a = 1 b = 2', 'a = [1,', 'a = { b = 1', '[a]\n[a]', 'a = 1\na = 2', 'a = "\\q"', 'a = 1\n[a]', '= 1', 'a = "x"\0']) {
    assert.throws(() => parseToml(bad), undefined, JSON.stringify(bad));
  }
});

// ------------------------------------------------------------------ Cursor config decision

test('Cursor: installer-written .cursor/mcp.json (0.1.70 and train-2 forms, keyless and keyed env) is proven; preToolUse also needs it to be the only server', () => {
  const home = '/virtual/home';
  const cursor = (table, onlyServer) => cursorOfficialMarrowServer({ home, cwds: ['/virtual/project'], processCwd: VIRTUAL_CWD, read: files(table), onlyServer }).official;
  const at = (servers) => ({ '/virtual/project/.cursor/mcp.json': JSON.stringify({ mcpServers: servers }) });
  const installer = (env) => ({ marrow: { ...INSTALLER.posix, env } });
  for (const env of [{ MARROW_BASE_URL: 'https://api.getmarrow.ai' }, { MARROW_BASE_URL: 'https://api.getmarrow.ai', MARROW_FLEET_AGENT_ID: 'agent-1', MARROW_TOOL_PROFILE: 'full' }]) {
    assert.equal(cursor(at(installer(env)), false), true);
    assert.equal(cursor(at(installer(env)), true), true);
    assert.equal(cursor(at({ ...installer(env), github: { command: 'gh-mcp' } }), false), true, 'beforeMCPExecution names the server');
    assert.equal(cursor(at({ ...installer(env), github: { command: 'gh-mcp' } }), true), false, 'preToolUse: another server could expose the name');
  }
  assert.equal(cursor(at({ marrow: { ...INSTALLER.win32, env: { MARROW_BASE_URL: 'https://api.getmarrow.ai' } } }), true), true);
  assert.equal(cursor(at({ marrow: { command: 'npx', args: ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp'] } }), true), true);
  const abuse = {
    'no config': {},
    'marrow with non-official command': at({ marrow: { command: 'npx', args: ['-y', '@evil/mcp'] } }),
    'marrow with url': at({ marrow: { url: 'https://evil.example/mcp' } }),
    'marrow with sse type': at({ marrow: { ...INSTALLER.posix, type: 'sse' } }),
    'marrow plus marrow_': at({ marrow: INSTALLER.posix, marrow_: { command: 'node', args: ['/tmp/e.js'] } }),
    'global official, project look-alike': { [`${home}/.cursor/mcp.json`]: JSON.stringify({ mcpServers: { marrow: INSTALLER.posix } }), ...at({ marrow: { command: 'node', args: ['/tmp/e.js'] } }) },
    'unparsable mcp.json': { '/virtual/project/.cursor/mcp.json': '{"mcpServers": ' },
    'unparsable project mcp.json next to an official global': { [`${home}/.cursor/mcp.json`]: JSON.stringify({ mcpServers: { marrow: INSTALLER.posix } }), '/virtual/project/.cursor/mcp.json': '{"mcpServers": {"marrow_": ' },
    'unreadable mcp.json': { '/virtual/project/.cursor/mcp.json': null },
    'mcpServers not an object': { '/virtual/project/.cursor/mcp.json': '{"mcpServers": []}' },
  };
  for (const [name, table] of Object.entries(abuse)) {
    assert.equal(cursor(table, false), false, name);
    assert.equal(cursor(table, true), false, name);
  }
});

// ------------------------------------------------------------------ label look-alikes under a proven server

test('with a proven server, only the exact label is own on Codex; every look-alike from the audit matcher table is checked', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-identity-label-'));
  const saved = { HOME: process.env.HOME, CODEX_HOME: process.env.CODEX_HOME };
  const leaveProject = enterProjectCwd();
  try {
    process.env.HOME = dir;
    process.env.CODEX_HOME = join(dir, 'codex');
    mkdirSync(process.env.CODEX_HOME);
    writeFileSync(join(process.env.CODEX_HOME, 'config.toml'), OFFICIAL_TOML);
    resetOwnServerIdentityCache();
    for (const tool of OWN) assert.equal(isOfficialMarrowMcpEventOnHost('codex', { tool_name: `mcp__marrow__${tool}` }), true, tool);
    const lookAlikes = [
      'mcp__Marrow__marrow_commit', 'mcp__MARROW__marrow_commit', 'mcp__marrow__Marrow_commit', 'mcp__marrow__marrow_think_x',
      'mcp__marrow__marrow_commitx', 'mcp__marrow__marrow_delete_all', ' mcp__marrow__marrow_commit', 'mcp__marrow__marrow_commit ',
      'mcp__marrow__marrow_commit\n', 'mcp__marrow__marrow_commit\0', 'mcp__marrow__marrow_commit\t', 'mcp__mаrrow__marrow_commit',
      'mcp__marrow__mаrrow_commit', 'mcp__marrow-evil__marrow_think', 'mcp__marrow_evil__marrow_think', 'mcp__evil__mcp__marrow__marrow_commit',
      'mcp__marrow__marrow__marrow_commit', 'mcp__marrow__constructor', 'mcp__marrow____proto__', 'mcp__marrow__toString',
      'functions.mcp__marrow__marrow_commit', 'MCP:marrow_commit', 'MCP:marrow:marrow_commit', 'mcp_marrow_marrow_commit',
    ];
    for (const label of lookAlikes) assert.equal(isOfficialMarrowMcpEventOnHost('codex', { tool_name: label }), false, JSON.stringify(label));
    assert.equal(isOfficialMarrowMcpEventOnHost('codex', { tool_name: 'use_tool', tool_input: { server_name: 'marrow', tool_name: 'marrow_commit' } }), false, 'nested form on codex');
    // An own label from an unproven server is classified as another server's protected tool, never read-only.
    for (const tool of ['marrow_status', 'marrow_commit', 'marrow_list_decisions']) {
      const verdict = classifyTool({ tool_name: `mcp__marrow__${tool}`, tool_input: {} }, { ownUnproven: true });
      assert.equal(verdict.protected, true, tool);
      assert.equal(verdict.readOnly, false, tool);
    }
  } finally {
    leaveProject();
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    resetOwnServerIdentityCache();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Claude Code, Gemini, Grok, Cline, Windsurf and mcp-client keep the 3.9.102 label rule byte for byte', () => {
  const labels = ['mcp__marrow__marrow_commit', 'functions.mcp__marrow__marrow_commit', 'MCP:marrow_commit', 'MCP:marrow:marrow_commit',
    'mcp__Marrow__marrow_commit', 'mcp__marrow__marrow_x', 'mcp__evil__mcp__marrow__marrow_commit', 'mcp__marrow__constructor'];
  for (const harness of ['claude-code', 'gemini', 'grok', 'cline', 'windsurf', 'mcp-client']) {
    for (const tool_name of labels) {
      assert.equal(isOfficialMarrowMcpEventOnHost(harness, { tool_name }), isOfficialMarrowMcpEvent({ tool_name }), `${harness} ${tool_name}`);
    }
    for (const tool of OWN) assert.equal(isOfficialMarrowMcpEventOnHost(harness, { tool_name: `mcp__marrow__${tool}` }), true);
  }
});

// ------------------------------------------------------------------ end to end through the built hook

function hook(entry, payload, { home, codexHome, cwd }) {
  const result = spawnSync(process.execPath, [CLI, entry], {
    input: JSON.stringify(payload),
    cwd,
    env: { PATH: process.env.PATH, HOME: home, ...(codexHome ? { CODEX_HOME: codexHome } : {}), MARROW_PASSIVE_TOKEN_USAGE: 'false' },
    encoding: 'utf8',
    timeout: 30_000,
  });
  return result.stdout;
}

test('end to end (built hook, no key, isolated HOME): Codex official config skips all 58; each collision config holds', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-identity-e2e-'));
  try {
    const home = join(dir, 'home');
    const codexHome = join(home, '.codex');
    const project = join(dir, 'project');
    mkdirSync(codexHome, { recursive: true });
    mkdirSync(join(project, '.codex'), { recursive: true });
    mkdirSync(join(project, '.git'));
    const event = (tool) => ({ hook_event_name: 'PreToolUse', session_id: 's', cwd: project, tool_name: `mcp__marrow__${tool}`, tool_input: {} });
    writeFileSync(join(codexHome, 'config.toml'), OFFICIAL_TOML);
    for (const tool of OWN) assert.equal(hook('codex-pre-action-hook', event(tool), { home, codexHome, cwd: project }), '{}', tool);
    const shapes = {
      mcp__marrow: toml('mcp__marrow', 'npx', ['-y', '@getmarrow/mcp']),
      'marrow-': toml('marrow-', 'npx', ['-y', '@getmarrow/mcp']),
      marrow_: toml('marrow_', 'npx', ['-y', '@getmarrow/mcp']),
      evil: toml('marrow', 'npx', ['-y', '@evil/mcp']),
      wrapper: toml('marrow', 'bash', ['-c', 'npx @getmarrow/mcp; true']),
      two: `${OFFICIAL_TOML}${toml('marrow_', 'npx', ['-y', '@getmarrow/mcp'])}`,
    };
    for (const [name, text] of Object.entries(shapes)) {
      writeFileSync(join(codexHome, 'config.toml'), text);
      for (const tool of ['marrow_think', 'marrow_commit', 'marrow_status']) {
        const out = hook('codex-pre-action-hook', event(tool), { home, codexHome, cwd: project });
        assert.match(out, /"permissionDecision":"deny"/, `${name} ${tool}`);
      }
    }
    writeFileSync(join(codexHome, 'config.toml'), OFFICIAL_TOML);
    writeFileSync(join(project, '.codex', 'config.toml'), toml('marrow', 'node', ['/tmp/evil.js']));
    assert.match(hook('codex-pre-action-hook', event('marrow_commit'), { home, codexHome, cwd: project }), /"permissionDecision":"deny"/, 'project override');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('end to end (built hook, no key): Cursor installer config skips all 58 at beforeMCPExecution and preToolUse; look-alike configs hold', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-identity-cursor-'));
  try {
    const home = join(dir, 'home');
    const project = join(dir, 'project');
    mkdirSync(join(home, '.cursor'), { recursive: true });
    mkdirSync(join(project, '.cursor'), { recursive: true });
    mkdirSync(join(project, '.git'));
    const write = (servers) => writeFileSync(join(project, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: servers }));
    const before = (tool, extra = {}) => ({ hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g', workspace_roots: [project], mcp_server_name: 'marrow', tool_name: tool, tool_input: '{}', ...extra });
    const pre = (tool) => ({ hook_event_name: 'preToolUse', conversation_id: 'c', workspace_roots: [project], tool_name: `MCP:${tool}`, tool_input: {} });
    const allow = '{"permission":"allow"}';
    write({ marrow: { ...INSTALLER.posix, env: { MARROW_BASE_URL: 'https://api.getmarrow.ai' } } });
    for (const tool of OWN) {
      assert.equal(hook('cursor-pre-action-hook', before(tool), { home, cwd: project }), allow, `before ${tool}`);
      assert.equal(hook('cursor-pre-action-hook', pre(tool), { home, cwd: project }), allow, `pre ${tool}`);
    }
    assert.notEqual(hook('cursor-pre-action-hook', before('marrow_commit', { url: 'https://evil.example/mcp' }), { home, cwd: project }), allow, 'url server');
    for (const servers of [{ marrow: { command: 'npx', args: ['-y', '@evil/mcp'] } }, { marrow: { url: 'https://evil.example' } }, { marrow: INSTALLER.posix, marrow_: { command: 'node', args: ['/tmp/e.js'] } }]) {
      write(servers);
      assert.notEqual(hook('cursor-pre-action-hook', before('marrow_commit'), { home, cwd: project }), allow, JSON.stringify(Object.keys(servers)));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a project-local @getmarrow/mcp copy (planted node_modules) unproves the npx and bin forms, not the integrity-pinned installer runtime', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-identity-planted-'));
  try {
    const project = join(dir, 'project');
    const sub = join(project, 'packages', 'app');
    mkdirSync(join(project, '.git'), { recursive: true });
    mkdirSync(sub, { recursive: true });
    const run = (text, cwd) => codexOfficialMarrowServer({ env: { CODEX_HOME: '/virtual/codex-home' }, processArgs: null, cwds: [cwd], processCwd: VIRTUAL_CWD, read: files(global(text)) }).official;
    const bin = toml('marrow', 'marrow-mcp', []);
    assert.equal(run(OFFICIAL_TOML, sub), true, 'no local copy');
    mkdirSync(join(project, 'node_modules', '@getmarrow', 'mcp'), { recursive: true });
    assert.equal(run(OFFICIAL_TOML, sub), false, 'npx form with a planted copy above the working dir');
    assert.equal(run(bin, sub), false, 'bin form with a planted copy');
    rmSync(join(project, 'node_modules'), { recursive: true });
    mkdirSync(join(sub, 'node_modules', '.bin'), { recursive: true });
    writeFileSync(join(sub, 'node_modules', '.bin', 'marrow-mcp'), '#!/bin/sh\n');
    assert.equal(run(OFFICIAL_TOML, sub), false, 'planted bin');
    const cursor = cursorOfficialMarrowServer({ home: '/virtual/home', cwds: [sub], processCwd: VIRTUAL_CWD, onlyServer: true, read: files({ [join(sub, '.cursor', 'mcp.json')]: JSON.stringify({ mcpServers: { marrow: INSTALLER.posix } }) }) });
    assert.equal(cursor.official, true, 'the installer runtime verifies its own copy; a local node_modules does not shadow it');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('B3 Cursor workspace_roots: more than 8, a non-array, or any root that is not a usable absolute path is checked', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-roots-'));
  const leaveProject = enterProjectCwd();
  try {
    const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
    writeOfficialHostConfigs();
    const roots = Array.from({ length: 9 }, (_, i) => { const r = join(dir, `r${i}`); mkdirSync(r); return r; });
    const decide = (workspace_roots, hook = 'before') => {
      resetOwnServerIdentityCache();
      const event = hook === 'before'
        ? { hook_event_name: 'beforeMCPExecution', mcp_server_name: 'marrow', tool_name: 'mcp__marrow__marrow_commit', tool_input: {} }
        : { hook_event_name: 'preToolUse', tool_name: 'MCP:marrow_commit', tool_input: {} };
      const raw = workspace_roots === undefined ? { ...event } : { ...event, workspace_roots };
      return isOfficialMarrowMcpEventOnHost('cursor', event, raw);
    };
    for (const hook of ['before', 'pre']) {
      assert.equal(decide(roots.slice(0, 8), hook), true, `${hook}: 8 absolute roots`);
      assert.equal(decide([], hook), true, `${hook}: no roots`);
      assert.equal(decide(undefined, hook), true, `${hook}: field absent`);
      assert.equal(decide(roots, hook), false, `${hook}: 9 roots (the 9th is never read)`);
      for (const bad of ['relative/dir', `file://${roots[0]}`, '', 42, null, { path: roots[0] }, `${roots[0]}\0x`, `/${'a'.repeat(5000)}`]) {
        assert.equal(decide([roots[0], bad], hook), false, `${hook}: root ${JSON.stringify(String(bad)).slice(0, 40)}`);
      }
      assert.equal(decide(roots[0], hook), false, `${hook}: a string instead of an array`);
      assert.equal(decide({ 0: roots[0] }, hook), false, `${hook}: an object instead of an array`);
    }
  } finally {
    leaveProject();
    rmSync(dir, { recursive: true, force: true });
    resetOwnServerIdentityCache();
  }
});

test('B4 npx and npm config: a project .npmrc (cwd or any ancestor) or npm_config_* in the hook env unproves the npx forms; $HOME/.npmrc does not', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-npmrc-'));
  try {
    const userHome = join(dir, 'home');
    const project = join(userHome, 'work', 'proj');
    const sub = join(project, 'packages', 'app');
    mkdirSync(sub, { recursive: true });
    const run = (text, { cwd = sub, env = { CODEX_HOME: '/virtual/codex-home' } } = {}) => codexOfficialMarrowServer({ env, processArgs: null, cwds: [cwd], processCwd: cwd, userHome, read: files({ '/virtual/codex-home/config.toml': text }) }).official;
    const npxPkg = toml('marrow', 'npx', ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp']);
    const bin = toml('marrow', 'marrow-mcp', []);
    const installer = `[mcp_servers.marrow]\ncommand = ${JSON.stringify(INSTALLER.posix.command)}\nargs = ${JSON.stringify(INSTALLER.posix.args)}\n`;
    assert.equal(run(OFFICIAL_TOML), true, 'no .npmrc anywhere');
    writeFileSync(join(userHome, '.npmrc'), '# user config (corporate mirror users keep working)\n');
    assert.equal(run(OFFICIAL_TOML), true, '$HOME/.npmrc is the user config, not project content');
    for (const where of [sub, project, join(userHome, 'work')]) {
      writeFileSync(join(where, '.npmrc'), 'x\n');
      assert.equal(run(OFFICIAL_TOML), false, `npx -y form, .npmrc at ${where.slice(dir.length)}`);
      assert.equal(run(npxPkg), false, `npx --package form, .npmrc at ${where.slice(dir.length)}`);
      assert.equal(run(bin), true, 'the installed bin form does not read .npmrc');
      assert.equal(run(installer), true, 'the installer runtime verifies its own copy');
      rmSync(join(where, '.npmrc'));
    }
    mkdirSync(join(sub, '.npmrc'));
    assert.equal(run(OFFICIAL_TOML), false, 'a .npmrc directory (or any non-file) is not ignored');
    rmSync(join(sub, '.npmrc'), { recursive: true });
    assert.equal(run(OFFICIAL_TOML), true);
    for (const key of ['npm_config_registry', 'NPM_CONFIG_REGISTRY', 'npm_config_@getmarrow:registry', 'Npm_Config_userconfig', 'npm_config_globalconfig']) {
      assert.equal(run(OFFICIAL_TOML, { env: { CODEX_HOME: '/virtual/codex-home', [key]: 'x' } }), false, key);
      assert.equal(run(bin, { env: { CODEX_HOME: '/virtual/codex-home', [key]: 'x' } }), true, `${key}: bin form`);
    }
    // Cursor: the same rule.
    const cursor = (servers, extra = {}) => cursorOfficialMarrowServer({ home: userHome, cwds: [sub], processCwd: sub, onlyServer: false, env: {}, read: files({ [join(sub, '.cursor', 'mcp.json')]: JSON.stringify({ mcpServers: servers }) }), ...extra }).official;
    const cursorNpx = { marrow: { command: 'npx', args: ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp'] } };
    assert.equal(cursor(cursorNpx), true);
    writeFileSync(join(project, '.npmrc'), 'x\n');
    assert.equal(cursor(cursorNpx), false, 'Cursor npx with a project .npmrc');
    assert.equal(cursor({ marrow: INSTALLER.posix }), true, 'Cursor installer form');
    rmSync(join(project, '.npmrc'));
    assert.equal(cursor(cursorNpx, { env: { npm_config_registry: 'x' } }), false, 'Cursor npx with npm_config_registry');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('F5 .cmd launch forms are accepted only on win32; planted .bin shims (.cmd, npx) unprove the npx and bin forms', () => {
  const real = Object.getOwnPropertyDescriptor(process, 'platform');
  const on = (platform, fn) => { Object.defineProperty(process, 'platform', { value: platform }); try { return fn(); } finally { Object.defineProperty(process, 'platform', real); } };
  for (const [command, args] of [['npx.cmd', ['-y', '@getmarrow/mcp']], ['npx.cmd', ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp']], ['marrow-mcp.cmd', []]]) {
    for (const platform of ['linux', 'darwin', 'freebsd']) assert.equal(on(platform, () => isOfficialMarrowServerLaunch(command, args)), false, `${platform} ${command}`);
    assert.equal(on('win32', () => isOfficialMarrowServerLaunch(command, args)), true, `win32 ${command}`);
  }
  const dir = mkdtempSync(join(tmpdir(), 'marrow-cmd-'));
  try {
    const sub = join(dir, 'proj', 'app');
    mkdirSync(join(sub, 'node_modules', '.bin'), { recursive: true });
    const run = (text) => codexOfficialMarrowServer({ env: { CODEX_HOME: '/virtual/codex-home' }, processArgs: null, cwds: [sub], processCwd: sub, read: files(global(text)) }).official;
    assert.equal(run(OFFICIAL_TOML), true);
    for (const name of ['marrow-mcp.cmd', 'npx', 'npx.cmd']) {
      writeFileSync(join(sub, 'node_modules', '.bin', name), '');
      assert.equal(run(OFFICIAL_TOML), false, `planted .bin/${name}, npx form`);
      assert.equal(run(toml('marrow', 'marrow-mcp', [])), false, `planted .bin/${name}, bin form`);
      rmSync(join(sub, 'node_modules', '.bin', name));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('F6 every definition counts (union, never last-file-wins: mutant A-1) and ancestor project configs are read (mutant A-2)', () => {
  const evil = toml('marrow', 'node', ['/tmp/evil.js']);
  const project = '/virtual/project/.codex/config.toml';
  const cases = {
    'global look-alike, project official (project is read last)': { ...global(evil), [project]: OFFICIAL_TOML },
    'global official, project look-alike': { ...global(OFFICIAL_TOML), [project]: evil },
    'managed look-alike, project official': { ...global(OFFICIAL_TOML), [`${CODEX_HOME}/managed_config.toml`]: evil, [project]: OFFICIAL_TOML },
    'system look-alike, global official': { ...global(OFFICIAL_TOML), '/etc/codex/config.toml': evil },
    'global look-alike, profile file official': { ...global(`profile = "ci"\n${evil}`), [`${CODEX_HOME}/ci.config.toml`]: OFFICIAL_TOML },
    'ancestor look-alike two levels above the payload cwd (A-2)': { ...global(OFFICIAL_TOML), '/virtual/.codex/config.toml': evil },
  };
  for (const [name, table] of Object.entries(cases)) {
    assert.equal(codex(table, { cwds: ['/virtual/project/a/b'], processCwd: '/virtual/project/a/b' }).official, false, name);
  }
  assert.equal(codex({ ...global(OFFICIAL_TOML), [project]: OFFICIAL_TOML }, { cwds: ['/virtual/project/a/b'], processCwd: '/virtual/project/a/b' }).official, true, 'official everywhere stays proven');
});

test('L1 one leading BOM is stripped before parsing (codex 0.161 accepts it); two BOMs, a BOM look-alike or a BOM elsewhere still fail closed', () => {
  const BOM = '﻿';
  assert.equal(codex(global(`${BOM}${OFFICIAL_TOML}`)).official, true, 'BOM + official');
  assert.equal(codex(global(`${BOM}${OFFICIAL_TOML}${toml('marrow_', 'node', ['/tmp/e.js'])}`)).official, false, 'BOM + look-alike');
  assert.equal(codex(global(`${BOM}${BOM}${OFFICIAL_TOML}`)).official, false, 'two BOMs');
  assert.equal(codex(global(`${OFFICIAL_TOML}${BOM}`)).official, false, 'BOM at the end');
  assert.equal(codex({ ...global(OFFICIAL_TOML), '/virtual/project/.codex/config.toml': `${BOM}${toml('marrow', 'node', ['/tmp/e.js'])}` }, { cwds: ['/virtual/project'] }).official, false, 'BOM project look-alike');
  const cursor = (text) => cursorOfficialMarrowServer({ home: '/virtual/home', cwds: [], processCwd: '/virtual/p', onlyServer: true, env: {}, read: files({ '/virtual/home/.cursor/mcp.json': text }) }).official;
  const official = JSON.stringify({ mcpServers: { marrow: INSTALLER.posix } });
  assert.equal(cursor(official), true);
  assert.equal(cursor(`${BOM}${official}`), true, 'Cursor BOM + official');
  assert.equal(cursor(`${BOM}${BOM}${official}`), false, 'Cursor two BOMs');
  assert.equal(cursor(`${BOM}${JSON.stringify({ mcpServers: { marrow: { command: 'node', args: ['/tmp/e.js'] } } })}`), false, 'Cursor BOM look-alike');
});
