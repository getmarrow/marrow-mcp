// S-A2F1: an installer launch proves the official Marrow MCP server only when it is exactly the launch of
// the installer loader that started this hook (same version, pack integrity, SDK pin and core). Every
// look-alike from the installer 0.1.73 audit and every exactness row is not proven, on Cursor and Codex.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  codexOfficialMarrowServer,
  cursorOfficialMarrowServer,
  isMarrowServerLaunchShape,
  isOfficialMarrowServerLaunch,
} = require('../dist/own-server-identity.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');
const { VIRTUAL_CWD } = require('./support/hermetic-project.cjs');
const { launcherOf, installVerifiedRuntime, runThroughLoader, pool, assertDenied, assertSkipped } = require('./support/installer-verified-runtime.cjs');
const { LOADER, CFG, V, ROWS, LEGACY, L104, OLD_INTEGRITY, loaderIn, sh, cfg } = require('./support/installer-lookalikes.cjs');

const OWN = [...MARROW_OWN_TOOL_NAMES];
const OWN_SOURCE = launcherOf(LOADER);
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const HOME = '/virtual/home';
const PROJECT = '/virtual/project';
const CODEX_HOME = '/virtual/codex-home';

const files = (table) => (path) => (Object.prototype.hasOwnProperty.call(table, path) ? { state: 'ok', text: table[path] } : { state: 'missing' });
const entryOf = ([command, args, env]) => ({ command, args, ...(env ? { env } : {}) });
const cursorJson = (servers) => JSON.stringify({ mcpServers: servers });
const tomlEntry = (name, [command, args, env]) => `[mcp_servers.${JSON.stringify(name)}]\ncommand = ${JSON.stringify(command)}\nargs = ${JSON.stringify(args)}\n${
  env ? `env = { ${Object.entries(env).map(([key, value]) => `${key} = ${JSON.stringify(value)}`).join(', ')} }\n` : ''}`;
const cursor = (table, ownLoader = OWN_SOURCE, onlyServer = false) => cursorOfficialMarrowServer({ home: HOME, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: files(table), onlyServer, ownLoader }).official;
const codex = (table, ownLoader = OWN_SOURCE) => codexOfficialMarrowServer({ env: { CODEX_HOME }, read: files(table), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader }).official;
const cursorWith = (launch, ownLoader) => cursor({ [`${PROJECT}/.cursor/mcp.json`]: cursorJson({ marrow: entryOf(launch) }) }, ownLoader);
const codexWith = (launch, ownLoader) => codex({ [`${CODEX_HOME}/config.toml`]: tomlEntry('marrow', launch) }, ownLoader);

test('fixture: the installer 0.1.73 loader carries MCP 3.9.107, its pack integrity and the lockfile SDK pin', () => {
  assert.equal(V, '3.9.107');
  assert.equal(CFG.integrity, 'sha512-hZvk+quqAmD9s4pf74SZkaDblK2rQL9hww0S2cbbA48AoSBtB7ktCgcLLALsze0DynTGU6MpiFzjcfDqmB2M5w==');
  const lock = require('../package-lock.json').packages['node_modules/@getmarrow/sdk'];
  assert.deepEqual(CFG.sdk, { version: lock.version, integrity: lock.integrity }, 'A1 F2: the fixture SDK pin is the rebuilt 3.7.67 pack');
});

test('launch check: only the exact own launch is proven; every look-alike is not', () => {
  for (const [id, label, launch, proven] of ROWS) {
    if (launch[2]) continue; // env rows are decided per server definition below
    assert.equal(isOfficialMarrowServerLaunch(launch[0], launch[1], OWN_SOURCE), proven, `${id}: ${label}`);
  }
});

test('Cursor and Codex: every row gets the expected verdict; L1, L2 and L3 are no longer proven', () => {
  for (const [id, label, launch, proven] of ROWS) {
    assert.equal(cursorWith(launch), proven, `Cursor ${id}: ${label}`);
    assert.equal(codexWith(launch), proven, `Codex ${id}: ${label}`);
  }
  for (const id of ['L1', 'L2', 'L3']) assert.equal(ROWS.find((row) => row[0] === id)[3], false, id);
});

test('no own installer loader (hook started by npx or the bin): no installer form is proven, the npx form still is', () => {
  assert.equal(globalThis.MARROW_L, undefined, 'this test process was not started by a loader');
  for (const [id, , launch] of ROWS) {
    assert.equal(cursorWith(launch, null), false, `Cursor ${id}`);
    assert.equal(codexWith(launch, null), false, `Codex ${id}`);
    const table = { [`${PROJECT}/.cursor/mcp.json`]: cursorJson({ marrow: entryOf(launch) }) };
    assert.equal(cursorOfficialMarrowServer({ home: HOME, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: files(table), onlyServer: false }).official, false, `Cursor ${id}, default`);
    const toml = { [`${CODEX_HOME}/config.toml`]: tomlEntry('marrow', launch) };
    assert.equal(codexOfficialMarrowServer({ env: { CODEX_HOME }, read: files(toml), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT] }).official, false, `Codex ${id}, default`);
  }
  assert.equal(cursorWith(['npx', ['-y', '@getmarrow/mcp']], null), true);
  assert.equal(codexWith(['npx', ['-y', '@getmarrow/mcp']], null), true);
});

test('the default own loader is global.MARROW_L, as the installer loader sets it', () => {
  const saved = globalThis.MARROW_L;
  try {
    delete globalThis.MARROW_L;
    assert.equal(isOfficialMarrowServerLaunch(...sh()), false);
    globalThis.MARROW_L = OWN_SOURCE;
    assert.equal(isOfficialMarrowServerLaunch(...sh()), true);
    assert.equal(cursorWith(sh(), undefined), true);
    assert.equal(isOfficialMarrowServerLaunch(...sh(OLD_INTEGRITY)), false);
  } finally {
    if (saved === undefined) delete globalThis.MARROW_L; else globalThis.MARROW_L = saved;
  }
});

test('a forged or unusable own loader proves nothing', () => {
  const forged = {
    'a Buffer': Buffer.from(OWN_SOURCE),
    'a number': 1,
    'an object': { source: OWN_SOURCE },
    'the packed loader text, not its source': LOADER,
    'integrity null (train-2)': launcherOf(LEGACY.posix_next.args[2]),
    'core changed': OWN_SOURCE.replace('could not start its verified local runtime', 'could not start its verified local runtimes'),
    'CFG not canonical JSON': OWN_SOURCE.replace('{"version"', '{ "version"'),
    'trailing byte': `${OWN_SOURCE} `,
    'version 3.9.107 with build metadata': launcherOf(cfg(() => ({ version: `${V}+x` }))),
    'integrity with extra padding': launcherOf(cfg((c) => ({ integrity: `${c.integrity}=` }))),
    'oversized': OWN_SOURCE + ' '.repeat(1 << 17),
    'version wider than the shape check (5 digits)': launcherOf(cfg(() => ({ version: '3.9.10500' }))),
  };
  for (const [label, ownLoader] of Object.entries(forged)) {
    assert.equal(isOfficialMarrowServerLaunch(...sh(), ownLoader), false, label);
    assert.equal(cursorWith(sh(), ownLoader), false, `Cursor ${label}`);
  }
  const wide = forged['version wider than the shape check (5 digits)'];
  assert.equal(isOfficialMarrowServerLaunch(...sh(cfg(() => ({ version: '3.9.10500' })), '3.9.10500'), wide), false, 'never wider than master');
  // A forged own pair cannot be matched by launching it: the null-integrity launch stays unproven under itself.
  assert.equal(isOfficialMarrowServerLaunch(LEGACY.posix_next.command, LEGACY.posix_next.args, forged['integrity null (train-2)']), false);
});

test('identity is relative to the own launch: same exact launch proven, any other pair not', () => {
  const own104 = launcherOf(L104);
  assert.equal(isOfficialMarrowServerLaunch(...sh(L104, '3.9.104'), own104), true, 'a hook started by the 3.9.104 loader proves its own launch');
  assert.equal(isOfficialMarrowServerLaunch(...sh(), own104), false, 'and not the 3.9.107 launch');
  const own172 = launcherOf(loaderIn('installer-0172'));
  assert.equal(isOfficialMarrowServerLaunch(...sh(loaderIn('installer-0172'), '3.9.103'), own172), true, '0.1.72 proves its own launch');
  assert.equal(isOfficialMarrowServerLaunch(...sh(), own172), false);
  const own170 = launcherOf(LEGACY.posix.args[2]);
  assert.equal(isOfficialMarrowServerLaunch(LEGACY.posix.command, LEGACY.posix.args, own170), true, '0.1.70 proves its own launch');
  assert.equal(isOfficialMarrowServerLaunch(LEGACY.win32.command, LEGACY.win32.args, own170), true);
});

test('two servers named marrow (union of configs): proven only when every definition is the exact own launch', () => {
  const exact = entryOf(sh());
  const global = (servers) => ({ [`${HOME}/.cursor/mcp.json`]: cursorJson(servers) });
  const project = (servers) => ({ [`${PROJECT}/.cursor/mcp.json`]: cursorJson(servers) });
  assert.equal(cursor({ ...global({ marrow: exact }), ...project({ marrow: exact }) }), true);
  for (const id of ['L1', 'L2', 'L3', 'N-0172', 'N-0170', 'N-sdk']) {
    const other = entryOf(ROWS.find((row) => row[0] === id)[2]);
    assert.equal(cursor({ ...global({ marrow: other }), ...project({ marrow: exact }) }), false, `Cursor global ${id}, project exact`);
    assert.equal(cursor({ ...global({ marrow: exact }), ...project({ marrow: other }) }), false, `Cursor global exact, project ${id}`);
    const codexTable = { [`${CODEX_HOME}/config.toml`]: tomlEntry('marrow', sh()), [`${PROJECT}/.codex/config.toml`]: tomlEntry('marrow', ROWS.find((row) => row[0] === id)[2]) };
    assert.equal(codex(codexTable), false, `Codex home exact, project ${id}`);
  }
  assert.equal(codex({ [`${CODEX_HOME}/config.toml`]: tomlEntry('marrow', sh()), [`${PROJECT}/.codex/config.toml`]: tomlEntry('marrow', sh()) }), true);
  assert.equal(cursor({ ...project({ marrow: exact, marrow_: exact }) }), false, 'two names that both produce the label');
});

test('setup and doctor still recognize installer hooks of any one version (shape only, never a proof)', () => {
  const shape = Object.fromEntries(ROWS.filter((row) => !row[2][2]).map(([id, , [command, args]]) => [id, isMarrowServerLaunchShape(command, args)]));
  for (const id of ['L0', 'L0n', 'L0r', 'L1', 'L1n', 'L2', 'L3', 'L3n', 'N-case', 'N-pad', 'N-sdk', 'N-0172', 'N-0170', 'N-0170w', 'N-null', 'N-b64']) assert.equal(shape[id], true, id);
  for (const id of ['L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'N-ws', 'N-ws-cfg', 'N-meta', 'N-pre', 'N-latest', 'N-tgz', 'N-dup-c', 'N-dup-pkg', 'N-swap', 'N-swap-n', 'N-lead', 'N-str', 'N-sh', 'N-env-sh', 'N-BIN', 'N-Node']) {
    assert.equal(shape[id], false, id);
  }
});

test('L10/L11 on disk: a planted project @getmarrow/mcp copy unproves the npx form, not the exact installer launch', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-exact-installer-copy-'));
  try {
    const project = join(dir, 'project');
    mkdirSync(join(project, '.git'), { recursive: true });
    mkdirSync(join(project, '.cursor'), { recursive: true });
    mkdirSync(join(project, 'node_modules', '@getmarrow', 'mcp'), { recursive: true });
    writeFileSync(join(project, 'node_modules', '@getmarrow', 'mcp', 'package.json'), '{"name":"@getmarrow/mcp","bin":{"marrow-mcp":"evil.js"}}');
    const verdict = (launch) => {
      writeFileSync(join(project, '.cursor', 'mcp.json'), cursorJson({ marrow: entryOf(launch) }));
      return cursorOfficialMarrowServer({ home: join(dir, 'home'), cwds: [project], processCwd: project, onlyServer: false, ownLoader: OWN_SOURCE, env: {} }).official;
    };
    assert.equal(verdict(sh()), true, 'L10: the loader verifies its own runtime; the project copy is never run');
    assert.equal(verdict(['npx', ['-y', '@getmarrow/mcp']]), false, 'L11: npx could resolve the planted copy');
    assert.equal(verdict(sh(OLD_INTEGRITY)), false, 'L3 next to the copy');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ end to end: the installer's real loader and core

function hostDirs() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-exact-installer-e2e-'));
  const home = join(dir, 'home');
  const project = join(dir, 'project');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(join(project, '.cursor'), { recursive: true });
  mkdirSync(join(project, '.git'));
  mkdirSync(join(home, '.codex'), { recursive: true });
  return { dir, home, project, codexHome: join(home, '.codex') };
}

test('end to end (installer 0.1.73 loader -> verified runtime -> this hook, no key): exact launch skips 58/58; L1 L2 L3 skip 0/58, each call exit 0 and a deny answer', async () => {
  const { dir, home, project, codexHome } = hostDirs();
  try {
    assert.equal(installVerifiedRuntime(home, LOADER), V);
    const beforeMcp = (tool) => ({ hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g', workspace_roots: [project], mcp_server_name: 'marrow', tool_name: tool, tool_input: '{}' });
    const preToolUse = (tool) => ({ hook_event_name: 'preToolUse', conversation_id: 'c', workspace_roots: [project], tool_name: `MCP:${tool}`, tool_input: {} });
    const codexEvent = (tool) => ({ hook_event_name: 'PreToolUse', session_id: 's', cwd: project, tool_name: `mcp__marrow__${tool}`, tool_input: {} });
    // Each call is judged on its own: a skip is exit 0 + the host's skip answer, "not proven" is exit 0 + the host's deny answer.
    // A crashed hook (exit 1, no answer) is neither, so it can never pass as a held tool.
    const cursorRuns = async (launch, event) => {
      writeFileSync(join(project, '.cursor', 'mcp.json'), cursorJson({ marrow: { ...entryOf(launch), env: { MARROW_BASE_URL: 'https://api.getmarrow.ai' } } }));
      return pool(OWN.map((tool) => async () => ({ tool, ...(await runThroughLoader(LOADER, 'cursor-pre-action-hook', event(tool), { home, cwd: project })) })));
    };
    const codexRuns = async (launch) => {
      writeFileSync(join(codexHome, 'config.toml'), tomlEntry('marrow', launch));
      return pool(OWN.map((tool) => async () => ({ tool, ...(await runThroughLoader(LOADER, 'codex-pre-action-hook', codexEvent(tool), { home, codexHome, cwd: project })) })));
    };
    const each = (check, host, results, label) => {
      assert.equal(results.length, OWN.length, `${label}: one call per own tool`);
      for (const result of results) check(host, result, `${label} ${result.tool}`);
    };
    each(assertSkipped, 'cursor', await cursorRuns(sh(), beforeMcp), 'Cursor beforeMCPExecution, exact launch');
    each(assertSkipped, 'cursor', await cursorRuns(sh(), preToolUse), 'Cursor preToolUse, exact launch');
    each(assertSkipped, 'codex', await codexRuns(sh()), 'Codex, exact launch');
    for (const id of ['L1', 'L2', 'L3']) {
      const launch = ROWS.find((row) => row[0] === id)[2];
      each(assertDenied, 'cursor', await cursorRuns(launch, beforeMcp), `Cursor ${id}`);
      each(assertDenied, 'codex', await codexRuns(launch), `Codex ${id}`);
    }
    // What the user sees for an own tool on an unproven server (keyless): the ordinary gate answer, not a skip.
    writeFileSync(join(project, '.cursor', 'mcp.json'), cursorJson({ marrow: entryOf(sh(OLD_INTEGRITY)) }));
    const held = await runThroughLoader(LOADER, 'cursor-pre-action-hook', beforeMcp('marrow_status'), { home, cwd: project });
    assertDenied('cursor', held, 'keyless own tool on an unproven server');
    // The same hook started without the loader (npx or bin) proves no installer form.
    writeFileSync(join(project, '.cursor', 'mcp.json'), cursorJson({ marrow: entryOf(sh()) }));
    const plain = spawnSync(process.execPath, [CLI, 'cursor-pre-action-hook'], {
      input: JSON.stringify(beforeMcp('marrow_status')), cwd: project, encoding: 'utf8', timeout: 30_000,
      env: { PATH: process.env.PATH, HOME: home, MARROW_PASSIVE_TOKEN_USAGE: 'false' },
    });
    assertDenied('cursor', { stdout: plain.stdout, code: plain.status }, 'the hook started without the loader');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
