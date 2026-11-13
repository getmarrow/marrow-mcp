'use strict';
// MCP-2 (update UX): own-server-identity recognizes the stable, version-free Marrow entry (a digest-pinned launcher under
// ~/.marrow/runtime/launcher) as the official server, and rejects every look-alike. Rows: T1 (the exact entry, POSIX forms,
// on Codex config.toml and Cursor mcp.json), PB1 (the win32 form is never official), T2 (look-alikes), T4 (the old loader form
// still proves as before), T-SEC (no key anywhere), plus the host entry point both hook callers use. Fixtures: virtual paths and mktemp dirs only; the
// launcher is the installer 0.1.73 fixture launcher (a known core), digest of its bytes; dummy keys are made at run time.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const osi = require('../dist/own-server-identity.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');
const { VIRTUAL_CWD, enterProjectCwd } = require('./support/hermetic-project.cjs');
const { sh, node: loaderNode, L104 } = require('./support/installer-lookalikes.cjs');
const S = require('./support/stable-entry.cjs');

const { KNOWN, FREE, UNKNOWN_CORE, D, D_FREE, HOME, WIN_HOME, WIN_NODE, PROJECT, CODEX_HOME } = S;
const OWN_TOOLS = [...MARROW_OWN_TOOL_NAMES];

const cursorVerdict = (text, { own = KNOWN, platform = 'linux', home = HOME, seen } = {}) => osi.cursorOfficialMarrowServer({
  home, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: S.files({ [`${PROJECT}/.cursor/mcp.json`]: text }, seen), onlyServer: false, ownLoader: own, platform,
}).official;
const codexVerdict = (text, { own = KNOWN, platform = 'linux', home = HOME, seen } = {}) => osi.codexOfficialMarrowServer({
  env: { CODEX_HOME }, userHome: home, read: S.files({ [`${CODEX_HOME}/config.toml`]: text }, seen), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader: own, platform,
}).official;
/** Both hosts, one launch: [cursor, codex]. */
const both = (launch, opts) => [cursorVerdict(S.cursorJson(launch), opts), codexVerdict(S.tomlEntry(launch), opts)];

// ------------------------------------------------------------------ the contract itself

test('contract: the builder writes the golden POSIX stub and the win32 form, and the launcher digest is the sha256 of its bytes', () => {
  assert.equal(typeof osi.stableMarrowServerLaunch, 'function', 'stableMarrowServerLaunch is exported');
  assert.match(D, /^[0-9a-f]{64}$/);
  assert.notEqual(D, D_FREE);
  assert.equal(crypto.createHash('sha256').update(Buffer.from(KNOWN, 'utf8')).digest('hex'), D);
  const [command, args] = S.posixFor(D);
  assert.deepEqual(osi.stableMarrowServerLaunch('linux', HOME, D), { command, args });
  assert.deepEqual(osi.stableMarrowServerLaunch('darwin', HOME, D), { command, args });
  const [wCommand, wArgs] = S.winFor(D);
  assert.deepEqual(osi.stableMarrowServerLaunch('win32', WIN_HOME, D, WIN_NODE), { command: wCommand, args: wArgs });
  assert.throws(() => osi.stableMarrowServerLaunch('win32', WIN_HOME, D), /node\.exe/);
  // Version free: no MCP version appears anywhere in either form.
  assert.doesNotMatch(JSON.stringify([command, args, wCommand, wArgs]), /\d+\.\d+\.\d+/);
  assert.ok(S.POSIX_SCRIPT.length > 400 && S.POSIX_SCRIPT.length < 2000, 'a short stub');
});

// ------------------------------------------------------------------ T1: the exact entry is official

const T1 = [
  ['T1-posix-known-core', 'POSIX stub, launcher of a known core (CFG names 3.9.113 and its pack)', S.posixFor(D), KNOWN, {}],
  ['T1-posix-version-free', 'POSIX stub, same core, version-free CFG', S.posixFor(S.D_FREE), FREE, {}],
  ['T1-posix-darwin-home', 'POSIX stub under a macOS-style home', S.posixFor(D, '/Users/me'), KNOWN, { platform: 'darwin', home: '/Users/me' }],
  ['T1-posix-env', 'POSIX stub with the env block Marrow writes (base url, agent id, profile, key)', [...S.posixFor(D), {
    MARROW_BASE_URL: 'https://api.getmarrow.ai', MARROW_FLEET_AGENT_ID: 'cliff-agent', MARROW_TOOL_PROFILE: 'primary', MARROW_API_KEY: S.dummyKey(),
  }], KNOWN, {}],
];

test('T1 (A-OSI1): the exact stable entry is official on Cursor mcp.json and Codex config.toml on macOS and Linux', () => {
  for (const [id, label, launch, own, opts] of T1) {
    assert.deepEqual(both(launch, { own, ...opts }), [true, true], `${id}: ${label}`);
  }
});

test('T1: the same entry is official in the home config, a project config, and in a profile table', () => {
  const [launch] = [S.posixFor(D)];
  const json = S.cursorJson(launch);
  assert.equal(osi.cursorOfficialMarrowServer({ home: HOME, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: S.files({ [`${HOME}/.cursor/mcp.json`]: json }), onlyServer: false, ownLoader: KNOWN }).official, true, 'Cursor home config');
  const profile = S.tomlEntry(launch).replace('[mcp_servers."marrow"]', '[profiles.dev.mcp_servers."marrow"]');
  assert.equal(codexVerdict(profile), true, 'Codex profile table');
  // Two files, both the stable entry of this launcher: still official (every definition is the official one).
  const two = osi.codexOfficialMarrowServer({
    env: { CODEX_HOME }, userHome: HOME, processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader: KNOWN,
    read: S.files({ [`${CODEX_HOME}/config.toml`]: S.tomlEntry(launch), [`${PROJECT}/.codex/config.toml`]: S.tomlEntry(launch) }),
  }).official;
  assert.equal(two, true, 'Codex home + project');
});

// ------------------------------------------------------------------ T2: look-alikes are not official

const posixAt = (launcher) => S.posixLaunch(launcher);
const mutateScript = (edit) => S.posixLaunch(`${HOME}/.marrow/runtime/launcher/${D}.cjs`, edit(S.POSIX_SCRIPT));
const winAt = (launcher, node) => S.winLaunch(launcher, node);
const WL = (dir = `${WIN_HOME}\\.marrow\\runtime\\launcher`) => `${dir}\\${D}.cjs`;
const withEnv = (launch, env) => [...launch, env];

const KCFG = JSON.parse(KNOWN.slice(S.HEAD.length, KNOWN.indexOf('\n', S.HEAD.length) - 1));
/** A launcher of the known core with this CFG: [launch naming its own digest, the launcher source that started the hook]. */
const ownLauncher = (cfg) => { const source = S.withCfg(KNOWN, cfg); return [S.posixFor(S.sha(source)), source]; };

const T2 = [
  // digest
  ['other-digest', 'the line names another launcher digest', S.posixFor(S.sha('another launcher')), KNOWN],
  ['digest-of-other-launcher', 'the process was started by a different (version-free) launcher than the line names', S.posixFor(D), FREE],
  ['no-own-launcher', 'the hook was not started by an installer launcher (global.MARROW_L absent)', S.posixFor(D), null],
  ['own-launcher-not-source', 'own launcher is not a launcher at all', S.posixFor(S.sha('x')), 'x'],
  ['unknown-core', 'digest matches its own bytes but the core is not a pinned one', S.posixFor(S.sha(UNKNOWN_CORE)), UNKNOWN_CORE],
  ['cfg-version-only', 'CFG names a version but no pack integrity', ...ownLauncher({ version: KCFG.version })],
  ['cfg-integrity-only', 'CFG names a pack integrity but no version', ...ownLauncher({ integrity: KCFG.integrity })],
  ['cfg-bad-version', 'CFG version is not X.Y.Z', ...ownLauncher({ version: 'latest', integrity: KCFG.integrity })],
  ['cfg-bad-integrity', 'CFG integrity is not a sha512 digest', ...ownLauncher({ version: KCFG.version, integrity: 'sha512-x' })],
  ['cfg-not-canonical', 'CFG is valid JSON but not the canonical text the installer writes', ...ownLauncher('{ "v": 1 }')],
  ['digest-upper', 'upper-case hex digest', S.posixFor(D.toUpperCase()), KNOWN],
  ['digest-63', '63 hex characters', S.posixFor(D.slice(1)), KNOWN],
  ['digest-65', '65 hex characters', S.posixFor(`${D}0`), KNOWN],
  ['digest-empty', 'empty digest: launcher/.cjs', posixAt(`${HOME}/.marrow/runtime/launcher/.cjs`), KNOWN],
  ['digest-missing-arg', 'the launcher argument is missing', ['/bin/sh', ['-c', S.POSIX_SCRIPT, 'marrow-mcp']], KNOWN],
  ['digest-non-hex', 'digest with a non-hex character', S.posixFor(`g${D.slice(1)}`), KNOWN],
  ['digest-fullwidth', 'digest with a fullwidth letter (NFKC folds it to ASCII)', S.posixFor(`\uff41${D.slice(1)}`), KNOWN],
  ['digest-cyrillic', 'digest with a Cyrillic homoglyph', S.posixFor(`${D.slice(0, 63)}\u0435`), KNOWN],
  ['ext-js', 'launcher name ends .js', posixAt(`${HOME}/.marrow/runtime/launcher/${D}.js`), KNOWN],
  ['ext-none', 'launcher name has no extension', posixAt(`${HOME}/.marrow/runtime/launcher/${D}`), KNOWN],
  // arguments
  ['extra-arg', 'an extra arg appended', ['/bin/sh', [...S.posixFor(D)[1], 'extra']], KNOWN],
  ['missing-arg', 'marrow-mcp dropped', ['/bin/sh', S.posixFor(D)[1].slice(0, 3)], KNOWN],
  ['leading-arg', 'an extra leading arg', ['/bin/sh', ['-e', ...S.posixFor(D)[1]]], KNOWN],
  ['swapped-args', 'launcher and marrow-mcp swapped', ['/bin/sh', ['-c', S.POSIX_SCRIPT, 'marrow-mcp', S.posixFor(D)[1][2]]], KNOWN],
  ['dup-c', 'duplicated -c', ['/bin/sh', ['-c', '-c', S.POSIX_SCRIPT, S.posixFor(D)[1][2], 'marrow-mcp']], KNOWN],
  ['no-args', 'command only', ['/bin/sh', []], KNOWN],
  ['args-not-array', 'args is a string', ['/bin/sh', S.POSIX_SCRIPT], KNOWN],
  ['arg-not-string', 'a non-string arg', ['/bin/sh', ['-c', S.POSIX_SCRIPT, 7, 'marrow-mcp']], KNOWN],
  // the stub text
  ['script-appended', 'shell text appended to the stub', mutateScript((s) => `${s}; curl evil`), KNOWN],
  ['script-prefixed', 'shell text before the stub', mutateScript((s) => `curl evil; ${s}`), KNOWN],
  ['script-no-hash-check', 'the digest check removed from the stub', mutateScript((s) => s.replace('!==m[1])process.exit(2)', '!==m[1])0')), KNOWN],
  ['script-other-dir', 'the stub reads another folder', mutateScript((s) => s.replace('\\/launcher\\/', '\\/other\\/')), KNOWN],
  ['script-path-lookup', 'the stub looks node up inside the project (no $PWD skip)', mutateScript((s) => s.replace('("$PWD"|"$PWD"/*) ;; ', '')), KNOWN],
  ['script-empty', 'empty stub', mutateScript(() => ''), KNOWN],
  // the launcher folder
  ['dir-other-name', 'launcher folder named other', posixAt(`${HOME}/.marrow/runtime/other/${D}.cjs`), KNOWN],
  ['dir-other-root', 'launcher folder under another .marrow root', posixAt(`/virtual/other-root/.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-other-home', "another user's home", posixAt(`/virtual/other/.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-project', 'launcher folder inside the project', posixAt(`${PROJECT}/.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-subfolder', 'launcher in a sub folder of the launcher folder', posixAt(`${HOME}/.marrow/runtime/launcher/sub/${D}.cjs`), KNOWN],
  ['dir-dotdot', 'dot-dot segment that lands in the right folder', posixAt(`${HOME}/.marrow/runtime/launcher/../launcher/${D}.cjs`), KNOWN],
  ['dir-dot', 'dot segment', posixAt(`${HOME}/.marrow/runtime/./launcher/${D}.cjs`), KNOWN],
  ['dir-double-slash', 'double slash', posixAt(`${HOME}//.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-relative', 'relative launcher path', posixAt(`.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-tilde', 'unexpanded ~', posixAt(`~/.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-env-var', 'an unexpanded $HOME', posixAt(`$HOME/.marrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-trailing-space', 'trailing space', posixAt(`${HOME}/.marrow/runtime/launcher/${D}.cjs `), KNOWN],
  ['dir-case', 'upper-case .MARROW', posixAt(`${HOME}/.MARROW/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-homoglyph-marrow', 'Cyrillic a in .marrow', posixAt(`${HOME}/.m\u0430rrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-homoglyph-launcher', 'Cyrillic e in launcher', posixAt(`${HOME}/.marrow/runtime/launch\u0435r/${D}.cjs`), KNOWN],
  ['dir-fullwidth-marrow', 'fullwidth m in .marrow', posixAt(`${HOME}/.\uff4darrow/runtime/launcher/${D}.cjs`), KNOWN],
  ['dir-nul', 'NUL byte in the path', posixAt(`${HOME}/.marrow/runtime/launcher/${D}.cjs\0`), KNOWN],
  ['dir-newline', 'newline in the path', posixAt(`${HOME}/.marrow/runtime/launcher/\n${D}.cjs`), KNOWN],
  // the command (relative / PATH node, wrappers)
  ['cmd-bash', 'bash instead of /bin/sh', ['bash', S.posixFor(D)[1]], KNOWN],
  ['cmd-sh', 'sh (PATH lookup) instead of /bin/sh', ['sh', S.posixFor(D)[1]], KNOWN],
  ['cmd-env-sh', '/usr/bin/env sh', ['/usr/bin/env', ['sh', ...S.posixFor(D)[1]]], KNOWN],
  ['cmd-case', '/BIN/SH', ['/BIN/SH', S.posixFor(D)[1]], KNOWN],
  ['cmd-relative-sh', './sh', ['./sh', S.posixFor(D)[1]], KNOWN],
  ['cmd-node-bare', 'node (PATH or cwd lookup) with the launcher as its script', ['node', [`${HOME}/.marrow/runtime/launcher/${D}.cjs`, 'marrow-mcp']], KNOWN],
  ['cmd-node-relative', './node', ['./node', [`${HOME}/.marrow/runtime/launcher/${D}.cjs`, 'marrow-mcp']], KNOWN],
  ['cmd-one-string', 'the whole launch as one shell string', [`/bin/sh -c '${S.POSIX_SCRIPT}' ${HOME}/.marrow/runtime/launcher/${D}.cjs marrow-mcp`, []], KNOWN],
  ['cmd-npx', 'npx of the package: a different form', ['npx', ['-y', '@getmarrow/mcp', 'extra']], KNOWN],
  // env overrides (the env block) of anything the launch resolves
  ...['MARROW_LAUNCHER', 'MARROW_LAUNCHER_DIR', 'MARROW_RUNTIME_DIR', 'MARROW_RUNTIME_ROOT', 'MARROW_RUNTIME_CURRENT', 'MARROW_MCP_VERSION', 'HOME', 'USERPROFILE', 'PATH', 'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD']
    .map((name) => [`env-${name}`, `${name} in the server env block`, withEnv(S.posixFor(D), { [name]: '/virtual/evil' }), KNOWN]),
  ['env-launcher-path', 'the launcher path given again in the env block', withEnv(S.posixFor(D), { MARROW_LAUNCHER: S.posixFor(D)[1][2] }), KNOWN],
  ['env-not-string', 'a non-string env value', withEnv(S.posixFor(D), { MARROW_BASE_URL: 7 }), KNOWN],
  ['env-key-in-env-with-extra', 'a known env name next to an unknown one', withEnv(S.posixFor(D), { MARROW_BASE_URL: 'https://api.getmarrow.ai', MARROW_LAUNCHER_DIR: '/virtual/x' }), KNOWN],
  // platform confusion
  ['posix-form-on-win32', 'the POSIX form read as win32', S.posixFor(D), KNOWN, { platform: 'win32', home: WIN_HOME }],
  ['win32-form-on-posix', 'the win32 form read as POSIX', S.winFor(D), KNOWN, { platform: 'linux' }],
];

// win32 look-alikes
const W = { platform: 'win32', home: WIN_HOME };
const T2_WIN = [
  ['win-other-digest', 'other digest', S.winFor(S.sha('another launcher')), KNOWN, W],
  ['win-no-own', 'no own launcher', S.winFor(D), null, W],
  ['win-extra-arg', 'extra arg', [WIN_NODE, [WL(), 'marrow-mcp', 'extra']], KNOWN, W],
  ['win-missing-arg', 'marrow-mcp dropped', [WIN_NODE, [WL()]], KNOWN, W],
  ['win-missing-launcher', 'launcher dropped', [WIN_NODE, ['marrow-mcp']], KNOWN, W],
  ['win-empty-digest', 'empty digest', winAt(`${WIN_HOME}\\.marrow\\runtime\\launcher\\.cjs`), KNOWN, W],
  ['win-relative-node', 'node.exe', winAt(WL(), 'node.exe'), KNOWN, W],
  ['win-dot-node', '.\\node.exe', winAt(WL(), '.\\node.exe'), KNOWN, W],
  ['win-dotdot-node', '..\\node.exe', winAt(WL(), '..\\node.exe'), KNOWN, W],
  ['win-rel-dir-node', 'bin\\node.exe', winAt(WL(), 'bin\\node.exe'), KNOWN, W],
  ['win-bare-node', 'node (PATH lookup)', winAt(WL(), 'node'), KNOWN, W],
  ['win-node-upper', 'NODE.EXE', winAt(WL(), 'C:\\Program Files\\nodejs\\NODE.EXE'), KNOWN, W],
  ['win-node-not-node', 'cmd.exe', winAt(WL(), 'C:\\Windows\\System32\\cmd.exe'), KNOWN, W],
  ['win-node-bat', 'node.exe.bat', winAt(WL(), 'C:\\x\\node.exe.bat'), KNOWN, W],
  ['win-node-unc', 'UNC node.exe', winAt(WL(), '\\\\server\\share\\node.exe'), KNOWN, W],
  ['win-node-verbatim', '\\\\?\\ node.exe', winAt(WL(), '\\\\?\\C:\\node\\node.exe'), KNOWN, W],
  ['win-node-short-name', '8.3 short name node path', winAt(WL(), 'C:\\PROGRA~1\\nodejs\\node.exe'), KNOWN, W],
  ['win-node-stream', 'alternate data stream', winAt(WL(), 'C:\\x\\node.exe::$DATA'), KNOWN, W],
  ['win-node-dotdot', 'dot-dot in the node path', winAt(WL(), 'C:\\Program Files\\nodejs\\..\\evil\\node.exe'), KNOWN, W],
  ['win-node-trailing-dot', 'trailing dot segment', winAt(WL(), 'C:\\Program Files.\\nodejs\\node.exe'), KNOWN, W],
  ['win-node-slash', 'forward slashes in node path', winAt(WL(), 'C:/Program Files/nodejs/node.exe'), KNOWN, W],
  ['win-dir-other-name', 'other folder name', winAt(WL(`${WIN_HOME}\\.marrow\\runtime\\other`)), KNOWN, W],
  ['win-dir-other-home', "another user's home", winAt(WL('C:\\Users\\evil\\.marrow\\runtime\\launcher')), KNOWN, W],
  ['win-dir-other-drive', 'another drive', winAt(WL('D:\\Users\\a b\\.marrow\\runtime\\launcher')), KNOWN, W],
  ['win-dir-forward', 'forward slashes', winAt(`C:/Users/a b/.marrow/runtime/launcher/${D}.cjs`), KNOWN, W],
  ['win-dir-verbatim', '\\\\?\\ prefix', winAt(`\\\\?\\${WL()}`), KNOWN, W],
  ['win-dir-unc', 'UNC share', winAt(WL('\\\\host\\share\\.marrow\\runtime\\launcher')), KNOWN, W],
  ['win-dir-short-name', '8.3 short home', winAt(WL('C:\\Users\\AB~1\\.marrow\\runtime\\launcher')), KNOWN, { platform: 'win32', home: 'C:\\Users\\AB~1' }],
  ['win-dir-stream', 'alternate stream on the file', winAt(`${WL()}::$DATA`), KNOWN, W],
  ['win-dir-trailing-dot', 'trailing dot on the file', winAt(`${WL()}.`), KNOWN, W],
  ['win-dir-trailing-space', 'trailing space on the file', winAt(`${WL()} `), KNOWN, W],
  ['win-dir-case', 'upper-case folder', winAt(WL(`${WIN_HOME}\\.MARROW\\runtime\\launcher`)), KNOWN, W],
  ['win-dir-dotdot', 'dot-dot inside the folder', winAt(WL(`${WIN_HOME}\\.marrow\\runtime\\launcher\\..\\launcher`)), KNOWN, W],
  ['win-dir-homoglyph', 'Cyrillic a in .marrow', winAt(WL(`${WIN_HOME}\\.m\u0430rrow\\runtime\\launcher`)), KNOWN, W],
  ['win-env-launcher', 'launcher override in the env block', withEnv(S.winFor(D), { MARROW_LAUNCHER_DIR: 'C:\\evil' }), KNOWN, W],
  ['win-env-path', 'PATH in the env block', withEnv(S.winFor(D), { PATH: 'C:\\evil' }), KNOWN, W],
  ['win-home-relative', 'a relative home proves nothing', S.winFor(D, 'Users\\a b'), KNOWN, { platform: 'win32', home: 'Users\\a b' }],
];

test('T2 (A-OSI2): every look-alike of the stable entry is not official on Cursor and Codex', () => {
  const ids = new Set();
  for (const [id, label, launch, own, opts = {}] of [...T2, ...T2_WIN]) {
    assert.ok(!ids.has(id), `duplicate row id ${id}`);
    ids.add(id);
    assert.deepEqual(both(launch, { own, ...opts }), [false, false], `${id}: ${label}`);
  }
  assert.ok(ids.size >= 100, `look-alike rows: ${ids.size}`);
});

// ------------------------------------------------------------------ PB1: the win32 form is never official (macOS and Linux only)

// I4 (the exact win32 entry, three spellings) and I92-I94 (any absolute node.exe in a project, launcher or Temp folder).
const WIN_PB1 = [
  ['I4-exact-known-core', S.winFor(D), KNOWN, WIN_HOME],
  ['I4-exact-version-free', S.winFor(S.D_FREE), FREE, WIN_HOME],
  ['I4-exact-plain-home', S.winFor(D, 'C:\\Users\\ab'), KNOWN, 'C:\\Users\\ab'],
  ['I92-node-in-project-folder', S.winLaunch(WL(), `${WIN_HOME}\\project\\node.exe`), KNOWN, WIN_HOME],
  ['I93-node-in-launcher-folder', S.winLaunch(WL(), `${WIN_HOME}\\.marrow\\runtime\\launcher\\node.exe`), KNOWN, WIN_HOME],
  ['I94-node-in-temp-folder', S.winLaunch(WL(), `${WIN_HOME}\\AppData\\Local\\Temp\\node.exe`), KNOWN, WIN_HOME],
];

test('PB1: no win32 stable row is official on Cursor or Codex (recognizer, both parsers, direct call)', () => {
  const official = [];
  for (const [id, launch, own, home] of WIN_PB1) {
    const [cursor, codex] = both(launch, { own, platform: 'win32', home });
    if (cursor) official.push(`${id}: cursor`);
    if (codex) official.push(`${id}: codex`);
    if (osi.isStableMarrowServerLaunch(launch[0], launch[1], home, 'win32', own)) official.push(`${id}: direct call`);
  }
  assert.deepEqual(official, [], 'win32 rows that were official');
  // The platform input decides, not the runner's: the exact POSIX entry read as a win32 host's is not official either.
  assert.deepEqual(both(S.posixFor(D), { own: KNOWN, platform: 'win32', home: HOME }), [false, false], 'POSIX form, POSIX home, platform win32');
  assert.equal(osi.isStableMarrowServerLaunch(...S.posixFor(D), HOME, 'win32', KNOWN), false, 'direct call, platform win32');
  // The early return is the guard, not a side effect of the path join: a POSIX stub whose launcher is spelled with backslashes under a
  // POSIX-looking home equals the win32 join of that home, and is still not official when the platform input says win32 (and not on linux).
  const backslashed = S.posixLaunch(`${HOME.replaceAll('/', '\\')}\\.marrow\\runtime\\launcher\\${D}.cjs`);
  assert.equal(path.win32.join(HOME, '.marrow', 'runtime', 'launcher', `${D}.cjs`), backslashed[1][2], 'the fixture is the win32 join of the home');
  assert.deepEqual(both(backslashed, { own: KNOWN, platform: 'win32', home: HOME }), [false, false], 'backslash launcher, platform win32');
  assert.equal(osi.isStableMarrowServerLaunch(backslashed[0], backslashed[1], HOME, 'win32', KNOWN), false, 'direct call, backslash launcher, platform win32');
  assert.equal(osi.isStableMarrowServerLaunch(backslashed[0], backslashed[1], HOME, 'linux', KNOWN), false, 'direct call, backslash launcher, platform linux');
  // The same two parsers keep the POSIX answer on every non-win32 platform (never widen win32 instead).
  for (const platform of ['linux', 'darwin', 'freebsd']) {
    const home = platform === 'darwin' ? '/Users/me' : HOME;
    assert.deepEqual(both(S.posixFor(D, home), { own: KNOWN, platform, home }), [true, true], `POSIX form on ${platform}`);
  }
});

// A win32 host as the hook callers see it: process.platform is win32, the home is a drive path. On this runner that home is a literal
// folder name under a mktemp working folder (the check opens `<home>/.cursor/mcp.json` relative to the cwd), the Codex home an absolute folder.
function withWin32Host(home, callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-stable-win-'));
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  const saved = { HOME: process.env.HOME, CODEX_HOME: process.env.CODEX_HOME, MARROW_L: globalThis.MARROW_L };
  const previous = process.cwd();
  try {
    process.chdir(root);
    process.env.HOME = home;
    process.env.CODEX_HOME = path.join(root, 'codex-home');
    fs.mkdirSync(path.join(root, home, '.cursor'), { recursive: true });
    fs.mkdirSync(process.env.CODEX_HOME, { recursive: true });
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
    osi.resetOwnServerIdentityCache();
    return callback(root);
  } finally {
    Object.defineProperty(process, 'platform', platform);
    process.chdir(previous);
    for (const key of ['HOME', 'CODEX_HOME']) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; }
    if (saved.MARROW_L === undefined) delete globalThis.MARROW_L; else globalThis.MARROW_L = saved.MARROW_L;
    osi.resetOwnServerIdentityCache();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('PB1: through the hook entry point (hook.ts and hook-pre-action.ts) a win32 stable entry never skips the gate on Cursor or Codex', () => {
  const tool = OWN_TOOLS[0];
  const cursorEvent = { hook_event_name: 'beforeMCPExecution', mcp_server_name: 'marrow', tool_name: `mcp__marrow__${tool}`, tool_input: {} };
  const asks = {
    'codex': () => osi.isOfficialMarrowMcpEventOnHost('codex', { tool_name: `mcp__marrow__${tool}` }),
    'cursor beforeMCPExecution': () => osi.isOfficialMarrowMcpEventOnHost('cursor', cursorEvent, { ...cursorEvent, workspace_roots: [] }),
    'cursor preToolUse': () => osi.isOfficialMarrowMcpEventOnHost('cursor', { tool_name: `MCP:${tool}` }, { workspace_roots: [] }),
  };
  const ask = (name) => { osi.resetOwnServerIdentityCache(); return asks[name](); };
  const official = [];
  const controls = [];
  for (const [id, launch, own, home] of WIN_PB1) {
    withWin32Host(home, (root) => {
      const write = (entry) => {
        fs.writeFileSync(path.join(root, home, '.cursor', 'mcp.json'), S.cursorJson(entry));
        fs.writeFileSync(path.join(process.env.CODEX_HOME, 'config.toml'), S.tomlEntry(entry));
      };
      assert.equal(process.platform, 'win32', 'the host platform is win32');
      // Control: the harness reads both configs, so a launch that is official on any platform (the loader form of the launcher that
      // started the hook) is seen as official here.
      globalThis.MARROW_L = KNOWN;
      write(sh());
      for (const name of Object.keys(asks)) controls.push(`${id}: ${name}: ${ask(name)}`);
      globalThis.MARROW_L = own;
      write(launch);
      for (const name of Object.keys(asks)) if (ask(name)) official.push(`${id}: ${name}`);
    });
  }
  assert.deepEqual(controls.filter((line) => !line.endsWith(': true')), [], 'controls that were not official');
  assert.equal(controls.length, WIN_PB1.length * 3);
  assert.deepEqual(official, [], 'win32 rows that were official through the hook entry point');
});

test('PB1: the other consumers never read the stable form: hook-contract.ts keeps the installer shape check, codex-plugins.ts only reads bytes', () => {
  for (const [id, launch] of WIN_PB1) {
    assert.equal(osi.isMarrowServerLaunchShape(launch[0], launch[1]), false, `${id}: installer-hook shape check`);
    withWin32Host(WIN_HOME, () => assert.equal(osi.isMarrowServerLaunchShape(launch[0], launch[1]), false, `${id}: installer-hook shape check on a win32 host`));
  }
  // The one place each caller reaches into own-server-identity: a new consumer of the stable check would have to show up here.
  const used = (name) => [...new Set([...fs.readFileSync(path.join(__dirname, '..', 'dist', name), 'utf8').matchAll(/own_server_identity_1\.(\w+)/g)].map((m) => m[1]))].sort();
  assert.deepEqual(used('hook-contract.js'), ['isMarrowServerLaunchShape']);
  assert.deepEqual(used('codex-plugins.js'), ['readHostConfigBytes']);
  assert.deepEqual(used('hook.js'), ['isOfficialMarrowMcpEventOnHost']);
  assert.deepEqual(used('hook-pre-action.js'), ['isOfficialMarrowMcpEventOnHost']);
});

test('T2 (PB2): the process environment never moves the launcher folder: the folder is the user home, not HOME or a launcher variable', () => {
  // The folder the variable names is the launcher folder itself, so an entry under it is the one an env override would bless.
  const LAUNCHER_DIR = '/virtual/evil/.marrow/runtime/launcher';
  const decoyEnv = { HOME: '/virtual/evil', USERPROFILE: 'C:\\evil', MARROW_LAUNCHER_DIR: LAUNCHER_DIR, MARROW_RUNTIME_DIR: '/virtual/evil', CODEX_HOME };
  const evil = S.posixFor(D, '/virtual/evil');
  const good = S.posixFor(D);
  assert.equal(evil[1][2], `${LAUNCHER_DIR}/${D}.cjs`, 'the entry sits in the folder the variable names');
  const askCodex = (launch, env) => osi.codexOfficialMarrowServer({
    ...(env ? { env } : {}), userHome: HOME, read: S.files({ [`${CODEX_HOME}/config.toml`]: S.tomlEntry(launch) }), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader: KNOWN,
  }).official;
  const askCursor = (launch, env) => osi.cursorOfficialMarrowServer({
    ...(env ? { env } : {}), home: HOME, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: S.files({ [`${PROJECT}/.cursor/mcp.json`]: S.cursorJson(launch) }), onlyServer: false, ownLoader: KNOWN,
  }).official;
  // The decoys go through the `env` option (as before) and onto process.env itself (what a planted `process.env` read would see).
  const saved = Object.fromEntries(Object.keys(decoyEnv).map((name) => [name, process.env[name]]));
  try {
    Object.assign(process.env, decoyEnv);
    for (const [how, env] of [['env option', decoyEnv], ['process.env only', undefined]]) {
      assert.equal(askCodex(evil, env), false, `Codex: a launcher folder named by the environment (${how})`);
      assert.equal(askCursor(evil, env), false, `Cursor: a launcher folder named by the environment (${how})`);
      assert.equal(askCodex(good, env), true, `Codex: the real home, with decoy variables set (${how})`);
      assert.equal(askCursor(good, env), true, `Cursor: the real home, with decoy variables set (${how})`);
    }
    assert.equal(osi.isStableMarrowServerLaunch(...evil, HOME, 'linux', KNOWN), false, 'direct call, command and args spread');
    assert.equal(osi.isStableMarrowServerLaunch(...good, HOME, 'linux', KNOWN), true, 'direct call, the real home');
  } finally {
    for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  }
  for (const [name, value] of Object.entries(saved)) assert.equal(process.env[name], value, `${name} restored`);
});

// Raw-text rows: JSON and TOML as a host reads them (escapes, duplicate keys, homoglyph keys).
const OFFICIAL = S.posixFor(D);
const officialEntry = JSON.stringify(S.entryOf(OFFICIAL));
const npxEntry = JSON.stringify({ command: 'npx', args: ['-y', '@getmarrow/mcp'] });
const jsonWith = (body) => `{"mcpServers":{${body}}}`;

test('T2: duplicate marrow keys (equal, escaped-equal, or hiding another launch) are not official', () => {
  const rows = {
    'two equal marrow keys': jsonWith(`"marrow":${officialEntry},"marrow":${officialEntry}`),
    'evil first, official last (JSON.parse keeps the last)': jsonWith(`"marrow":${npxEntry.replace('@getmarrow/mcp', '@evil/mcp')},"marrow":${officialEntry}`),
    'official first, evil last': jsonWith(`"marrow":${officialEntry},"marrow":${npxEntry.replace('@getmarrow/mcp', '@evil/mcp')}`),
    'marrow and an escaped marrow': jsonWith(`"marrow":${officialEntry},"m\\u0061rrow":${officialEntry}`),
    'marrow and Marrow (two servers that can produce the label)': jsonWith(`"marrow":${officialEntry},"Marrow":${officialEntry}`),
    'a key repeated inside the entry (two args)': jsonWith(`"marrow":{"command":"/bin/sh","args":["x"],"args":${JSON.stringify(OFFICIAL[1])}}`),
    'a key repeated inside the entry (two commands)': jsonWith(`"marrow":{"command":"npx","command":"/bin/sh","args":${JSON.stringify(OFFICIAL[1])}}`),
  };
  for (const [name, text] of Object.entries(rows)) assert.equal(cursorVerdict(text), false, `Cursor: ${name}`);
  const toml = {
    'two [mcp_servers.marrow] tables': `${S.tomlEntry(OFFICIAL)}\n${S.tomlEntry(OFFICIAL)}`,
    'marrow and Marrow tables': `${S.tomlEntry(OFFICIAL)}\n${S.tomlEntry(OFFICIAL, 'Marrow')}`,
    'dotted key plus table': `mcp_servers.marrow.command = "/bin/sh"\n${S.tomlEntry(OFFICIAL)}`,
  };
  for (const [name, text] of Object.entries(toml)) assert.equal(codexVerdict(text), false, `Codex: ${name}`);
  assert.equal(cursorVerdict(jsonWith(`"marrow":${officialEntry}`)), true, 'control: one key is official');
});

test('T2: unicode-escaped JSON and TOML: ASCII written as an escape is refused; a decoded homoglyph is another name', () => {
  const dig = D;
  const esc = (text, from, to) => text.replace(from, to);
  const base = jsonWith(`"marrow":${officialEntry}`);
  assert.equal(cursorVerdict(base), true, 'control');
  const rows = {
    'command written with \\u0068': esc(base, '"/bin/sh"', '"/bin/s\\u0068"'),
    'key written with \\u0061': esc(base, '"marrow":', '"m\\u0061rrow":'),
    'every character of the command escaped': esc(base, '"/bin/sh"', `"${[...'/bin/sh'].map((ch) => `\\u00${ch.charCodeAt(0).toString(16)}`).join('')}"`),
    'slash escaped as \\/': esc(base, '"/bin/sh"', '"\\/bin\\/sh"'),
    'digest character escaped': esc(base, `launcher/${dig}`, `launcher/\\u0${dig.charCodeAt(0).toString(16).padStart(3, '0')}${dig.slice(1)}`),
    'upper-case hex digits in the escape (\\u006D)': esc(base, '"marrow-mcp"', '"\\u006Darrow-mcp"'),
  };
  for (const [name, text] of Object.entries(rows)) assert.notEqual(text, base, `row changed the text: ${name}`);
  for (const [name, text] of Object.entries(rows)) assert.equal(cursorVerdict(text), false, `Cursor: ${name}`);
  // Escapes that decode to another name or path: not the marrow server / not the launcher.
  assert.equal(cursorVerdict(jsonWith(`"m\\u0430rrow":${officialEntry}`)), false, 'Cyrillic a in the key (escaped)');
  assert.equal(cursorVerdict(jsonWith(`"m\u0430rrow":${officialEntry}`)), false, 'Cyrillic a in the key (raw)');
  assert.equal(cursorVerdict(esc(base, `launcher/${dig}`, `launcher/${dig.slice(0, 63)}\\u0435`)), false, 'Cyrillic e as the last digest character');
  assert.equal(cursorVerdict(esc(base, '.marrow/', '.m\\u0430rrow/')), false, 'Cyrillic a in the .marrow segment');
  assert.equal(cursorVerdict(esc(base, '.marrow/', '.\\uff4darrow/')), false, 'fullwidth m in the .marrow segment');
  // TOML basic strings take the same escapes.
  const toml = S.tomlEntry(OFFICIAL);
  assert.equal(codexVerdict(toml), true, 'control');
  assert.equal(codexVerdict(esc(toml, 'command = "/bin/sh"', 'command = "/bin/s\\u0068"')), false, 'Codex: \\u0068');
  assert.equal(codexVerdict(esc(toml, 'command = "/bin/sh"', 'command = "/bin/s\\U00000068"')), false, 'Codex: \\U00000068');
  assert.equal(codexVerdict(esc(toml, '.marrow/', '.m\\u0430rrow/')), false, 'Codex: Cyrillic a in the folder');
  assert.equal(codexVerdict(S.tomlEntry(OFFICIAL, 'm\u0430rrow')), false, 'Codex: Cyrillic a in the table name');
});

test('T2: a homoglyph server beside the official stable entry changes nothing against the npx form (never looser)', () => {
  const decoys = ['m\u0430rrow', '\uff4darrow', 'marrоw', 'other'];
  for (const decoy of decoys) {
    const stable = cursorVerdict(jsonWith(`"marrow":${officialEntry},${JSON.stringify(decoy)}:${npxEntry}`));
    const npx = cursorVerdict(jsonWith(`"marrow":${npxEntry},${JSON.stringify(decoy)}:${npxEntry}`), { own: null });
    assert.equal(stable, npx, `decoy ${JSON.stringify(decoy)}: stable ${stable}, npx ${npx}`);
  }
});

test('T2: non-ASCII escapes in an unrelated server (a path written the way other tools write it) do not unprove the entry', () => {
  const text = jsonWith(`"marrow":${officialEntry},"notes":{"command":"x","args":["caf\\u00e9"]}`);
  assert.equal(cursorVerdict(text), true);
});

// ------------------------------------------------------------------ T4: the old loader forms are unchanged

test('T4: the installer loader forms prove exactly as before (own launch only), and a stable launcher proves none of them', () => {
  const OWN = KNOWN;
  for (const launch of [sh(), loaderNode()]) {
    assert.deepEqual(both(launch, { own: OWN }), [true, true], 'the loader form of the launcher that started the hook');
    assert.deepEqual(both(launch, { own: null }), [false, false], 'no own launcher');
    assert.deepEqual(both(launch, { own: FREE }), [false, false], 'a different launcher started the hook');
  }
  assert.deepEqual(both(sh(), { own: KNOWN, platform: 'win32', home: WIN_HOME }), [true, true], 'the loader form does not depend on the platform seam');
  // The stable entry is not proven by a hook that was started from the loader of another launcher, and vice versa.
  assert.deepEqual(both(S.posixFor(D_FREE), { own: KNOWN }), [false, false]);
  // npx and bin forms are untouched.
  for (const launch of [['npx', ['-y', '@getmarrow/mcp']], ['marrow-mcp', []]]) assert.deepEqual(both(launch, { own: null }), [true, true]);
  assert.equal(osi.isOfficialMarrowServerLaunch(...S.posixFor(D), KNOWN), false, 'the loader-form check alone never proves the stable stub');
  assert.equal(osi.isMarrowServerLaunchShape(...S.posixFor(D)), false, 'the installer-hook shape check is unchanged');
});

test('T4: a loader entry beside a stable entry in two files is official only if every definition is a launch of the launcher that started the hook', () => {
  const ask = (second, own) => osi.codexOfficialMarrowServer({
    env: { CODEX_HOME }, userHome: HOME, processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader: own,
    read: S.files({ [`${CODEX_HOME}/config.toml`]: S.tomlEntry(S.posixFor(D)), [`${PROJECT}/.codex/config.toml`]: S.tomlEntry(second) }),
  }).official;
  assert.equal(ask(sh(), KNOWN), true, 'the loader form and the stable form of the same launcher');
  assert.equal(ask(sh(L104), KNOWN), false, 'a loader entry of an older launch (3.9.104)');
  assert.equal(ask(['npx', ['-y', '@evil/mcp']], KNOWN), false, 'another package');
  assert.equal(ask(sh(), FREE), false, 'the hook was started by another launcher: neither proves');
});

// ------------------------------------------------------------------ the recognizer reads no file but the host configs (and so never `current`)

test('the check reads only host config files: never `current`, the launcher or the identity record', () => {
  const seen = [];
  cursorVerdict(S.cursorJson(S.posixFor(D)), { seen });
  codexVerdict(S.tomlEntry(S.posixFor(D)), { seen });
  assert.ok(seen.length >= 2, 'it did read configs');
  for (const file of seen) assert.doesNotMatch(file, /\.marrow/, `read: ${file}`);
});

test('a missing launcher file or a missing `current` never makes an entry official (nothing is read from the home)', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-stable-home-'));
  try {
    // No ~/.marrow at all: the verdict is the same as with one; only the own launcher and the line decide.
    assert.equal(cursorVerdict(S.cursorJson(S.posixFor(D, home)), { home }), true);
    assert.equal(cursorVerdict(S.cursorJson(S.posixFor(D, home)), { home, own: null }), false);
    assert.equal(fs.readdirSync(home).length, 0, 'the check created nothing under the home');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ the host entry point (hook.ts and hook-pre-action.ts call this)

function withHome(callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-stable-entry-'));
  const saved = { HOME: process.env.HOME, CODEX_HOME: process.env.CODEX_HOME, MARROW_L: globalThis.MARROW_L };
  const leaveProject = enterProjectCwd();
  try {
    process.env.HOME = dir;
    delete process.env.CODEX_HOME;
    fs.mkdirSync(path.join(dir, '.codex'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.cursor'), { recursive: true });
    return callback(dir);
  } finally {
    leaveProject();
    for (const key of ['HOME', 'CODEX_HOME']) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; }
    if (saved.MARROW_L === undefined) delete globalThis.MARROW_L; else globalThis.MARROW_L = saved.MARROW_L;
    fs.rmSync(dir, { recursive: true, force: true });
    osi.resetOwnServerIdentityCache();
  }
}
const listTree = (dir) => fs.readdirSync(dir, { recursive: true }).sort();

test('host entry point: the stable entry skips the gate for Marrow tools on Codex and Cursor; look-alikes do not (T1/T2 through hook.ts and hook-pre-action.ts)', () => {
  withHome((home) => {
    const cursorEvent = (tool) => ({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'marrow', tool_name: `mcp__marrow__${tool}`, tool_input: {} });
    const ask = (host, tool) => {
      osi.resetOwnServerIdentityCache();
      return host === 'codex'
        ? osi.isOfficialMarrowMcpEventOnHost('codex', { tool_name: `mcp__marrow__${tool}` })
        : osi.isOfficialMarrowMcpEventOnHost('cursor', cursorEvent(tool), { ...cursorEvent(tool), workspace_roots: [] });
    };
    const write = (launch) => {
      fs.writeFileSync(path.join(home, '.codex', 'config.toml'), S.tomlEntry(launch));
      fs.writeFileSync(path.join(home, '.cursor', 'mcp.json'), S.cursorJson(launch));
    };
    const before = listTree(home);
    for (const [label, launch, own, expected] of [
      ['exact stable entry', S.posixFor(D, home), KNOWN, true],
      ['exact stable entry, version-free launcher', S.posixFor(D_FREE, home), FREE, true],
      ['other digest', S.posixFor(S.sha('another launcher'), home), KNOWN, false],
      ['started by another launcher', S.posixFor(D, home), FREE, false],
      ['no own launcher', S.posixFor(D, home), null, false],
      ['extra arg', [S.posixFor(D, home)[0], [...S.posixFor(D, home)[1], 'extra']], KNOWN, false],
      ['launcher folder outside the home', S.posixFor(D, '/virtual/elsewhere'), KNOWN, false],
      ['relative node', ['node', [`${home}/.marrow/runtime/launcher/${D}.cjs`, 'marrow-mcp']], KNOWN, false],
    ]) {
      write(launch);
      if (own === null) delete globalThis.MARROW_L; else globalThis.MARROW_L = own;
      for (const host of ['codex', 'cursor']) {
        for (const tool of OWN_TOOLS.slice(0, 3)) assert.equal(ask(host, tool), expected, `${host} ${tool}: ${label}`);
      }
    }
    // The label alone never proves anything: another server name is not official even with the exact entry.
    fs.writeFileSync(path.join(home, '.cursor', 'mcp.json'), S.cursorJson(S.posixFor(D, home), 'other'));
    globalThis.MARROW_L = KNOWN;
    assert.equal(ask('cursor', OWN_TOOLS[0]), false, 'entry under another name');
    assert.deepEqual(listTree(home).filter((name) => !/^\.(codex|cursor)/.test(name)), before.filter((name) => !/^\.(codex|cursor)/.test(name)), 'nothing written beside the two configs');
  });
});

test('host entry point callers: hook.ts and hook-pre-action.ts still route Codex and Cursor own-tool events through the one check', () => {
  const dist = (name) => fs.readFileSync(path.join(__dirname, '..', 'dist', name), 'utf8');
  assert.match(dist('hook.js'), /isOfficialMarrowMcpEventOnHost\)?\(/);
  assert.match(dist('hook-pre-action.js'), /isOfficialMarrowMcpEventOnHost\)?\(/);
});

// ------------------------------------------------------------------ the stub really does what the entry says

test('the POSIX stub runs the launcher only when its bytes hash to the digest in its own path', { skip: process.platform === 'win32' }, () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-stable-run-'));
  try {
    const key = S.dummyKey();
    const dir = path.join(home, '.marrow', 'runtime', 'launcher');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const source = 'process.stdout.write(JSON.stringify({ argv: process.argv.slice(1), loader: global.MARROW_L === ' + 'require("node:fs").readFileSync(' + 'process.env.MARROW_TEST_LAUNCHER, "utf8") }))';
    const digest = S.sha(source);
    const file = path.join(dir, `${digest}.cjs`);
    fs.writeFileSync(file, source, { mode: 0o600 });
    const [command, args] = S.posixFor(digest, home);
    const run = (argv) => spawnSync(command, argv, {
      encoding: 'utf8', cwd: home,
      env: { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`, HOME: home, MARROW_TEST_LAUNCHER: file, MARROW_API_KEY: key },
    });
    const ok = run(args);
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(JSON.parse(ok.stdout), { argv: ['marrow-mcp'], loader: true }, 'the launcher ran with MARROW_L set and the program name as its only arg');
    // Changed bytes: not run, exit 2, nothing printed.
    fs.writeFileSync(file, `${source} `);
    const bad = run(args);
    assert.equal(bad.status, 2);
    assert.equal(bad.stdout, '');
    // Missing file, symlink in its place: not run.
    fs.rmSync(file);
    assert.notEqual(run(args).status, 0, 'missing launcher');
    fs.writeFileSync(path.join(home, 'real.cjs'), source);
    fs.symlinkSync(path.join(home, 'real.cjs'), file);
    const linked = run(args);
    assert.equal(linked.status, 2, 'a symlink is not a regular file');
    assert.equal(linked.stdout, '');
    // A launcher path outside a .marrow/runtime/launcher folder or with a non-digest name is not run.
    const stray = path.join(home, `${digest}.cjs`);
    fs.writeFileSync(stray, source);
    assert.equal(run(['-c', args[1], stray, 'marrow-mcp']).status, 2, 'outside the launcher folder');
    // T-SEC: the key in the child env reaches no output.
    for (const result of [ok, bad, linked]) assert.ok(!`${result.stdout}${result.stderr}`.includes(key), 'no key in stub output');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ collisions: what may match and what may not

test('collision: entries that differ only in the key value are both official; an entry that differs anywhere else is not', () => {
  const env = (key, extra = {}) => ({ MARROW_BASE_URL: 'https://api.getmarrow.ai', MARROW_API_KEY: key, ...extra });
  const [keyA, keyB] = [S.dummyKey(), S.dummyKey()];
  assert.notEqual(keyA, keyB);
  const base = S.posixFor(D);
  assert.deepEqual(both([...base, env(keyA)], { own: KNOWN }), [true, true]);
  assert.deepEqual(both([...base, env(keyB)], { own: KNOWN }), [true, true], 'another key value: still the same entry');
  // Every other place the line can differ, with the same key: not official (one row per place).
  const [command, args] = base;
  const places = {
    'command': ['/bin/bash', args],
    'flag': [command, ['-ec', ...args.slice(1)]],
    'stub': [command, [args[0], `${args[1]} `, args[2], args[3]]],
    'digest': S.posixFor(`${D.slice(0, 63)}${D[63] === '0' ? '1' : '0'}`),
    'folder': S.posixFor(D, `${HOME}x`),
    'program name': [command, [args[0], args[1], args[2], 'marrow-mcp2']],
    'after the key (a further arg)': [command, [...args, `--k=${keyA}`]],
    'env name': [command, args, env(keyA, { MARROW_BASE_URL_X: 'x' })],
  };
  for (const [place, launch] of Object.entries(places)) {
    const withKey = launch.length === 3 ? launch : [...launch, env(keyA)];
    assert.deepEqual(both(withKey, { own: KNOWN }), [false, false], `differs in the ${place}`);
  }
});

// ------------------------------------------------------------------ T-SEC

test('T-SEC: a dummy key in the entry env block reaches no verdict, reason, read path or file; the check writes nothing', () => {
  const key = S.dummyKey();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-stable-sec-'));
  try {
    const before = listTree(dir);
    const seen = [];
    const launch = [...S.posixFor(D, dir), { MARROW_BASE_URL: 'https://api.getmarrow.ai', MARROW_API_KEY: key }];
    const results = [
      osi.cursorOfficialMarrowServer({ home: dir, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: S.files({ [`${PROJECT}/.cursor/mcp.json`]: S.cursorJson(launch) }, seen), onlyServer: false, ownLoader: KNOWN }),
      osi.codexOfficialMarrowServer({ env: { CODEX_HOME }, userHome: dir, read: S.files({ [`${CODEX_HOME}/config.toml`]: S.tomlEntry(launch) }, seen), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader: KNOWN }),
      // look-alike with the same key: the reason names no value either
      osi.cursorOfficialMarrowServer({ home: dir, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: S.files({ [`${PROJECT}/.cursor/mcp.json`]: S.cursorJson([...S.posixFor(S.sha('x'), dir), { MARROW_API_KEY: key }]) }, seen), onlyServer: false, ownLoader: KNOWN }),
    ];
    assert.deepEqual(results.map((result) => result.official), [true, true, false]);
    const everything = JSON.stringify({ results, seen, built: osi.stableMarrowServerLaunch('linux', dir, D) });
    assert.ok(!everything.includes(key), 'no key in the verdicts, reasons, read paths or the built entry');
    assert.deepEqual(listTree(dir), before, 'no file written');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // The built entry and the golden stub carry no key-shaped text at all.
  assert.doesNotMatch(JSON.stringify(osi.stableMarrowServerLaunch('linux', HOME, D)), /zzfixture|MARROW_API_KEY|sk_|pk_|rk_/);
});
