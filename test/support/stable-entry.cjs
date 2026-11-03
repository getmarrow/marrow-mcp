'use strict';
// MCP-2 fixtures: the stable (version-free) Marrow entry, as the installer will write it, and what the own-server-identity
// check must make of it. Nothing here reads a key, the network or the real home; every path is virtual or under a mktemp dir.
//
// The POSIX stub text is a golden file (test/fixtures/stable-entry/posix-stub.txt): it is the contract with the installer, so
// it is kept as bytes apart from src/own-server-identity.ts and a change to either one without the other is a red test.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { LOADER } = require('./installer-lookalikes.cjs');
const { launcherOf } = require('./installer-verified-runtime.cjs');
const { assertNotLiveKey } = require('./dummy-secret.cjs');

const HEAD = "'use strict';\nconst CFG = ";
const POSIX_SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'stable-entry', 'posix-stub.txt'), 'utf8');

/** A launcher of a known (pinned) core: the installer 0.1.73 fixture launcher, CFG naming MCP 3.9.110 and its pack. */
const KNOWN = launcherOf(LOADER);
/** The same core with a CFG that names no version and no pack (the launcher reads `current`). */
const withCfg = (source, cfg) => `${HEAD}${typeof cfg === 'string' ? cfg : JSON.stringify(cfg)};${source.slice(source.indexOf('\n', HEAD.length))}`;
const FREE = withCfg(KNOWN, { v: 1 });
/** A core nobody pinned (one word changed): its digest matches itself and proves nothing. */
const UNKNOWN_CORE = KNOWN.replace('could not start its verified local runtime', 'could not start its verified local runtimes');

const sha = (text) => crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
const D = sha(KNOWN);
const D_FREE = sha(FREE);

const HOME = '/virtual/home';
const WIN_HOME = 'C:\\Users\\a b';
const WIN_NODE = 'C:\\Program Files\\nodejs\\node.exe';
const PROJECT = '/virtual/project';
const CODEX_HOME = '/virtual/codex-home';

/** The POSIX stable entry for a launcher path: [command, args]. */
const posixLaunch = (launcher, script = POSIX_SCRIPT) => ['/bin/sh', ['-c', script, launcher, 'marrow-mcp']];
const posixFor = (digest, home = HOME) => posixLaunch(`${home}/.marrow/runtime/launcher/${digest}.cjs`);
/** The win32 stable entry for a launcher path. */
const winLaunch = (launcher, node = WIN_NODE) => [node, [launcher, 'marrow-mcp']];
const winFor = (digest, home = WIN_HOME) => winLaunch(`${home}\\.marrow\\runtime\\launcher\\${digest}.cjs`);

/** A fresh dummy key (fixed non-key prefix, runtime hex, classified not-live on every draw). */
const dummyKey = () => assertNotLiveKey(`zzfixture-${crypto.randomBytes(12).toString('hex')}`);

const entryOf = ([command, args, env]) => ({ command, args, ...(env ? { env } : {}) });
const cursorJson = (launch, name = 'marrow') => JSON.stringify({ mcpServers: { [name]: entryOf(launch) } });
const tomlString = (value) => JSON.stringify(value);
const tomlEntry = ([command, args, env], name = 'marrow') => `[mcp_servers.${JSON.stringify(name)}]\ncommand = ${tomlString(command)}\nargs = ${JSON.stringify(args)}\n${
  env ? `env = { ${Object.entries(env).map(([key, value]) => `${key} = ${JSON.stringify(value)}`).join(', ')} }\n` : ''}`;

const files = (table, seen) => (file) => {
  if (seen) seen.push(file);
  return Object.prototype.hasOwnProperty.call(table, file) ? { state: 'ok', text: table[file] } : { state: 'missing' };
};

module.exports = {
  HEAD, POSIX_SCRIPT, KNOWN, FREE, UNKNOWN_CORE, withCfg, sha, D, D_FREE, HOME, WIN_HOME, WIN_NODE, PROJECT, CODEX_HOME,
  posixLaunch, posixFor, winLaunch, winFor, dummyKey, entryOf, cursorJson, tomlEntry, files,
};
