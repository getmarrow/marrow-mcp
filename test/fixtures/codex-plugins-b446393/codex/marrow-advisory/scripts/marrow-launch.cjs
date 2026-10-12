'use strict';
// Codex launcher. Starts one pinned @getmarrow/mcp entrypoint for this plugin's hooks, or the MCP
// server when the explicit `mcp` argument is given (no argument at all refuses). It adds no policy: every decision comes from the same Codex
// entrypoints that `npx @getmarrow/install` writes into .codex/hooks.json.
//
// Only a copy whose files match mcp-manifest.json byte for byte ever runs:
//   1. node_modules in this plugin, if present;
//   2. otherwise a private copy in the plugin data directory (${PLUGIN_DATA}), installed once with
//      `npm ci` from the same lockfile (install scripts off, outside the project directory) and
//      checked against the manifest.
// Only `prepare` (the SessionStart hook) and the MCP server install that copy. The tool hooks have a
// 5-second limit, so they never install: they only look for a verified copy.
// Nothing resolves a version at run time and nothing runs from the project's node_modules.
// When no verified copy can be loaded, the pre-action hook holds the tool call (fail closed) and
// the other entrypoints exit with a non-blocking error.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const POSIX = process.platform !== 'win32';
const PRE_ACTION = 'codex-pre-action-hook';
const PREPARE = 'prepare';
const MCP_MODE = 'mcp';
const ENTRYPOINTS = new Set([
  MCP_MODE,
  PREPARE,
  'codex-context-hook',
  'codex-pre-action-hook',
  'codex-hook',
  'codex-session-hook',
]);
const NPM_TIMEOUT_MS = 120000;
const LOCK_WAIT_MS = 150000;
const LOCK_STALE_MS = 300000;

const args = process.argv.slice(2);

function fail(reason) {
  const fix = 'Reconnect to the network and start a new Codex session so the plugin can install it, '
    + 'or ask the owner to reinstall the plugin: codex plugin remove marrow@getmarrow, then codex plugin add marrow@getmarrow.';
  if (args[0] === PRE_ACTION) {
    process.stdout.write(`${JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `Marrow plugin: ${reason} The action is held until Marrow can start. ${fix}`,
      },
    })}\n`);
    process.exitCode = 0;
    return;
  }
  process.stderr.write(`Marrow plugin: ${reason} ${fix}\n`);
  process.exitCode = 1;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function loadManifest() {
  try {
    const pin = readJson(path.join(ROOT, 'package.json')).dependencies['@getmarrow/mcp'];
    const manifest = readJson(path.join(__dirname, 'mcp-manifest.json'));
    const ok = VERSION_RE.test(String(pin))
      && manifest.schema === 'marrow-plugin-mcp-manifest.v1'
      && manifest.mcp && manifest.mcp.version === pin
      && /^[0-9a-f]{64}$/.test(String(manifest.sha256))
      && Array.isArray(manifest.files)
      && typeof manifest.bin === 'string'
      && manifest.files.includes(manifest.bin);
    return ok ? manifest : null;
  } catch {
    return null;
  }
}

function owned(stat) {
  return !POSIX || typeof process.getuid !== 'function' || stat.uid === process.getuid();
}

// Package files as sorted relative paths. npm's own lock copy and .bin links are not package files.
// Anything that is not a plain file or directory (links, FIFOs, sockets, devices) and anything
// writable by every user rejects the whole copy.
function listFiles(base, relative) {
  const out = [];
  const entries = fs.readdirSync(path.join(base, relative))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const name of entries) {
    const rel = relative ? `${relative}/${name}` : name;
    if (rel === '.bin' || rel === '.package-lock.json') continue;
    const stat = fs.lstatSync(path.join(base, rel));
    if (POSIX && (stat.mode & 0o002) !== 0) throw new Error('writable');
    if (stat.isDirectory()) out.push(...listFiles(base, rel));
    else if (stat.isFile()) out.push(rel);
    else throw new Error('type');
  }
  return out;
}

// Returns the entry file when `base` (a node_modules directory) matches the manifest exactly.
function verifiedEntry(manifest, base) {
  try {
    const stat = fs.lstatSync(base);
    if (!stat.isDirectory() || !owned(stat) || (POSIX && (stat.mode & 0o002) !== 0)) return null;
    const files = listFiles(base, '');
    if (JSON.stringify(files) !== JSON.stringify(manifest.files)) return null;
    const hash = crypto.createHash('sha256');
    for (const file of files) {
      hash.update(file);
      hash.update('\0');
      hash.update(fs.readFileSync(path.join(base, file)));
      hash.update('\0');
    }
    return hash.digest('hex') === manifest.sha256 ? path.join(base, manifest.bin) : null;
  } catch {
    return null;
  }
}

// A directory this plugin owns: real directory, this user's, closed to group and others.
function privateDir(dir) {
  try {
    const stat = fs.lstatSync(dir);
    return stat.isDirectory() && owned(stat) && (!POSIX || (stat.mode & 0o077) === 0);
  } catch {
    return false;
  }
}

function npmCommand() {
  const bin = path.dirname(process.execPath);
  const candidates = POSIX
    ? [path.join(bin, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'), '/usr/share/nodejs/npm/bin/npm-cli.js']
    : [path.join(bin, 'node_modules', 'npm', 'bin', 'npm-cli.js')];
  for (const cli of candidates) {
    try {
      if (fs.statSync(cli).isFile()) return { file: process.execPath, prefix: [cli] };
    } catch {
      // try the next location
    }
  }
  // POSIX PATH lookup never searches the current directory unless PATH asks for it; no shell.
  return POSIX ? { file: 'npm', prefix: [] } : null;
}

function removeQuietly(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch {
    // a leftover directory is removed by the next successful install
  }
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function installCopy(data, id, manifest) {
  const npm = npmCommand();
  if (!npm) return false;
  const stage = path.join(data, `${id}.stage-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  try {
    fs.mkdirSync(stage, { mode: 0o700 });
    for (const file of ['package.json', 'package-lock.json']) {
      fs.copyFileSync(path.join(ROOT, file), path.join(stage, file));
    }
    const { spawnSync } = require('child_process');
    const result = spawnSync(npm.file, [...npm.prefix, 'ci', '--ignore-scripts', '--no-bin-links', '--omit=dev',
      '--no-audit', '--no-fund', '--loglevel=error'], {
      cwd: stage,
      env: { ...process.env, npm_config_ignore_scripts: 'true', npm_config_update_notifier: 'false' },
      stdio: 'ignore',
      timeout: NPM_TIMEOUT_MS,
      windowsHide: true,
    });
    if (result.status !== 0 || !verifiedEntry(manifest, path.join(stage, 'node_modules'))) return false;
    fs.renameSync(stage, path.join(data, id));
    return true;
  } catch {
    return false;
  } finally {
    removeQuietly(stage);
  }
}

// The plugin data directory. Codex sets PLUGIN_DATA (and CLAUDE_PLUGIN_DATA) for plugin hooks only;
// a plugin MCP server gets no path variables, so it uses the same directory Codex gives the hooks:
// <codex home>/plugins/data/<plugin>-<marketplace> for a copy cached at
// <codex home>/plugins/cache/<marketplace>/<plugin>/<version>. Any other layout has no data directory.
function dataDir() {
  const given = process.env.PLUGIN_DATA || process.env.CLAUDE_PLUGIN_DATA;
  if (given) return path.isAbsolute(given) ? given : null;
  const plugin = path.dirname(ROOT);
  const marketplace = path.dirname(plugin);
  const cache = path.dirname(marketplace);
  if (path.basename(cache) !== 'cache' || path.basename(path.dirname(cache)) !== 'plugins') return null;
  return path.join(path.dirname(cache), 'data', `${path.basename(plugin)}-${path.basename(marketplace)}`);
}

// One-time install into the plugin data directory; concurrent starts wait on a lock directory.
// Without `install`, only an already verified copy is used.
function dataCopy(manifest, install) {
  const data = dataDir();
  if (!data || !path.isAbsolute(data)) return null;
  const id = `mcp-${manifest.mcp.version}-${manifest.sha256.slice(0, 16)}`;
  const dir = path.join(data, id);
  const check = () => (privateDir(dir) ? verifiedEntry(manifest, path.join(dir, 'node_modules')) : null);
  let entry = check();
  if (entry || !install) return entry;
  try {
    fs.mkdirSync(data, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(data);
    if (!stat.isDirectory() || !owned(stat) || (POSIX && (stat.mode & 0o002) !== 0)) return null;
  } catch {
    return null;
  }
  const lock = path.join(data, `${id}.lock`);
  const deadline = Date.now() + LOCK_WAIT_MS;
  while (Date.now() < deadline) {
    try {
      fs.mkdirSync(lock, { mode: 0o700 });
    } catch {
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) removeQuietly(lock);
      } catch {
        // lock released meanwhile
      }
      sleep(250);
      entry = check();
      if (entry) return entry;
      continue;
    }
    try {
      entry = check();
      if (entry) return entry;
      removeQuietly(dir);
      return installCopy(data, id, manifest) ? check() : null;
    } finally {
      removeQuietly(lock);
    }
  }
  return null;
}

function main() {
  if (args.length === 0) {
    // A hook whose host dropped its arguments must never fall into MCP-server mode: the server
    // waits on stdin and times out, which fails open. The server is started only by the explicit
    // `mcp` argument in the plugin's MCP config. This path prints one line to stderr, nothing to stdout,
    // and exits 2 without starting anything. What exit 2 does depends on the event: on Claude Code Stop
    // it keeps the agent going (stderr goes to the model); on PreToolUse it blocks the tool call; on
    // UserPromptSubmit it blocks the prompt; on result and session events it blocks nothing. No shipped
    // hook command reaches this path, because each one names its entrypoint inline.
    process.stderr.write('Marrow plugin: no entrypoint given (the MCP server needs the explicit "mcp" argument). Nothing was started.\n');
    process.exitCode = 2;
    return;
  }
  if (args.length > 1 || !ENTRYPOINTS.has(args[0])) {
    process.stderr.write('Marrow plugin: unknown entrypoint.\n');
    process.exitCode = 1;
    return;
  }
  const manifest = loadManifest();
  if (!manifest) return fail('its pinned @getmarrow/mcp manifest is missing or does not match package.json.');
  const install = args[0] === MCP_MODE || args[0] === PREPARE;
  const entry = verifiedEntry(manifest, path.join(ROOT, 'node_modules')) || dataCopy(manifest, install);
  if (!entry) return fail('could not load a verified copy of the pinned @getmarrow/mcp.');
  if (args[0] === PREPARE) return;
  process.argv = [process.argv[0], entry, ...(args[0] === MCP_MODE ? [] : args)];
  require(entry);
}

main();
