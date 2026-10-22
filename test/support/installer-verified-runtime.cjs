'use strict';
// A verified local runtime laid out the way @getmarrow/install's runtime core (sha256 73ea5779...)
// checks it: ~/.marrow/runtime/mcp/<version>/ (every level 0700) with node_modules/@getmarrow/{mcp,sdk},
// a `node` link and a 0600 `.verified` record whose version and integrity are the loader's CFG. The
// package inside is this checkout's build, so a hook started through the installer's real loader runs
// the code under test exactly as an installed runtime would (global.MARROW_L set by the loader itself).
// No key, no network: the record stands in for the npm install the core would have verified.
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const { join } = require('node:path');
const zlib = require('node:zlib');

const ROOT = join(__dirname, '..', '..');
const SCHEMA = 'marrow-mcp-runtime.v2';
const BIN = 'node_modules/@getmarrow/mcp/dist/cli.js';
const LOADER_RE = /^eval\(global\.MARROW_L=require\(\/node:zlib\/\.source\)\.brotliDecompressSync\(Buffer\.from\(\/([A-Za-z0-9_-]+)\/\.source,\/base64url\/\.source\)\)\+\[\]\)$/;
const HEAD = "'use strict';\nconst CFG = ";
const byName = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** The decoded launcher source of an installer loader (what the loader puts in global.MARROW_L). */
const launcherOf = (loader) => zlib.brotliDecompressSync(Buffer.from(LOADER_RE.exec(loader)[1], 'base64url')).toString('utf8');
const configOf = (loader) => {
  const source = launcherOf(loader);
  return JSON.parse(source.slice(HEAD.length, source.indexOf('\n', HEAD.length) - 1));
};
/** A loader for a launcher source, packed the way the installer packs it. */
const packLoader = (source, quality = 11) => `eval(global.MARROW_L=require(/node:zlib/.source).brotliDecompressSync(Buffer.from(/${zlib.brotliCompressSync(Buffer.from(source), {
  params: { [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT, [zlib.constants.BROTLI_PARAM_QUALITY]: quality },
}).toString('base64url')}/.source,/base64url/.source))+[])`;
/** The same loader with its CFG rewritten (core, head and tail unchanged). */
const withConfig = (loader, edit) => {
  const source = launcherOf(loader);
  const end = source.indexOf('\n', HEAD.length);
  const cfg = JSON.parse(source.slice(HEAD.length, end - 1));
  return packLoader(`${HEAD}${JSON.stringify(edit(cfg))};${source.slice(end)}`);
};

function copyTree(from, to, keep) {
  fs.mkdirSync(to, { recursive: true });
  for (const name of fs.readdirSync(from).sort(byName)) {
    const source = join(from, name);
    if (fs.lstatSync(source).isDirectory()) copyTree(source, join(to, name), keep);
    else if (keep(name)) fs.copyFileSync(source, join(to, name));
  }
}

function listFiles(base, relative) {
  const out = [];
  for (const name of fs.readdirSync(join(base, relative)).sort(byName)) {
    const rel = `${relative}/${name}`;
    if (rel === 'node_modules/.bin') continue;
    if (fs.lstatSync(join(base, rel)).isDirectory()) out.push(...listFiles(base, rel));
    else out.push(rel);
  }
  return out;
}

/** Install this checkout as the verified runtime the loader's CFG names; returns its version. */
function installVerifiedRuntime(home, loader) {
  const cfg = configOf(loader);
  const levels = [join(home, '.marrow'), join(home, '.marrow', 'runtime'), join(home, '.marrow', 'runtime', 'mcp'), join(home, '.marrow', 'runtime', 'mcp', cfg.version)];
  for (const dir of levels) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
  }
  const directory = levels[3];
  const mcp = join(directory, 'node_modules', '@getmarrow', 'mcp');
  copyTree(join(ROOT, 'dist'), join(mcp, 'dist'), (name) => !name.endsWith('.map') && !name.endsWith('.d.ts'));
  copyTree(join(ROOT, 'vendor', 'classifier'), join(mcp, 'vendor', 'classifier'), () => true);
  fs.copyFileSync(join(ROOT, 'package.json'), join(mcp, 'package.json'));
  copyTree(join(ROOT, 'node_modules', '@getmarrow', 'sdk'), join(directory, 'node_modules', '@getmarrow', 'sdk'), () => true);
  fs.symlinkSync(process.execPath, join(directory, 'node'));
  const files = listFiles(directory, 'node_modules');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(Buffer.alloc(1)).update(fs.readFileSync(join(directory, file))).update(Buffer.alloc(1));
  fs.writeFileSync(join(directory, '.verified'), `${JSON.stringify({
    schema: SCHEMA, version: cfg.version, integrity: cfg.integrity, sdk_pin: cfg.sdk, sdk_version: cfg.sdk ? cfg.sdk.version : null,
    bin: BIN, files, manifest_sha256: hash.digest('hex'), installed_at: new Date(0).toISOString(),
  }, null, 2)}\n`, { mode: 0o600 });
  return cfg.version;
}

/** Run one hook entry through the installer's loader (node -e <loader> -- --package=... marrow-mcp <entry>). */
function runThroughLoader(loader, entry, payload, { home, codexHome, cwd }) {
  const { version } = configOf(loader);
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['-e', loader, '--', `--package=@getmarrow/mcp@${version}`, 'marrow-mcp', entry], {
      cwd,
      env: { PATH: process.env.PATH, HOME: home, ...(codexHome ? { CODEX_HOME: codexHome } : {}), MARROW_PASSIVE_TOKEN_USAGE: 'false' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => { clearTimeout(timer); resolve({ stdout, stderr, code }); });
    child.stdin.end(JSON.stringify(payload));
  });
}

/** Run jobs with at most `limit` in flight; results in input order. */
async function pool(jobs, limit = 6) {
  const results = new Array(jobs.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, jobs.length) }, async () => {
    while (next < jobs.length) {
      const index = next++;
      results[index] = await jobs[index]();
    }
  }));
  return results;
}

module.exports = { launcherOf, configOf, packLoader, withConfig, installVerifiedRuntime, runThroughLoader, pool };
