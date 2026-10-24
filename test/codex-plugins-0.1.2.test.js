// PKG-M4: the Codex plugins move to marrow@0.1.2 and marrow-advisory@0.1.2, pinned to @getmarrow/mcp
// 3.9.103. The pins for 0.1.2 are added beside the 0.1.1 pins (not instead of them), and the host
// proof accepts the new release with exactly its six pinned files and nothing else.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { cpSync, lutimesSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { codexOfficialMarrowServer } = require('../dist/own-server-identity.js');
const { OFFICIAL_CODEX_PLUGIN_PINS } = require('../dist/codex-plugin-pins.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');

const NEW = join(__dirname, 'fixtures', 'codex-plugins-0.1.2');
const OLD = join(__dirname, 'fixtures', 'codex-plugins-b446393');
const CHECK = join(__dirname, '..', 'scripts', 'codex-plugin-pins-check.cjs');
const HOUR = 3600_000;
const SIX = ['.codex-plugin/plugin.json', '.mcp.json', 'package-lock.json', 'package.json', 'scripts/marrow-launch.cjs', 'scripts/mcp-manifest.json'];
const PLUGINS = ['marrow', 'marrow-advisory'];

function walk(dir, fn) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    fn(path);
    if (statSync(path).isDirectory()) walk(path, fn);
  }
}

function home(t) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-plugins-012-'));
  t.after(() => { spawnSync('chmod', ['-R', 'u+rwx', dir]); rmSync(dir, { recursive: true, force: true }); });
  const codexHome = join(dir, 'codex');
  const project = join(dir, 'project');
  mkdirSync(codexHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  const start = Date.now();
  const api = {
    dir, codexHome, project, start,
    install(plugin, { version = '0.1.2', from = join(NEW, 'codex', plugin) } = {}) {
      const target = join(codexHome, 'plugins', 'cache', 'getmarrow', plugin, version);
      mkdirSync(target, { recursive: true });
      cpSync(from, target, { recursive: true });
      api.age(target);
      return target;
    },
    age(path, when = start - HOUR) {
      const at = new Date(when);
      utimesSync(path, at, at);
      if (statSync(path).isDirectory()) walk(path, (p) => utimesSync(p, at, at));
    },
    ageLink(path, when = start - HOUR) { const at = new Date(when); lutimesSync(path, at, at); },
    config(text) { writeFileSync(join(codexHome, 'config.toml'), text); },
    enable: (...ids) => ids.map((id) => `[plugins.${JSON.stringify(id)}]\nenabled = true\n`).join(''),
    decide(extra = {}) {
      return codexOfficialMarrowServer({ env: { CODEX_HOME: codexHome }, processArgs: null, processCwd: project, cwds: [project], processStartMs: start, ...extra });
    },
  };
  return api;
}

test('M4 pins: 0.1.2 is pinned beside 0.1.1, six files each, and the CI check recomputes them from the 0.1.2 plugins', () => {
  assert.deepEqual(Object.keys(OFFICIAL_CODEX_PLUGIN_PINS).sort(), ['marrow-advisory@0.1.1', 'marrow-advisory@0.1.2', 'marrow@0.1.1', 'marrow@0.1.2']);
  for (const [key, pins] of Object.entries(OFFICIAL_CODEX_PLUGIN_PINS)) assert.deepEqual(Object.keys(pins).sort(), SIX, key);
  for (const plugin of PLUGINS) {
    const oldPins = OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.1`];
    const newPins = OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.2`];
    // The launcher and .mcp.json are unchanged; the manifest, the MCP pin and the lockfile moved.
    assert.equal(newPins['scripts/marrow-launch.cjs'], oldPins['scripts/marrow-launch.cjs']);
    assert.equal(newPins['.mcp.json'], oldPins['.mcp.json']);
    for (const file of ['.codex-plugin/plugin.json', 'scripts/mcp-manifest.json', 'package.json', 'package-lock.json']) assert.notEqual(newPins[file], oldPins[file], `${plugin} ${file}`);
  }
  const run = spawnSync(process.execPath, [CHECK, NEW], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout);
  assert.equal((run.stdout.match(/^ok /gm) || []).length, 12);
  assert.match(run.stdout, /ok   marrow@0\.1\.2 scripts\/mcp-manifest\.json/);
  assert.match(run.stdout, /ok   marrow-advisory@0\.1\.2 package-lock\.json/);
});

test('M4 pins: the 0.1.2 plugin files pin MCP 3.9.103 and SDK 3.7.65 with sha512 integrity, the same as the Claude Code plugin', () => {
  for (const plugin of PLUGINS) {
    const read = (file) => JSON.parse(readFileSync(join(NEW, 'codex', plugin, file), 'utf8'));
    const manifest = read('scripts/mcp-manifest.json');
    const pkg = read('package.json');
    const lock = read('package-lock.json');
    assert.equal(manifest.mcp.version, '3.9.103');
    assert.equal(manifest.sdk.version, '3.7.65');
    assert.match(manifest.mcp.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
    assert.equal(pkg.dependencies['@getmarrow/mcp'], '3.9.103');
    assert.equal(lock.packages['node_modules/@getmarrow/mcp'].version, '3.9.103');
    assert.equal(lock.packages['node_modules/@getmarrow/mcp'].integrity, manifest.mcp.integrity);
    assert.equal(lock.packages['node_modules/@getmarrow/sdk'].integrity, manifest.sdk.integrity);
    assert.equal(read('.codex-plugin/plugin.json').version, '0.1.2');
    assert.equal(read('.codex-plugin/plugin.json').metadata.pins['@getmarrow/mcp'], '3.9.103');
  }
});

test('M4 accept: each 0.1.2 plugin alone, with its six files, is the official plugin (MCP 3.9.103 pins); 0.1.1 still is too', (t) => {
  for (const plugin of PLUGINS) {
    const h = home(t);
    h.install(plugin);
    h.config(h.enable(`${plugin}@getmarrow`));
    assert.deepEqual(h.decide(), { official: true, reason: 'official plugin' }, plugin);
    const older = home(t);
    older.install(plugin, { version: '0.1.1', from: join(OLD, 'codex', plugin) });
    older.config(older.enable(`${plugin}@getmarrow`));
    assert.equal(older.decide().official, true, `${plugin}@0.1.1 is not turned into new friction`);
  }
});

test('M4 reject: one changed byte in any pinned file, in the middle or appended, is checked, not official', (t) => {
  for (const plugin of PLUGINS) {
    for (const file of SIX) {
      const h = home(t);
      const c = h.install(plugin);
      const path = join(c, file);
      const raw = readFileSync(path);
      const middle = Buffer.from(raw);
      const at = Math.floor(middle.length / 2);
      middle[at] = middle[at] === 0x20 ? 0x09 : 0x20;
      writeFileSync(path, middle);
      h.age(c);
      h.config(h.enable(`${plugin}@getmarrow`));
      assert.equal(h.decide().official, false, `${plugin} ${file}`);
      writeFileSync(path, Buffer.concat([raw, Buffer.from([0xff])]));
      h.age(c);
      assert.equal(h.decide().official, false, `${plugin} ${file} + invalid byte`);
      writeFileSync(path, raw);
      h.age(c);
      assert.equal(h.decide().official, true, `${plugin} ${file} restored`);
    }
  }
});

test('M4 reject: an extra manifest, a second cached version, or a second marrow server beside the 0.1.2 plugin is checked', (t) => {
  for (const plugin of PLUGINS) {
    const extraManifest = home(t);
    const c = extraManifest.install(plugin);
    mkdirSync(join(c, '.claude-plugin'));
    writeFileSync(join(c, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'marrow' }));
    extraManifest.age(c);
    extraManifest.config(extraManifest.enable(`${plugin}@getmarrow`));
    assert.equal(extraManifest.decide().official, false, `${plugin} + .claude-plugin manifest`);

    const twoVersions = home(t);
    twoVersions.install(plugin);
    twoVersions.install(plugin, { version: '0.1.1', from: join(OLD, 'codex', plugin) });
    twoVersions.config(twoVersions.enable(`${plugin}@getmarrow`));
    assert.equal(twoVersions.decide().official, false, `${plugin}: 0.1.1 and 0.1.2 both cached`);

    const second = home(t);
    second.install(plugin);
    second.config(`${second.enable(`${plugin}@getmarrow`)}[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n`);
    assert.equal(second.decide().official, false, `${plugin} + README marrow server`);

    const both = home(t);
    both.install('marrow');
    both.install('marrow-advisory');
    both.config(both.enable('marrow@getmarrow', 'marrow-advisory@getmarrow'));
    assert.equal(both.decide().official, false, 'both 0.1.2 plugins enabled');
  }
});

test('M4 reject: a symlink in place of a pinned file, a linked version folder that leaves the cache, or a link to different bytes', (t) => {
  for (const plugin of PLUGINS) {
    for (const file of SIX) {
      // A link to a copy outside the cache, dated like the rest, so only the real-path rule can catch it.
      const outside = home(t);
      const c = outside.install(plugin);
      const copy = join(outside.dir, 'outside-file');
      cpSync(join(c, file), copy);
      outside.age(copy);
      rmSync(join(c, file));
      symlinkSync(copy, join(c, file));
      outside.ageLink(join(c, file));
      outside.age(c);
      outside.config(outside.enable(`${plugin}@getmarrow`));
      assert.equal(outside.decide().official, false, `${plugin} ${file}: link to a file outside the cache`);

      // A link to /dev/zero is not a regular file.
      const zero = home(t);
      const z = zero.install(plugin);
      rmSync(join(z, file));
      symlinkSync('/dev/zero', join(z, file));
      zero.config(zero.enable(`${plugin}@getmarrow`));
      assert.equal(zero.decide().official, false, `${plugin} ${file}: link to /dev/zero`);
    }
    const folder = home(t);
    const real = folder.install(plugin);
    const out = join(folder.dir, 'outside');
    cpSync(real, out, { recursive: true });
    folder.age(out);
    rmSync(real, { recursive: true });
    symlinkSync(out, real);
    folder.ageLink(real);
    folder.config(folder.enable(`${plugin}@getmarrow`));
    assert.equal(folder.decide().official, false, `${plugin}: version folder linked outside the cache`);
  }
});

test('M4 reject: the old version label with the new bytes, the new label with the old bytes, and a mislabelled cache folder', (t) => {
  for (const plugin of PLUGINS) {
    // New bytes, manifest says 0.1.1: the 0.1.1 pins do not match the new files.
    const oldLabel = home(t);
    const c = oldLabel.install(plugin, { version: '0.1.1' });
    const manifestPath = join(c, '.codex-plugin', 'plugin.json');
    writeFileSync(manifestPath, readFileSync(manifestPath, 'utf8').replace('"version": "0.1.2"', '"version": "0.1.1"'));
    oldLabel.age(c);
    oldLabel.config(oldLabel.enable(`${plugin}@getmarrow`));
    assert.equal(oldLabel.decide().official, false, `${plugin}: 0.1.1 label on 0.1.2 bytes`);

    // New bytes in a folder named 0.1.1 (manifest still says 0.1.2): the folder must carry its own version.
    const folder = home(t);
    folder.install(plugin, { version: '0.1.1' });
    folder.config(folder.enable(`${plugin}@getmarrow`));
    assert.equal(folder.decide().official, false, `${plugin}: 0.1.2 files under a 0.1.1 folder`);

    // Old bytes with the new label.
    const newLabel = home(t);
    const d = newLabel.install(plugin, { version: '0.1.2', from: join(OLD, 'codex', plugin) });
    const oldManifest = join(d, '.codex-plugin', 'plugin.json');
    writeFileSync(oldManifest, readFileSync(oldManifest, 'utf8').replace('"version": "0.1.1"', '"version": "0.1.2"'));
    newLabel.age(d);
    newLabel.config(newLabel.enable(`${plugin}@getmarrow`));
    assert.equal(newLabel.decide().official, false, `${plugin}: 0.1.1 bytes under the 0.1.2 label`);

    // A copy of the new files under another version is not official.
    const other = home(t);
    const e = other.install(plugin, { version: '0.1.9' });
    const otherManifest = join(e, '.codex-plugin', 'plugin.json');
    writeFileSync(otherManifest, readFileSync(otherManifest, 'utf8').replace('"version": "0.1.2"', '"version": "0.1.9"'));
    other.age(e);
    other.config(other.enable(`${plugin}@getmarrow`));
    assert.equal(other.decide().official, false, `${plugin}: new bytes under an unpinned version`);
  }
});

test('M4 unpinned files stay unpinned: skills and hooks text changes do not turn a 0.1.2 plugin into a look-alike (documented behaviour, unchanged)', (t) => {
  const h = home(t);
  const c = h.install('marrow');
  writeFileSync(join(c, 'hooks', 'hooks.json'), `${readFileSync(join(c, 'hooks', 'hooks.json'), 'utf8')}\n`);
  h.age(c);
  h.config(h.enable('marrow@getmarrow'));
  assert.equal(h.decide().official, true);
});

test('M4 end to end (built hook, keyless, isolated HOME): the 0.1.2 plugin skips all own tools; a changed launcher or the old label with new bytes holds', (t) => {
  const CLI = join(__dirname, '..', 'dist', 'cli.js');
  for (const plugin of PLUGINS) {
    const h = home(t);
    const userHome = join(h.dir, 'home');
    mkdirSync(userHome);
    const cache = h.install(plugin);
    h.config(h.enable(`${plugin}@getmarrow`));
    const table = join(h.dir, 'proc-table.cjs');
    writeFileSync(table, `globalThis[Symbol.for('marrow.test.processTable')] = { [String(process.ppid)]: { pid: process.ppid, ppid: 1, args: ['codex', 'exec'], terminal: false, startMs: ${h.start} } };\n`);
    const run = (tool) => spawnSync(process.execPath, ['--require', table, CLI, 'codex-pre-action-hook'], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: h.project, tool_name: `mcp__marrow__${tool}`, tool_input: {} }),
      cwd: h.project,
      env: { PATH: process.env.PATH, HOME: userHome, CODEX_HOME: h.codexHome, TMPDIR: h.dir },
      encoding: 'utf8',
    }).stdout.trim();
    for (const tool of MARROW_OWN_TOOL_NAMES) assert.equal(run(tool), '{}', `${plugin} ${tool}`);
    const launcher = join(cache, 'scripts', 'marrow-launch.cjs');
    const original = readFileSync(launcher);
    writeFileSync(launcher, Buffer.concat([original, Buffer.from('\n')]));
    h.age(cache);
    assert.match(run('marrow_commit'), /"permissionDecision":"deny"/, `${plugin}: launcher changed`);
    writeFileSync(launcher, original);
    const manifestPath = join(cache, '.codex-plugin', 'plugin.json');
    const manifestBytes = readFileSync(manifestPath);
    writeFileSync(manifestPath, manifestBytes.toString('utf8').replace('"version": "0.1.2"', '"version": "0.1.1"'));
    h.age(cache);
    assert.match(run('marrow_commit'), /"permissionDecision":"deny"/, `${plugin}: old label on new bytes`);
    writeFileSync(manifestPath, manifestBytes);
    h.age(cache);
    assert.equal(run('marrow_commit'), '{}', `${plugin}: restored`);
  }
});

test('M4 the pins file keeps no duplicate or malformed digest', () => {
  for (const [key, pins] of Object.entries(OFFICIAL_CODEX_PLUGIN_PINS)) {
    for (const [file, digest] of Object.entries(pins)) assert.match(digest, /^[0-9a-f]{64}$/, `${key} ${file}`);
  }
  assert.equal(crypto.createHash('sha256').update(readFileSync(join(NEW, 'codex', 'marrow', '.mcp.json'))).digest('hex'), OFFICIAL_CODEX_PLUGIN_PINS['marrow@0.1.2']['.mcp.json']);
});
