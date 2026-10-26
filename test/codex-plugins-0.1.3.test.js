// The Codex plugins marrow@0.1.3 and marrow-advisory@0.1.3 (getmarrow/plugins release/codex-0.1.3),
// pinned to @getmarrow/mcp 3.9.107. The pins for 0.1.3 sit beside the 0.1.1 pins (not instead of them);
// the unshipped 0.1.2 drafts have no entry. The host proof accepts a release with exactly its six
// pinned files and nothing else.
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

const NEW = join(__dirname, 'fixtures', 'codex-plugins-0.1.3');
const OLD = join(__dirname, 'fixtures', 'codex-plugins-b446393');
const DRAFT = join(__dirname, 'fixtures', 'codex-plugins-0.1.2-draft');
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
  const dir = mkdtempSync(join(tmpdir(), 'marrow-plugins-013-'));
  t.after(() => { spawnSync('chmod', ['-R', 'u+rwx', dir]); rmSync(dir, { recursive: true, force: true }); });
  const codexHome = join(dir, 'codex');
  const project = join(dir, 'project');
  mkdirSync(codexHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  const start = Date.now();
  const api = {
    dir, codexHome, project, start,
    install(plugin, { version = '0.1.3', from = join(NEW, 'codex', plugin) } = {}) {
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

test('0.1.3 pins: 0.1.3 is pinned beside 0.1.1, six files each, and the CI check recomputes them from the 0.1.3 plugins', () => {
  assert.deepEqual(Object.keys(OFFICIAL_CODEX_PLUGIN_PINS).sort(), ['marrow-advisory@0.1.1', 'marrow-advisory@0.1.3', 'marrow@0.1.1', 'marrow@0.1.3']);
  for (const [key, pins] of Object.entries(OFFICIAL_CODEX_PLUGIN_PINS)) assert.deepEqual(Object.keys(pins).sort(), SIX, key);
  for (const plugin of PLUGINS) {
    const oldPins = OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.1`];
    const newPins = OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.3`];
    // The launcher and .mcp.json are unchanged; the manifest, the MCP pin and the lockfile moved.
    assert.equal(newPins['scripts/marrow-launch.cjs'], oldPins['scripts/marrow-launch.cjs']);
    assert.equal(newPins['.mcp.json'], oldPins['.mcp.json']);
    for (const file of ['.codex-plugin/plugin.json', 'scripts/mcp-manifest.json', 'package.json', 'package-lock.json']) assert.notEqual(newPins[file], oldPins[file], `${plugin} ${file}`);
  }
  const run = spawnSync(process.execPath, [CHECK, NEW], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout);
  assert.equal((run.stdout.match(/^ok /gm) || []).length, 12);
  assert.match(run.stdout, /ok   marrow@0\.1\.3 scripts\/mcp-manifest\.json/);
  assert.match(run.stdout, /ok   marrow-advisory@0\.1\.3 package-lock\.json/);
});

test('0.1.3 pins: the 0.1.3 plugin files pin MCP 3.9.107 and SDK 3.7.67 with sha512 integrity, the same as the Claude Code plugin', () => {
  for (const plugin of PLUGINS) {
    const read = (file) => JSON.parse(readFileSync(join(NEW, 'codex', plugin, file), 'utf8'));
    const manifest = read('scripts/mcp-manifest.json');
    const pkg = read('package.json');
    const lock = read('package-lock.json');
    assert.equal(manifest.mcp.version, '3.9.107');
    assert.equal(manifest.sdk.version, '3.7.67');
    assert.match(manifest.mcp.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
    assert.equal(pkg.dependencies['@getmarrow/mcp'], '3.9.107');
    assert.equal(lock.packages['node_modules/@getmarrow/mcp'].version, '3.9.107');
    assert.equal(lock.packages['node_modules/@getmarrow/mcp'].integrity, manifest.mcp.integrity);
    assert.equal(lock.packages['node_modules/@getmarrow/sdk'].integrity, manifest.sdk.integrity);
    assert.equal(read('.codex-plugin/plugin.json').version, '0.1.3');
    assert.equal(read('.codex-plugin/plugin.json').metadata.pins['@getmarrow/mcp'], '3.9.107');
  }
});

test('0.1.3 accept: each 0.1.3 plugin alone, with its six files, is the official plugin (MCP 3.9.107 pins); 0.1.1 still is too', (t) => {
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

test('0.1.3 reject: one changed byte in any pinned file, in the middle or appended, is checked, not official', (t) => {
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
      writeFileSync(path, raw.subarray(0, raw.length - 1));
      h.age(c);
      assert.equal(h.decide().official, false, `${plugin} ${file} - last byte`);
      writeFileSync(path, raw);
      h.age(c);
      assert.equal(h.decide().official, true, `${plugin} ${file} restored`);
    }
  }
});

test('0.1.3 reject: an extra manifest, a second cached version, or a second marrow server beside the 0.1.3 plugin is checked', (t) => {
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
    assert.equal(twoVersions.decide().official, false, `${plugin}: 0.1.1 and 0.1.3 both cached`);

    const second = home(t);
    second.install(plugin);
    second.config(`${second.enable(`${plugin}@getmarrow`)}[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n`);
    assert.equal(second.decide().official, false, `${plugin} + README marrow server`);

    const both = home(t);
    both.install('marrow');
    both.install('marrow-advisory');
    both.config(both.enable('marrow@getmarrow', 'marrow-advisory@getmarrow'));
    assert.equal(both.decide().official, false, 'both 0.1.3 plugins enabled');
  }
});

test('0.1.3 reject: a symlink in place of a pinned file, a linked version folder that leaves the cache, or a link to different bytes', (t) => {
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

test('0.1.3 reject: the old version label with the new bytes, the new label with the old bytes, and a mislabelled cache folder', (t) => {
  for (const plugin of PLUGINS) {
    // New bytes, manifest says 0.1.1: the 0.1.1 pins do not match the new files.
    const oldLabel = home(t);
    const c = oldLabel.install(plugin, { version: '0.1.1' });
    const manifestPath = join(c, '.codex-plugin', 'plugin.json');
    writeFileSync(manifestPath, readFileSync(manifestPath, 'utf8').replace('"version": "0.1.3"', '"version": "0.1.1"'));
    oldLabel.age(c);
    oldLabel.config(oldLabel.enable(`${plugin}@getmarrow`));
    assert.equal(oldLabel.decide().official, false, `${plugin}: 0.1.1 label on 0.1.3 bytes`);

    // New bytes in a folder named 0.1.1 (manifest still says 0.1.3): the folder must carry its own version.
    const folder = home(t);
    folder.install(plugin, { version: '0.1.1' });
    folder.config(folder.enable(`${plugin}@getmarrow`));
    assert.equal(folder.decide().official, false, `${plugin}: 0.1.3 files under a 0.1.1 folder`);

    // Old bytes with the new label.
    const newLabel = home(t);
    const d = newLabel.install(plugin, { version: '0.1.3', from: join(OLD, 'codex', plugin) });
    const oldManifest = join(d, '.codex-plugin', 'plugin.json');
    writeFileSync(oldManifest, readFileSync(oldManifest, 'utf8').replace('"version": "0.1.1"', '"version": "0.1.3"'));
    newLabel.age(d);
    newLabel.config(newLabel.enable(`${plugin}@getmarrow`));
    assert.equal(newLabel.decide().official, false, `${plugin}: 0.1.1 bytes under the 0.1.3 label`);

    // A copy of the new files under another version is not official.
    const other = home(t);
    const e = other.install(plugin, { version: '0.1.9' });
    const otherManifest = join(e, '.codex-plugin', 'plugin.json');
    writeFileSync(otherManifest, readFileSync(otherManifest, 'utf8').replace('"version": "0.1.3"', '"version": "0.1.9"'));
    other.age(e);
    other.config(other.enable(`${plugin}@getmarrow`));
    assert.equal(other.decide().official, false, `${plugin}: new bytes under an unpinned version`);
  }
});

test('0.1.3 unpinned files stay unpinned: skills and hooks text changes do not turn a 0.1.3 plugin into a look-alike (documented behaviour, unchanged)', (t) => {
  const h = home(t);
  const c = h.install('marrow');
  writeFileSync(join(c, 'hooks', 'hooks.json'), `${readFileSync(join(c, 'hooks', 'hooks.json'), 'utf8')}\n`);
  h.age(c);
  h.config(h.enable('marrow@getmarrow'));
  assert.equal(h.decide().official, true);
});

test('0.1.3 end to end (built hook, keyless, isolated HOME): the 0.1.3 plugin skips all own tools; a changed launcher or the old label with new bytes holds', (t) => {
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
    writeFileSync(manifestPath, manifestBytes.toString('utf8').replace('"version": "0.1.3"', '"version": "0.1.1"'));
    h.age(cache);
    assert.match(run('marrow_commit'), /"permissionDecision":"deny"/, `${plugin}: old label on new bytes`);
    writeFileSync(manifestPath, manifestBytes);
    h.age(cache);
    assert.equal(run('marrow_commit'), '{}', `${plugin}: restored`);
  }
});

test('0.1.3 the pins file keeps no duplicate or malformed digest', () => {
  for (const [key, pins] of Object.entries(OFFICIAL_CODEX_PLUGIN_PINS)) {
    for (const [file, digest] of Object.entries(pins)) assert.match(digest, /^[0-9a-f]{64}$/, `${key} ${file}`);
  }
  assert.equal(crypto.createHash('sha256').update(readFileSync(join(NEW, 'codex', 'marrow', '.mcp.json'))).digest('hex'), OFFICIAL_CODEX_PLUGIN_PINS['marrow@0.1.3']['.mcp.json']);
});

function manifestPath(dir) { return join(dir, '.codex-plugin', 'plugin.json'); }
function relabel(dir, from, to) {
  const path = manifestPath(dir);
  const text = readFileSync(path, 'utf8');
  assert.ok(text.includes(`"version": "${from}"`), `manifest says ${from}`);
  writeFileSync(path, text.replace(`"version": "${from}"`, `"version": "${to}"`));
}
function digestOf(path) { return crypto.createHash('sha256').update(readFileSync(path)).digest('hex'); }

test('0.1.3 accept (i): the eda4fcea bytes of both plugins are the pinned digests and, alone, are the official plugin', (t) => {
  for (const plugin of PLUGINS) {
    const key = `${plugin}@0.1.3`;
    for (const file of SIX) assert.equal(digestOf(join(NEW, 'codex', plugin, file)), OFFICIAL_CODEX_PLUGIN_PINS[key][file], `${key} ${file}`);
    const h = home(t);
    h.install(plugin);
    h.config(h.enable(`${plugin}@getmarrow`));
    assert.deepEqual(h.decide(), { official: true, reason: 'official plugin' }, plugin);
  }
});

test('0.1.3 reject (ii): the unshipped 0.1.2 draft bytes have no entry, under 0.1.2, in a 0.1.3 folder, or with a 0.1.3 label', (t) => {
  for (const plugin of PLUGINS) {
    assert.equal(OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.2`], undefined, `${plugin}@0.1.2 has no entry`);
    const draft = join(DRAFT, 'codex', plugin);
    assert.equal(JSON.parse(readFileSync(manifestPath(draft), 'utf8')).version, '0.1.2');
    // Exactly as the draft was: folder 0.1.2, manifest 0.1.2.
    const own = home(t);
    own.install(plugin, { version: '0.1.2', from: draft });
    own.config(own.enable(`${plugin}@getmarrow`));
    assert.equal(own.decide().official, false, `${plugin}: 0.1.2 draft bytes under 0.1.2`);
    // The draft bytes in a folder named 0.1.3 (manifest still 0.1.2).
    const folder = home(t);
    folder.install(plugin, { version: '0.1.3', from: draft });
    folder.config(folder.enable(`${plugin}@getmarrow`));
    assert.equal(folder.decide().official, false, `${plugin}: 0.1.2 draft bytes in a 0.1.3 folder`);
    // The draft bytes relabelled 0.1.3 in a 0.1.3 folder: the 0.1.3 digests do not match the draft files.
    const label = home(t);
    const c = label.install(plugin, { version: '0.1.3', from: draft });
    relabel(c, '0.1.2', '0.1.3');
    label.age(c);
    label.config(label.enable(`${plugin}@getmarrow`));
    assert.equal(label.decide().official, false, `${plugin}: 0.1.2 draft bytes relabelled 0.1.3`);
    // One file at a time from the draft into the 0.1.3 set: a mix is not either release.
    for (const file of SIX) {
      if (digestOf(join(draft, file)) === digestOf(join(NEW, 'codex', plugin, file))) continue;
      const mix = home(t);
      const m = mix.install(plugin);
      writeFileSync(join(m, file), readFileSync(join(draft, file)));
      mix.age(m);
      mix.config(mix.enable(`${plugin}@getmarrow`));
      assert.equal(mix.decide().official, false, `${plugin}: draft ${file} inside the 0.1.3 set`);
    }
  }
});

test('0.1.3 reject (iii): the 0.1.3 bytes with a manifest that says 0.1.2, or in a cache folder named 0.1.2', (t) => {
  for (const plugin of PLUGINS) {
    const manifest = home(t);
    const a = manifest.install(plugin);
    relabel(a, '0.1.3', '0.1.2');
    manifest.age(a);
    manifest.config(manifest.enable(`${plugin}@getmarrow`));
    assert.equal(manifest.decide().official, false, `${plugin}: 0.1.3 bytes, manifest says 0.1.2`);

    const folder = home(t);
    folder.install(plugin, { version: '0.1.2' });
    folder.config(folder.enable(`${plugin}@getmarrow`));
    assert.equal(folder.decide().official, false, `${plugin}: 0.1.3 bytes in a folder named 0.1.2`);

    const both = home(t);
    const b = both.install(plugin, { version: '0.1.2' });
    relabel(b, '0.1.3', '0.1.2');
    both.age(b);
    both.config(both.enable(`${plugin}@getmarrow`));
    assert.equal(both.decide().official, false, `${plugin}: 0.1.3 bytes, folder and manifest say 0.1.2`);
  }
});

test('0.1.3 unchanged (v): the 0.1.1 plugins are official exactly as before, and one changed 0.1.1 byte is not', (t) => {
  for (const plugin of PLUGINS) {
    const h = home(t);
    h.install(plugin, { version: '0.1.1', from: join(OLD, 'codex', plugin) });
    h.config(h.enable(`${plugin}@getmarrow`));
    assert.deepEqual(h.decide(), { official: true, reason: 'official plugin' }, `${plugin}@0.1.1`);
    for (const file of SIX) {
      const changed = home(t);
      const c = changed.install(plugin, { version: '0.1.1', from: join(OLD, 'codex', plugin) });
      writeFileSync(join(c, file), Buffer.concat([readFileSync(join(c, file)), Buffer.from('\n')]));
      changed.age(c);
      changed.config(changed.enable(`${plugin}@getmarrow`));
      assert.equal(changed.decide().official, false, `${plugin}@0.1.1 ${file} + newline`);
    }
  }
  const run = spawnSync(process.execPath, [CHECK, OLD], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout);
  assert.equal((run.stdout.match(/^ok   (?:marrow|marrow-advisory)@0\.1\.1 /gm) || []).length, 12);
});

function addPlugin(h, id, servers, version = '1.0.0') {
  const [name, marketplace] = id.split('@');
  const dir = join(h.codexHome, 'plugins', 'cache', marketplace, name, version);
  mkdirSync(join(dir, '.codex-plugin'), { recursive: true });
  writeFileSync(manifestPath(dir), JSON.stringify({ name, version }));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
  h.age(dir);
}

test('0.1.3 unchanged (vi): a second plugin beside the official one is harmless unless it can produce the marrow label', (t) => {
  const sets = [['0.1.3', NEW], ['0.1.1', OLD]];
  for (const [version, root] of sets) {
    for (const plugin of PLUGINS) {
      const setup = (id, servers) => {
        const h = home(t);
        h.install(plugin, { version, from: join(root, 'codex', plugin) });
        addPlugin(h, id, servers);
        h.config(h.enable(`${plugin}@getmarrow`, id));
        return h;
      };
      assert.deepEqual(setup('docs@other', { docs: { command: 'docs-server' } }).decide(), { official: true, reason: 'official plugin' }, `${plugin}@${version} + an unrelated server`);
      for (const name of ['marrow', 'Marrow', 'MARROW', 'marrow-', 'mcp_marrow', 'mcp__', '_', 'marr\u200Bow']) {
        assert.equal(setup('look@other', { [name]: { command: 'node', args: ['evil.js'] } }).decide().official, false, `${plugin}@${version} + a second plugin with a server named ${JSON.stringify(name)}`);
      }
      // A second plugin that copies an official release file by file under another name is not the official plugin either.
      const copy = home(t);
      copy.install(plugin, { version, from: join(root, 'codex', plugin) });
      const other = join(copy.codexHome, 'plugins', 'cache', 'other', plugin, version);
      mkdirSync(other, { recursive: true });
      cpSync(join(root, 'codex', plugin), other, { recursive: true });
      copy.age(other);
      copy.config(copy.enable(`${plugin}@getmarrow`, `${plugin}@other`));
      assert.equal(copy.decide().official, false, `${plugin}@${version} + a second copy of the same release`);
    }
  }
});

test('0.1.3 pins collide nowhere: one key, one digest set, no shared six-file set, no entry for the draft bytes, no entry for the same bytes under another version', () => {
  const keys = Object.keys(OFFICIAL_CODEX_PLUGIN_PINS);
  assert.equal(new Set(keys).size, keys.length);
  const sets = keys.map((key) => SIX.map((file) => OFFICIAL_CODEX_PLUGIN_PINS[key][file]).join(' '));
  assert.equal(new Set(sets).size, sets.length, 'no two entries share a full six-file digest set');
  // Per file: the two plugins differ in plugin.json, package.json and package-lock.json of the same release.
  for (const version of ['0.1.1', '0.1.3']) {
    for (const file of ['.codex-plugin/plugin.json', 'package.json', 'package-lock.json']) {
      assert.notEqual(OFFICIAL_CODEX_PLUGIN_PINS[`marrow@${version}`][file], OFFICIAL_CODEX_PLUGIN_PINS[`marrow-advisory@${version}`][file], `${version} ${file}`);
    }
  }
  // Keys are `<name>@<version>` of the manifest, and each names the same version the manifest in its own fixture says.
  for (const key of keys) assert.match(key, /^(?:marrow|marrow-advisory)@0\.1\.[13]$/);
  // The draft bytes: no entry holds any draft six-file set, and no pinned release holds the draft manifest.
  for (const plugin of PLUGINS) {
    const draftSet = SIX.map((file) => digestOf(join(DRAFT, 'codex', plugin, file))).join(' ');
    assert.ok(!sets.includes(draftSet), `${plugin}: the draft six-file set is not pinned`);
    assert.ok(!Object.values(OFFICIAL_CODEX_PLUGIN_PINS).some((pins) => pins['.codex-plugin/plugin.json'] === digestOf(manifestPath(join(DRAFT, 'codex', plugin)))), `${plugin}: the draft manifest is not pinned`);
  }
});
