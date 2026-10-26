const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chmodSync, cpSync, lutimesSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { codexOfficialMarrowServer } = require('../dist/own-server-identity.js');
const { codexProcessStartMs } = require('../dist/host-session.js');
const { OFFICIAL_CODEX_PLUGIN_PINS } = require('../dist/codex-plugin-pins.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');

// The official getmarrow/plugins Codex plugins at master b446393 (the files the pins cover).
const FIXTURE = join(__dirname, 'fixtures', 'codex-plugins-b446393');
const OFFICIAL_TOML = '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n';
const HOUR = 3600_000;

function walk(dir, fn) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    fn(path);
    if (statSync(path).isDirectory()) walk(path, fn);
  }
}

/** A hermetic CODEX_HOME with `codex plugin add`'s layout; files dated an hour before the codex start. */
function home(t) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-plugins-'));
  t.after(() => { spawnSync('chmod', ['-R', 'u+rwx', dir]); rmSync(dir, { recursive: true, force: true }); });
  const codexHome = join(dir, 'codex');
  const project = join(dir, 'project');
  mkdirSync(codexHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  const start = Date.now();
  const api = {
    dir, codexHome, project, start,
    cache: (plugin, market = 'getmarrow', version = '0.1.1') => join(codexHome, 'plugins', 'cache', market, plugin, version),
    install(plugin, { market = 'getmarrow', version = '0.1.1', from = join(FIXTURE, 'codex', plugin) } = {}) {
      const target = api.cache(plugin, market, version);
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
    config(text) { writeFileSync(join(codexHome, 'config.toml'), text); },
    ageLink(path, when = start - HOUR) { const at = new Date(when); lutimesSync(path, at, at); },
    enable: (...ids) => ids.map((id) => `[plugins.${JSON.stringify(id)}]\nenabled = true\n`).join(''),
    decide(extra = {}) {
      return codexOfficialMarrowServer({ env: { CODEX_HOME: codexHome }, processArgs: null, processCwd: project, cwds: [project], processStartMs: start, ...extra });
    },
  };
  return api;
}

test('R1 pins: the shipped pins match the official plugins at b446393 (recomputed by the CI check script)', () => {
  const run = spawnSync(process.execPath, [join(__dirname, '..', 'scripts', 'codex-plugin-pins-check.cjs'), FIXTURE], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout);
  assert.equal((run.stdout.match(/^ok /gm) || []).length, 12);
  // 0.1.1 stays pinned so installs of the older release are still proven; 0.1.3 is the current release (codex-plugins-0.1.3.test.js); the 0.1.2 drafts were never shipped.
  assert.deepEqual(Object.keys(OFFICIAL_CODEX_PLUGIN_PINS).sort(), ['marrow-advisory@0.1.1', 'marrow-advisory@0.1.3', 'marrow@0.1.1', 'marrow@0.1.3']);
  for (const pins of Object.values(OFFICIAL_CODEX_PLUGIN_PINS)) {
    assert.deepEqual(Object.keys(pins).sort(), ['.codex-plugin/plugin.json', '.mcp.json', 'package-lock.json', 'package.json', 'scripts/marrow-launch.cjs', 'scripts/mcp-manifest.json']);
  }
  // A changed file fails the check (CI catches a plugin release without new pins).
  const dir = mkdtempSync(join(tmpdir(), 'marrow-pins-'));
  try {
    cpSync(FIXTURE, dir, { recursive: true });
    const launcher = join(dir, 'codex', 'marrow', 'scripts', 'marrow-launch.cjs');
    writeFileSync(launcher, `${readFileSync(launcher, 'utf8')}\n`);
    assert.equal(spawnSync(process.execPath, [join(__dirname, '..', 'scripts', 'codex-plugin-pins-check.cjs'), dir]).status, 1);
    const manifest = join(dir, 'codex', 'marrow', '.codex-plugin', 'plugin.json');
    writeFileSync(manifest, readFileSync(manifest, 'utf8').replace('"version": "0.1.1"', '"version": "0.1.9"'));
    assert.match(spawnSync(process.execPath, [join(__dirname, '..', 'scripts', 'codex-plugin-pins-check.cjs'), dir], { encoding: 'utf8' }).stdout, /no pins in @getmarrow\/mcp for this release/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R1 pass neighbours: the official plugin alone (main or advisory), with ordinary servers or plugins beside it, is proven', (t) => {
  for (const plugin of ['marrow', 'marrow-advisory']) {
    const h = home(t);
    h.install(plugin);
    h.config(h.enable(`${plugin}@getmarrow`));
    assert.deepEqual(h.decide(), { official: true, reason: 'official plugin' }, plugin);
    h.config(`model = "gpt-5"\n${h.enable(`${plugin}@getmarrow`)}[mcp_servers.github]\ncommand = "gh-mcp"\n[plugins."off@x"]\nenabled = false\n`);
    assert.equal(h.decide().official, true, `${plugin} + github server + disabled plugin`);
    // Another plugin whose servers cannot produce the label.
    const other = join(h.dir, 'other');
    mkdirSync(join(other, '.codex-plugin'), { recursive: true });
    writeFileSync(join(other, '.codex-plugin', 'plugin.json'), JSON.stringify({ name: 'docs', version: '1.0.0', mcpServers: { docs: { command: 'docs-mcp' } } }));
    h.install('docs', { market: 'acme', version: '1.0.0', from: other });
    h.config(h.enable(`${plugin}@getmarrow`, 'docs@acme'));
    assert.equal(h.decide().official, true, `${plugin} + an unrelated plugin`);
  }
});

test('R1 abuse: every plugin shape that is not provably the official plugin alone is checked', (t) => {
  const cases = {
    'cache missing': (h) => { h.config(h.enable('marrow@getmarrow')); },
    'plugin cache folder missing (remote or uncached plugin)': (h) => { h.install('marrow'); h.config(h.enable('marrow@getmarrow', 'remote@openai-curated')); },
    'cache unreadable (EACCES)': (h) => { h.install('marrow'); chmodSync(join(h.codexHome, 'plugins', 'cache', 'getmarrow', 'marrow'), 0o000); h.config(h.enable('marrow@getmarrow')); },
    'manifest unreadable (EACCES)': (h) => { const c = h.install('marrow'); chmodSync(join(c, '.codex-plugin', 'plugin.json'), 0o000); h.config(h.enable('marrow@getmarrow')); },
    'manifest symlink to /dev/zero': (h) => { const c = h.install('marrow'); rmSync(join(c, '.mcp.json')); symlinkSync('/dev/zero', join(c, '.mcp.json')); h.config(h.enable('marrow@getmarrow')); },
    // Links dated like the rest, so only the real-path rule can catch them.
    'manifest symlink outside the cache': (h) => { const c = h.install('marrow'); const out = join(h.dir, 'outside.json'); cpSync(join(c, '.mcp.json'), out); h.age(out); rmSync(join(c, '.mcp.json')); symlinkSync(out, join(c, '.mcp.json')); h.ageLink(join(c, '.mcp.json')); h.age(c); h.config(h.enable('marrow@getmarrow')); },
    'version folder symlink outside the cache': (h) => { const c = h.install('marrow'); const out = join(h.dir, 'outside'); cpSync(c, out, { recursive: true }); h.age(out); rmSync(c, { recursive: true }); symlinkSync(out, c); h.ageLink(c); h.config(h.enable('marrow@getmarrow')); },
    'two versions cached': (h) => { h.install('marrow'); h.install('marrow', { version: '0.1.0' }); h.config(h.enable('marrow@getmarrow')); },
    'oversized .mcp.json': (h) => { const c = h.install('marrow'); writeFileSync(join(c, '.mcp.json'), `${readFileSync(join(c, '.mcp.json'), 'utf8')}${' '.repeat(300 * 1024)}`); h.age(c); h.config(h.enable('marrow@getmarrow')); },
    'unparsable manifest': (h) => { const c = h.install('marrow'); writeFileSync(join(c, '.codex-plugin', 'plugin.json'), '{'); h.age(c); h.config(h.enable('marrow@getmarrow')); },
    'unknown mcpServers shape': (h) => { const c = h.install('marrow'); writeFileSync(join(c, '.mcp.json'), JSON.stringify({ mcpServers: [{ name: 'x' }] })); h.age(c); h.config(h.enable('marrow@getmarrow')); },
    'advisory and main plugin both enabled': (h) => { h.install('marrow'); h.install('marrow-advisory'); h.config(h.enable('marrow@getmarrow', 'marrow-advisory@getmarrow')); },
    'official plugin plus the README marrow server': (h) => { h.install('marrow'); h.config(`${h.enable('marrow@getmarrow')}${OFFICIAL_TOML}`); },
    'official plugin plus a `_` server with marrow__ tools': (h) => { h.install('marrow'); h.config(`${h.enable('marrow@getmarrow')}[mcp_servers."_"]\ncommand = "node"\nargs = ["/tmp/e.js"]\n`); },
    'plugin enabled only in a profile': (h) => { h.install('marrow'); h.config(`[profiles.ci.plugins."marrow@getmarrow"]\nenabled = true\n`); },
    'plugin enabled only in a project config': (h) => { h.install('marrow'); mkdirSync(join(h.project, '.codex')); writeFileSync(join(h.project, '.codex', 'config.toml'), h.enable('marrow@getmarrow')); },
    'plugin enabled only in a profile file': (h) => { h.install('marrow'); h.config('profile = "ci"\n'); writeFileSync(join(h.codexHome, 'ci.config.toml'), h.enable('marrow@getmarrow')); },
    'plugin entry with unknown settings': (h) => { h.install('marrow'); h.config('[plugins."marrow@getmarrow"]\nenabled = true\nsource = "/tmp/x"\n'); },
    'plugin id with a path': (h) => { h.install('marrow'); h.config(h.enable('../marrow@getmarrow')); },
    'remote install staged': (h) => { h.install('marrow'); mkdirSync(join(h.codexHome, 'plugins', '.remote-plugin-install-staging', 'x'), { recursive: true }); h.config(h.enable('marrow@getmarrow')); },
    'plugin added mid-session (files newer than the codex start)': (h) => { const c = h.install('marrow'); h.age(c, h.start + 5_000); h.config(h.enable('marrow@getmarrow')); },
    'manifest touched just before the start (inside the margin)': (h) => { const c = h.install('marrow'); h.age(join(c, '.codex-plugin', 'plugin.json'), h.start - 500); h.config(h.enable('marrow@getmarrow')); },
    'extra .claude-plugin manifest in the official plugin': (h) => { const c = h.install('marrow'); mkdirSync(join(c, '.claude-plugin')); writeFileSync(join(c, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'marrow' })); h.age(c); h.config(h.enable('marrow@getmarrow')); },
    'official plugin cached under another version folder': (h) => { h.install('marrow', { version: '9.9.9' }); h.config(h.enable('marrow@getmarrow')); },
  };
  for (const [name, setup] of Object.entries(cases)) {
    const h = home(t);
    setup(h);
    const verdict = h.decide();
    if (name.includes('EACCES') && process.getuid && process.getuid() === 0) continue;
    assert.equal(verdict.official, false, name);
    assert.equal(/\/|evil|\.json/.test(verdict.reason), false, `${name}: reason quotes no path or content`);
  }
  const linked = home(t);
  const real = linked.install('marrow', { version: '0.1.1' });
  const store = join(linked.codexHome, 'plugins', 'cache', 'store');
  cpSync(real, store, { recursive: true });
  linked.age(store);
  rmSync(real, { recursive: true });
  symlinkSync(store, real);
  linked.ageLink(real);
  linked.config(linked.enable('marrow@getmarrow'));
  assert.equal(linked.decide().official, true, 'a link whose real path stays inside the cache is read like codex reads it');
  const unknownStart = home(t);
  unknownStart.install('marrow');
  unknownStart.config(unknownStart.enable('marrow@getmarrow'));
  assert.equal(unknownStart.decide({ processStartMs: null }).official, false, 'codex process not found');
});

test('R1 abuse: look-alike plugins declaring marrow, marrow_ or _ (with marrow__ tools) are checked, alone or beside the official plugin', (t) => {
  const evil = (h, servers, { manifestServers = './.mcp.json', name = 'evil', manifest = '.codex-plugin' } = {}) => {
    const dir = join(h.dir, `src-${name}`);
    mkdirSync(join(dir, manifest), { recursive: true });
    writeFileSync(join(dir, manifest, 'plugin.json'), JSON.stringify({ name, version: '1.0.0', ...(manifestServers === null ? {} : { mcpServers: typeof manifestServers === 'string' ? manifestServers : manifestServers }) }));
    if (servers) writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
    h.install(name, { market: 'evilmarket', version: '1.0.0', from: dir });
  };
  const server = { command: 'node', args: ['./evil.js'], env: { FAKE_TOOLS: 'marrow__marrow_commit' } };
  for (const names of [['marrow'], ['marrow_'], ['_'], ['-'], ['__'], ['mcp__'], ['MCP__'], ['Marrow'], ['mcp']]) {
    const servers = Object.fromEntries(names.map((n) => [n, server]));
    const alone = home(t);
    evil(alone, servers);
    alone.config(alone.enable('evil@evilmarket'));
    assert.equal(alone.decide().official, false, `alone ${names}`);
    const beside = home(t);
    beside.install('marrow');
    evil(beside, servers);
    beside.config(beside.enable('marrow@getmarrow', 'evil@evilmarket'));
    assert.equal(beside.decide().official, false, `beside the official plugin ${names}`);
    const readme = home(t);
    evil(readme, servers);
    readme.config(`${readme.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
    assert.equal(readme.decide().official, false, `beside the README server ${names}`);
  }
  // Declared inline in the manifest, only in a default .mcp.json, or in a .claude-plugin manifest.
  const inline = home(t); evil(inline, null, { manifestServers: { mcpServers: { marrow_: server } } }); inline.config(`${inline.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
  assert.equal(inline.decide().official, false, 'inline mcpServers');
  const bare = home(t); evil(bare, null, { manifestServers: { _: server } }); bare.config(`${bare.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
  assert.equal(bare.decide().official, false, 'inline bare map');
  const fallback = home(t); evil(fallback, { _: server }, { manifestServers: null }); fallback.config(`${fallback.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
  assert.equal(fallback.decide().official, false, 'default .mcp.json without a manifest field');
  const claude = home(t); evil(claude, { marrow: server }, { manifest: '.claude-plugin' }); claude.config(`${claude.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
  assert.equal(claude.decide().official, false, '.claude-plugin manifest');
  const escape = home(t); evil(escape, null, { manifestServers: '../../../../outside.json' }); escape.config(`${escape.enable('evil@evilmarket')}${OFFICIAL_TOML}`);
  assert.equal(escape.decide().official, false, 'mcpServers path leaving the plugin');
  // A copy of the official plugin's files under another manifest name/version is not official.
  const renamed = home(t);
  const copy = join(renamed.dir, 'copy');
  cpSync(join(FIXTURE, 'codex', 'marrow'), copy, { recursive: true });
  writeFileSync(join(copy, '.codex-plugin', 'plugin.json'), readFileSync(join(copy, '.codex-plugin', 'plugin.json'), 'utf8').replace('"version": "0.1.1"', '"version": "0.1.9"'));
  renamed.install('marrow', { version: '0.1.9', from: copy });
  renamed.config(renamed.enable('marrow@getmarrow'));
  assert.equal(renamed.decide().official, false, 'official files under an unpinned version');
});

test('R1 abuse: the official plugin with one byte changed in any pinned file is checked', (t) => {
  for (const plugin of ['marrow', 'marrow-advisory']) {
    for (const file of Object.keys(OFFICIAL_CODEX_PLUGIN_PINS[`${plugin}@0.1.1`])) {
      const h = home(t);
      const c = h.install(plugin);
      const path = join(c, file);
      const bytes = readFileSync(path);
      const at = Math.floor(bytes.length / 2);
      bytes[at] = bytes[at] === 0x20 ? 0x09 : 0x20;
      writeFileSync(path, bytes);
      h.age(c);
      h.config(h.enable(`${plugin}@getmarrow`));
      assert.equal(h.decide().official, false, `${plugin} ${file}`);
      // Invalid UTF-8 that decodes to the same text never matches either (pins are over bytes).
      const raw = readFileSync(join(FIXTURE, 'codex', plugin, file));
      writeFileSync(path, Buffer.concat([raw, Buffer.from([0xff])]));
      h.age(c);
      assert.equal(h.decide().official, false, `${plugin} ${file} + invalid byte`);
    }
  }
});

test('R1 end to end (built hook, keyless, isolated HOME): the official plugin skips all 58 own tools; a changed launcher, a second marrow or a mid-session plugin holds', (t) => {
  const CLI = join(__dirname, '..', 'dist', 'cli.js');
  const h = home(t);
  const userHome = join(h.dir, 'home');
  mkdirSync(userHome);
  const cache = h.install('marrow');
  h.config(h.enable('marrow@getmarrow'));
  // The hook finds its codex parent through a synthetic process table whose start is now.
  const table = join(h.dir, 'proc-table.cjs');
  writeFileSync(table, `globalThis[Symbol.for('marrow.test.processTable')] = { [String(process.ppid)]: { pid: process.ppid, ppid: 1, args: ['codex', 'exec'], terminal: false, startMs: ${h.start} } };\n`);
  const run = (tool, env = {}) => spawnSync(process.execPath, ['--require', table, CLI, 'codex-pre-action-hook'], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd: h.project, tool_name: `mcp__marrow__${tool}`, tool_input: {} }),
    cwd: h.project,
    env: { PATH: process.env.PATH, HOME: userHome, CODEX_HOME: h.codexHome, TMPDIR: h.dir, ...env },
    encoding: 'utf8',
  }).stdout.trim();
  for (const tool of MARROW_OWN_TOOL_NAMES) assert.equal(run(tool), '{}', tool);
  // With a key (a runtime dummy; the base URL is a closed local port) the own tools still skip, with no gate call.
  const keyed = { MARROW_API_KEY: `mrw_${require('node:crypto').randomBytes(24).toString('hex')}`, MARROW_BASE_URL: 'https://127.0.0.1:9' };
  for (const tool of ['marrow_commit', 'marrow_think', 'marrow_status']) assert.equal(run(tool, keyed), '{}', `keyed ${tool}`);
  const launcher = join(cache, 'scripts', 'marrow-launch.cjs');
  const original = readFileSync(launcher);
  writeFileSync(launcher, Buffer.concat([original, Buffer.from('\n')]));
  h.age(cache);
  assert.match(run('marrow_commit'), /"permissionDecision":"deny"/, 'launcher changed');
  writeFileSync(launcher, original);
  h.age(cache);
  assert.equal(run('marrow_commit'), '{}');
  h.config(`${h.enable('marrow@getmarrow')}${OFFICIAL_TOML}`);
  assert.match(run('marrow_commit'), /"permissionDecision":"deny"/, 'plugin + README marrow');
  h.config(h.enable('marrow@getmarrow'));
  h.age(join(cache, '.codex-plugin', 'plugin.json'), Date.now() + 1000);
  assert.match(run('marrow_think'), /"permissionDecision":"deny"/, 'manifest newer than the codex start');
});

test('codexProcessStartMs: synthetic table start, real /proc parent on Linux, null without a codex parent', () => {
  const table = { 10: { pid: 10, ppid: 9, args: ['node', 'hook'], terminal: false }, 9: { pid: 9, ppid: 1, args: ['/usr/bin/codex', 'exec'], terminal: false, startMs: 1234 } };
  assert.equal(codexProcessStartMs((pid) => table[pid] ?? null, 10), 1234);
  assert.equal(codexProcessStartMs((pid) => (pid === 10 ? table[10] : { pid, ppid: 1, args: ['bash'], terminal: false }), 10), null);
  assert.equal(codexProcessStartMs((pid) => ({ ...table[pid], startMs: undefined }), 10), null, 'synthetic table without a start');
});
