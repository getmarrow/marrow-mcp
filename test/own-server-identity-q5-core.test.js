// Q5: the installer's runtime core changed (its stage sits under the real path of ~/.marrow/runtime/mcp, so a
// HOME behind a symlinked parent installs). INSTALLER_RUNTIME_CORE_SHA256 carries both cores: the old one
// (installers 0.1.70-0.1.74, still on every written hook) and the new one. Each core proves only a launch that
// is exactly the loader that started the hook; a third core, or any change to either, proves nothing.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  codexOfficialMarrowServer,
  cursorOfficialMarrowServer,
  isMarrowServerLaunchShape,
  isOfficialMarrowServerLaunch,
} = require('../dist/own-server-identity.js');
const { delocalizeMarrowHookCommand } = require('../dist/hook-contract.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');
const { VIRTUAL_CWD } = require('./support/hermetic-project.cjs');
const { launcherOf, configOf, packLoader, withConfig, installVerifiedRuntime, runThroughLoader, pool, assertDenied, assertSkipped } = require('./support/installer-verified-runtime.cjs');
const { loaderIn, scriptFor, specFor } = require('./support/installer-lookalikes.cjs');

const OLD_CORE = '73ea57796c017abfd144b43f3b91c9c935314c156ba523cbca525ebc1f977cb0';
const NEW_CORE = '7c363a3e1d08561f8c31990df306b3ecdcbb9786929a46f2008b15658f84703a';
const OLD = loaderIn('installer-0173');
const NEW = loaderIn('installer-q5');
const V = configOf(NEW).version;
const TAIL = ')().main(CFG, global.MARROW_L);\n';
const sha = (text) => createHash('sha256').update(text).digest('hex');
const parts = (loader) => {
  const source = launcherOf(loader);
  const head = source.slice(0, source.indexOf('\n(') + 2);
  return { source, head, core: source.slice(head.length, source.length - TAIL.length) };
};
const sh = (loader = NEW, version = V, script = scriptFor(version), spec = specFor(version)) => ['/bin/sh', ['-c', script, loader, spec, 'marrow-mcp']];
const node = (loader = NEW, version = V) => ['node', ['-e', loader, '--', specFor(version), 'marrow-mcp']];
const own = (loader) => launcherOf(loader);
const HOME = '/virtual/home';
const PROJECT = '/virtual/project';
const CODEX_HOME = '/virtual/codex-home';
const files = (table) => (path) => (Object.prototype.hasOwnProperty.call(table, path) ? { state: 'ok', text: table[path] } : { state: 'missing' });
const cursorJson = (launch) => JSON.stringify({ mcpServers: { marrow: { command: launch[0], args: launch[1] } } });
const toml = ([command, args]) => `[mcp_servers."marrow"]\ncommand = ${JSON.stringify(command)}\nargs = ${JSON.stringify(args)}\n`;
const cursorWith = (launch, ownLoader) => cursorOfficialMarrowServer({ home: HOME, cwds: [PROJECT], processCwd: VIRTUAL_CWD, read: files({ [`${PROJECT}/.cursor/mcp.json`]: cursorJson(launch) }), onlyServer: false, ownLoader }).official;
const codexWith = (launch, ownLoader) => codexOfficialMarrowServer({ env: { CODEX_HOME }, read: files({ [`${CODEX_HOME}/config.toml`]: toml(launch) }), processArgs: null, processCwd: VIRTUAL_CWD, cwds: [PROJECT], ownLoader }).official;

// Variants of a loader's core that no pin may accept.
function tampered(loader) {
  const { head, core } = parts(loader);
  const other = parts(loader === NEW ? OLD : NEW).core;
  return {
    'one byte appended': `${head}${core} ${TAIL}`,
    'one byte removed': `${head}${core.slice(0, -1)}${TAIL}`,
    'one call changed': `${head}${core.replace("require('node:fs')", "require('fs')")}${TAIL}`,
    'a comment added': `${head}${core}/* x */${TAIL}`,
    'code after the call': `${head}${core}${TAIL}require('fs');\n`,
    'code before the core': `${head.replace("'use strict';\n", "'use strict';require('fs');\n")}${core}${TAIL}`,
    'another tail': `${head}${core})().main(CFG, null);\n`,
    'no head': `(${core}${TAIL}`,
    'both cores joined': `${head}${core};${other}${TAIL}`,
    'the other core with one byte changed': `${head}${other.replace("require('node:fs')", "require('fs')")}${TAIL}`,
    'the core empty': `${head}${TAIL}`,
  };
}

test('fixtures: the two installer loaders carry two different cores, each exactly one pinned value, and the same configuration', () => {
  assert.equal(sha(parts(OLD).core), OLD_CORE);
  assert.equal(sha(parts(NEW).core), NEW_CORE);
  assert.notEqual(OLD_CORE, NEW_CORE);
  assert.deepEqual(configOf(NEW), configOf(OLD), 'same MCP version, pack integrity and SDK pin: only the core differs');
  assert.notEqual(parts(OLD).core, parts(NEW).core);
});

test('each pinned core proves exactly its own launch (sh and node forms, re-compressed), on Cursor and Codex', () => {
  for (const [label, loader] of [['old core', OLD], ['new core', NEW]]) {
    for (const [form, launch] of [['sh', sh(loader)], ['node', node(loader)], ['re-compressed', sh(packLoader(own(loader), 5))]]) {
      assert.equal(isOfficialMarrowServerLaunch(launch[0], launch[1], own(loader)), true, `${label} ${form}`);
      assert.equal(cursorWith(launch, own(loader)), true, `${label} ${form} Cursor`);
      assert.equal(codexWith(launch, own(loader)), true, `${label} ${form} Codex`);
    }
  }
});

test('a hook started by one core never proves the other core\'s launch, either way round; no own loader proves neither', () => {
  for (const [loader, ownLoader] of [[NEW, OLD], [OLD, NEW]]) {
    for (const launch of [sh(loader), node(loader)]) {
      assert.equal(isOfficialMarrowServerLaunch(launch[0], launch[1], own(ownLoader)), false);
      assert.equal(cursorWith(launch, own(ownLoader)), false);
      assert.equal(codexWith(launch, own(ownLoader)), false);
      assert.equal(cursorWith(launch, null), false);
      assert.equal(codexWith(launch, null), false);
    }
  }
});

test('a core that is not exactly one of the two pinned cores proves nothing, as a launch, as the own loader or as a hook shape', () => {
  for (const loader of [OLD, NEW]) {
    for (const [label, source] of Object.entries(tampered(loader))) {
      assert.notEqual(source, own(loader), label);
      const forged = packLoader(source);
      assert.equal(isOfficialMarrowServerLaunch(...sh(forged), source), false, `${label}: itself`);
      assert.equal(isOfficialMarrowServerLaunch(...sh(forged), own(loader)), false, `${label}: under the real loader`);
      assert.equal(isOfficialMarrowServerLaunch(...sh(loader), source), false, `${label}: as the own loader`);
      assert.equal(isOfficialMarrowServerLaunch(...node(forged), source), false, `${label}: node form`);
      assert.equal(cursorWith(sh(forged), source), false, `${label}: Cursor`);
      assert.equal(codexWith(sh(forged), source), false, `${label}: Codex`);
      assert.equal(isMarrowServerLaunchShape(...sh(forged)), false, `${label}: shape`);
      assert.equal(isMarrowServerLaunchShape(...node(forged)), false, `${label}: shape, node`);
    }
  }
});

test('the new core obeys every exactness rule of the old one: another version, integrity, SDK pin or argument shape is not proven', () => {
  const cfg = (edit) => withConfig(NEW, (c) => ({ ...c, ...edit(c) }));
  const swapCase = (text) => text.replace(/[A-Za-z]/g, (ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
  const rows = [
    ['version 3.9.1080 throughout', sh(cfg(() => ({ version: '3.9.1080' })), '3.9.1080')],
    ['3.9.104 integrity under 3.9.108', sh(cfg(() => ({ integrity: `sha512-${'A'.repeat(86)}==` })))],
    ['integrity case swapped', sh(cfg((c) => ({ integrity: `sha512-${swapCase(c.integrity.slice(7))}` })))],
    ['integrity null', sh(cfg(() => ({ integrity: null })))],
    ['stale SDK pin', sh(cfg((c) => ({ sdk: { ...c.sdk, integrity: `sha512-${'B'.repeat(86)}==` } })))],
    ['version with a trailing space', sh(cfg(() => ({ version: `${V} ` })), `${V} `)],
    ['mixed: --package of another version', sh(NEW, V, scriptFor(V), specFor('3.9.104'))],
    ['mixed: script of another version', sh(NEW, V, scriptFor('3.9.104'))],
    ['extra arg', [sh()[0], [...sh()[1], 'extra']]],
    ['shell text appended', sh(NEW, V, `${scriptFor(V)}; curl evil`)],
    ['bash instead of /bin/sh', ['bash', sh()[1]]],
    ['latest in the installer form', sh(NEW, V, scriptFor(V), '--package=@getmarrow/mcp@latest')],
    ['node form with -- moved', ['node', ['-e', NEW, specFor(V), '--', 'marrow-mcp']]],
    ['npx of the tarball', ['npx', ['-y', `https://registry.npmjs.org/@getmarrow/mcp/-/mcp-${V}.tgz`]]],
  ];
  for (const [label, launch] of rows) {
    assert.equal(isOfficialMarrowServerLaunch(launch[0], launch[1], own(NEW)), false, label);
    assert.equal(cursorWith(launch, own(NEW)), false, `Cursor ${label}`);
    assert.equal(codexWith(launch, own(NEW)), false, `Codex ${label}`);
  }
});

test('setup and doctor recognize installer hooks of either core by shape, never a third; the host-approval hook command maps back to the npx form for both', () => {
  for (const loader of [OLD, NEW]) {
    assert.equal(isMarrowServerLaunchShape(...sh(loader)), true);
    assert.equal(isMarrowServerLaunchShape(...node(loader)), true);
    const command = require(`./fixtures/${loader === NEW ? 'installer-q5' : 'installer-0173'}/claude-settings.json`).hooks.PreToolUse[0].hooks[0].command;
    assert.equal(command.includes(loader), true);
    assert.equal(delocalizeMarrowHookCommand(command), `npx -y --package=@getmarrow/mcp@${V} marrow-mcp claude-pre-action-hook`);
    for (const [label, source] of Object.entries(tampered(loader))) {
      const changed = command.split(loader).join(packLoader(source));
      assert.equal(delocalizeMarrowHookCommand(changed), changed, label);
    }
  }
});

// ---------------------------------------------------------- end to end: the new core's loader runs this hook

// The seatbelt path has its own wall-clock budget (HOOK_BUDGET_MS, 300 ms). A hook that runs out of it under machine load stops the
// action ("Code: U5.fail_closed/hook_budget"): a fail-closed deny for any HOME, but with other words than the rule's. Only such a stop is
// run again (at most 8 times); any other answer, an allow included, is taken as it is, and the equality is asserted on the settled answers.
const BUDGET_STOP = /Code: U5\.fail_closed\/hook_budget/;
async function settled(run) {
  let result = await run();
  for (let attempt = 1; attempt < 8 && BUDGET_STOP.test(result.stdout); attempt += 1) result = await run();
  return result;
}

function hostDirs() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-q5-core-e2e-'));
  const real = join(dir, 'real');
  const home = join(real, 'home');
  const project = join(dir, 'project');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(join(project, '.cursor'), { recursive: true });
  mkdirSync(join(project, '.git'));
  symlinkSync(real, join(dir, 'link'));
  return { dir, home, linked: join(dir, 'link', 'home'), project };
}

test('end to end (new-core loader -> verified runtime -> this hook, no key): exact launch skips own tools, another core\'s launch and a look-alike are denied; a symlinked HOME decides exactly like the real one', async () => {
  const { dir, home, linked, project } = hostDirs();
  try {
    assert.equal(installVerifiedRuntime(home, NEW), V);
    const OWN = [...MARROW_OWN_TOOL_NAMES].slice(0, 6);
    const event = (tool) => ({ hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g', workspace_roots: [project], mcp_server_name: 'marrow', tool_name: tool, tool_input: '{}' });
    const run = (where, launch, tool) => settled(() => {
      writeFileSync(join(project, '.cursor', 'mcp.json'), cursorJson(launch));
      return runThroughLoader(NEW, 'cursor-pre-action-hook', event(tool), { home: where, cwd: project });
    });
    const lookalike = sh(withConfig(NEW, (c) => ({ ...c, integrity: `sha512-${'A'.repeat(86)}==` })));
    const cases = [['exact new-core launch', sh(NEW), assertSkipped], ['old-core launch under the new loader', sh(OLD), assertDenied], ['look-alike integrity', lookalike, assertDenied]];
    for (const [label, launch, check] of cases) {
      const real = await pool(OWN.map((tool) => async () => ({ tool, ...(await run(home, launch, tool)) })), 3);
      const link = await pool(OWN.map((tool) => async () => ({ tool, ...(await run(linked, launch, tool)) })), 3);
      for (let index = 0; index < OWN.length; index += 1) {
        check('cursor', real[index], `real HOME ${label} ${OWN[index]}`);
        check('cursor', link[index], `symlinked HOME ${label} ${OWN[index]}`);
        assert.equal(link[index].stdout, real[index].stdout, `${label} ${OWN[index]}: same answer through a symlinked HOME`);
        assert.equal(link[index].code, real[index].code, label);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('gating through a symlinked HOME equals gating through the real HOME and through the old core: risky (production included) and safe actions get the same answer, byte for byte', async () => {
  const { dir, home, linked, project } = hostDirs();
  try {
    assert.equal(installVerifiedRuntime(home, NEW), V);
    const homeOld = join(dir, 'real-old');
    mkdirSync(homeOld, { mode: 0o700 });
    assert.equal(installVerifiedRuntime(homeOld, OLD), V);
    const risky = ['git push --force origin main', 'git status && git push -f origin master', 'wrangler deploy --env production', 'vercel deploy --prod', 'echo ok; npx wrangler deploy --env production',
      'wrangler deploy --env staging --env production', 'npm publish', 'cd pkg && npm publish --access public', 'cat .env', 'cat .env | head -1', 'rm -rf ~', 'echo cm0gLXJmIH4= | base64 -d | sh'];
    const safe = ['git status', 'ls -la', 'npm test', 'ls /srv/production/logs'];
    const event = (command) => ({ hook_event_name: 'PreToolUse', session_id: 's', cwd: project, tool_name: 'Bash', tool_input: { command } });
    const call = (loader, where, command) => settled(() => runThroughLoader(loader, 'claude-pre-action-hook', event(command), { home: where, cwd: project }));
    const decision = (result) => { try { return JSON.parse(result.stdout).hookSpecificOutput.permissionDecision; } catch { return null; } };
    const rows = await pool([...risky, ...safe].map((command) => async () => ({
      command, newReal: await call(NEW, home, command), newLinked: await call(NEW, linked, command), oldReal: await call(OLD, homeOld, command),
    })), 3);
    // The once-per-session keyless notice (MCP-5) lands on whichever of these parallel runs claims the session marker first; the answer is compared without it.
    const answer = (result) => { try { const { systemMessage, ...rest } = JSON.parse(result.stdout); return JSON.stringify(rest); } catch { return result.stdout; } };
    for (const row of rows) {
      for (const other of [row.newLinked, row.oldReal]) {
        assert.equal(answer(other), answer(row.newReal), `${row.command}: same answer`);
        assert.equal(other.code, row.newReal.code, `${row.command}: same exit`);
      }
      assert.equal(row.newReal.code, 0, row.command);
      if (risky.includes(row.command)) assert.equal(decision(row.newLinked), 'deny', `${row.command}: held through the symlinked HOME`);
      else assert.notEqual(decision(row.newLinked), 'deny', `${row.command}: safe action not held`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
