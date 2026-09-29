const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const preload = resolve(__dirname, 'support', 'isolated-environment.cjs');

test('npm test preloads the isolated environment for every test file', () => {
  const { scripts } = require('../package.json');
  assert.match(scripts.test, /node --test --require \.\/test\/support\/isolated-environment\.cjs test\/\*\.test\.js$/);
});

test('the isolated environment ignores a disabled host control switch and host Marrow identity', () => {
  const hostHome = mkdtempSync(join(tmpdir(), 'marrow-mcp-host-home-'));
  try {
    mkdirSync(join(hostHome, '.marrow'), { mode: 0o700 });
    writeFileSync(join(hostHome, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled: false, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: 0o600 });
    const script = `
      const { homedir } = require('node:os');
      const { readLocalControlState } = require(${JSON.stringify(resolve(__dirname, '..', 'dist', 'control-state.js'))});
      process.stdout.write(JSON.stringify({
        home: process.env.HOME,
        homedir: homedir(),
        control: readLocalControlState().state,
        inherited: Object.keys(process.env).filter((key) => /^(?:MARROW_|CLAUDE_CODE_)/.test(key) || key === 'CLAUDECODE' || key === 'CODEX_HOME'),
      }));
    `;
    const hostEnv = {
      PATH: process.env.PATH,
      HOME: hostHome,
      MARROW_API_KEY: 'synthetic-host-key',
      MARROW_FLEET_AGENT_ID: 'host-agent',
      CLAUDE_CODE_CHILD_SESSION: '1',
      CODEX_HOME: join(hostHome, '.codex'),
    };
    const unisolated = spawnSync(process.execPath, ['-e', script], { env: hostEnv, encoding: 'utf8' });
    assert.equal(unisolated.status, 0, unisolated.stderr);
    assert.equal(JSON.parse(unisolated.stdout).control, 'disabled');

    const isolated = spawnSync(process.execPath, ['--require', preload, '-e', script], { env: hostEnv, encoding: 'utf8' });
    assert.equal(isolated.status, 0, isolated.stderr);
    const result = JSON.parse(isolated.stdout);
    assert.notEqual(result.home, hostHome);
    assert.equal(result.homedir, result.home);
    assert.ok(result.home.startsWith(tmpdir()));
    assert.equal(result.control, 'default_enabled');
    assert.deepEqual(result.inherited, []);
    assert.throws(() => statSync(result.home), { code: 'ENOENT' }, 'the temporary HOME is removed on exit');
  } finally {
    rmSync(hostHome, { recursive: true, force: true });
  }
});
