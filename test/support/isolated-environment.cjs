'use strict';

// Preloaded by `npm test` (node --test --require) into the runner and every
// test-file process. Hook code reads ~/.marrow: the owner's local control
// switch, spools, loop-guard state and credentials. Tests must never depend on
// or change this machine's copy, or reach the Marrow API with the host's key,
// so each process gets a private temporary HOME and no inherited Marrow
// identity or host-session markers. Tests that need other values set them.
const { mkdtempSync, rmSync } = require('node:fs');
const childProcess = require('node:child_process');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const home = mkdtempSync(join(tmpdir(), 'marrow-mcp-test-home-'));
process.env.HOME = home;
process.env.USERPROFILE = home;
// Kept: the path of an installed Claude Code bundle, for the pinned-texts check (a file path, not an identity).
const keep = new Set(['MARROW_TEST_CLAUDE_CODE_BUNDLE']);
for (const key of Object.keys(process.env)) {
  if (keep.has(key)) continue;
  if (/^(?:MARROW_|CLAUDE_CODE_)/.test(key) || key === 'CLAUDECODE' || key === 'CODEX_HOME') delete process.env[key];
  // `npm test` exports npm_config_* to its children; the own-tool identity check treats those as
  // a possible npx redirect, so a hook under test starts from a shell-like environment.
  if (/^npm_config_/i.test(key)) delete process.env[key];
}

// The passwd home (os.userInfo().homedir) is where the seatbelt reads account evidence and writes its
// receipts, and no environment variable can move it. Without this, a hook the tests spawn would read
// and write the machine's real ~/.marrow. Every child process the suite starts gets an empty scratch
// passwd home through test/support/passwd-home-fake.cjs; a test that sets SBT_PASSWD_HOME itself keeps its own.
const passwdHome = mkdtempSync(join(tmpdir(), 'marrow-mcp-test-passwd-'));
process.env.SBT_PASSWD_HOME = passwdHome;
const FAKE = join(__dirname, 'passwd-home-fake.cjs');
require(FAKE);
function childEnv(env) {
  const out = { ...(env && typeof env === 'object' ? env : process.env) };
  out.NODE_OPTIONS = `${out.NODE_OPTIONS ? `${out.NODE_OPTIONS} ` : ''}--require=${FAKE}`;
  if (!out.SBT_PASSWD_HOME) out.SBT_PASSWD_HOME = passwdHome;
  return out;
}
// spawn, spawnSync, execFile, execFileSync, fork, exec and execSync: the options object is the first plain object after the command.
function withChildEnv(args) {
  const list = [...args];
  const at = list.findIndex((arg, index) => index > 0 && arg && typeof arg === 'object' && !Array.isArray(arg));
  if (at > 0) {
    list[at] = { ...list[at], env: childEnv(list[at].env) };
    return list;
  }
  const callback = list.findIndex((arg, index) => index > 0 && typeof arg === 'function');
  list.splice(callback > 0 ? callback : list.length, 0, { env: childEnv(null) });
  return list;
}
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'exec', 'execSync']) {
  const original = childProcess[name];
  childProcess[name] = function patched(...args) {
    return original.apply(this, withChildEnv(args));
  };
}
process.on('exit', () => {
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
  try { rmSync(passwdHome, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
});
