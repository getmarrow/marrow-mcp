'use strict';

// The own-server identity check (src/own-server-identity.ts) starts from the hook's working folder (and the event's) and
// looks upward for project npm config, a planted local @getmarrow/mcp copy and host config. For a test that is about
// something else that folder must not be the package checkout: a checkout sits wherever the person put it, and anything
// above it (a user npm config in an account home, a node_modules in a parent) would change the verdict the test asserts.
// So a test that reaches the check from the process folder runs it from a fresh, empty project folder:
//   projectCwd()       the folder, for `cwd:` of a spawned hook
//   enterProjectCwd()  makes it the process cwd and returns the function that restores the old one (call it in `finally`);
//                      only for in-process calls that have no cwd seam (isOfficialMarrowMcpEventOnHost,
//                      runPreActionHookCommand), around one test, never for a whole runner or file
//   VIRTUAL_CWD        for the functions that take `processCwd` and read through an in-memory reader: no real folder at all
// The product walk is unchanged. Tests that need a real project config above their cwd (test/npm-project-config.test.js,
// test/hermetic-identity-harness.test.js) still build one and assert the product holds on it.
const { mkdirSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const VIRTUAL_CWD = '/virtual/hermetic-process-cwd';

let made = null;

function projectCwd() {
  if (made) return made;
  const root = mkdtempSync(join(tmpdir(), 'marrow-mcp-test-project-'));
  const dir = join(root, 'project');
  mkdirSync(dir);
  made = dir;
  process.on('exit', () => {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
  });
  return dir;
}

function enterProjectCwd() {
  const previous = process.cwd();
  process.chdir(projectCwd());
  return () => { process.chdir(previous); };
}

module.exports = { VIRTUAL_CWD, enterProjectCwd, projectCwd };
