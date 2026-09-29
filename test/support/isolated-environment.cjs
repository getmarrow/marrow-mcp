'use strict';

// Preloaded by `npm test` (node --test --require) into the runner and every
// test-file process. Hook code reads ~/.marrow: the owner's local control
// switch, spools, loop-guard state and credentials. Tests must never depend on
// or change this machine's copy, or reach the Marrow API with the host's key,
// so each process gets a private temporary HOME and no inherited Marrow
// identity or host-session markers. Tests that need other values set them.
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const home = mkdtempSync(join(tmpdir(), 'marrow-mcp-test-home-'));
process.env.HOME = home;
process.env.USERPROFILE = home;
for (const key of Object.keys(process.env)) {
  if (/^(?:MARROW_|CLAUDE_CODE_)/.test(key) || key === 'CLAUDECODE' || key === 'CODEX_HOME') delete process.env[key];
}
process.on('exit', () => {
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
});
