'use strict';

// Runs in a FRESH process (test/env-dump-coverage.test.js spawns it) so a mapper loaded by another test cannot hide a load. It counts, with no clock:
// how many times the seatbelt mapper module is loaded and how many times its shell entry point is called for each command. It prints one JSON
// line of counts, never a command and never an environment. usage: node env-filter-count.cjs <classify|post> <json file holding an array of commands>
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');
const state = { loads: 0, calls: 0 };
const load = Module._load;
Module._load = function patchedLoad(request, ...rest) {
  const loaded = load.call(this, request, ...rest);
  if (/(?:^|[\\/])seatbelt[\\/]mapper(?:\.js)?$/.test(request) && !loaded.__counted) {
    state.loads += 1;
    const entry = loaded.evaluateSeatbeltShell;
    loaded.evaluateSeatbeltShell = function counted(...args) { state.calls += 1; return entry.apply(this, args); };
    loaded.__counted = true;
  }
  return loaded;
};

const [mode, file] = process.argv.slice(2);
const commands = JSON.parse(fs.readFileSync(file, 'utf8'));
const perCommand = [];
if (mode === 'classify') {
  const { classifyTool } = require(path.join(root, 'dist/hook-pre-action.js'));
  for (const command of commands) {
    const before = state.calls;
    classifyTool({ tool_name: 'Bash', tool_input: { command } });
    perCommand.push(state.calls - before);
  }
} else {
  // The PostToolUse path (hook.ts shouldSkipAutoLog) reads the policy alone.
  const policy = require(path.join(root, 'dist/hook-tool-policy.js'));
  for (const command of commands) {
    const before = state.calls;
    policy.isReadOnlyToolEvent({ tool_name: 'Bash', tool_input: { command } });
    policy.isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command } });
    perCommand.push(state.calls - before);
  }
}
process.stdout.write(`${JSON.stringify({ loads: state.loads, calls: state.calls, perCommand })}\n`);
