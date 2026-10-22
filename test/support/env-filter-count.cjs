'use strict';

// Runs in a FRESH process (test/env-dump-coverage.test.js spawns it) so a mapper loaded by another test cannot hide a load. It counts, with no clock:
// how many times the seatbelt mapper module is loaded and how many times its shell entry point is called for each command. It prints one JSON
// line of counts, never a command and never an environment.
// usage: node env-filter-count.cjs <classify|post> <json file holding an array of commands> [PostToolUse|PostToolUseFailure]
//   classify  the PreToolUse classification (dist/hook-pre-action.js classifyTool, as the keyed pre-action hook calls it)
//   post      the REAL PostToolUse handler (dist/hook.js runHookCommand), in this process, with a private HOME and every network and
//             process-starting entry point trapped (a trapped call is counted and throws; nothing is sent and nothing is started)
const Module = require('node:module');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');
const [mode, file, eventName = 'PostToolUse'] = process.argv.slice(2);

// A private HOME and passwd home, no Marrow identity: the handler must never read or write this machine's ~/.marrow.
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-post-'));
process.env.HOME = scratch;
process.env.USERPROFILE = scratch;
process.env.SBT_PASSWD_HOME = path.join(scratch, 'passwd-home');
fs.mkdirSync(process.env.SBT_PASSWD_HOME, { recursive: true });
require('./passwd-home-fake.cjs');
for (const key of Object.keys(process.env)) {
  if (/^(?:MARROW_|CLAUDE_CODE_)/.test(key) || key === 'CLAUDECODE' || key === 'CODEX_HOME' || /^npm_config_/i.test(key)) delete process.env[key];
}

const state = { loads: 0, calls: 0, classifyCalls: 0, trapped: 0 };
const mapperFile = path.join(root, 'dist', 'seatbelt', 'mapper.js');
const load = Module._load;
Module._load = function patchedLoad(request, parent, ...rest) {
  const loaded = load.call(this, request, parent, ...rest);
  let filename = null;
  try { filename = Module._resolveFilename(request, parent); } catch { /* a builtin or an unresolvable name is not the mapper */ }
  if (filename === mapperFile && !loaded.__counted) {
    state.loads += 1;
    const entry = loaded.evaluateSeatbeltShell;
    loaded.evaluateSeatbeltShell = function counted(...args) { state.calls += 1; return entry.apply(this, args); };
    loaded.__counted = true;
  }
  return loaded;
};

// Network and process entry points: counted and refused by name only (no argument is ever kept).
function trap(owner, names, label) {
  for (const name of names) {
    if (typeof owner[name] !== 'function') continue;
    owner[name] = function trapped() { state.trapped += 1; throw new Error(`blocked: ${label}.${name}`); };
  }
}
if (mode === 'post') {
  globalThis.fetch = function trapped() { state.trapped += 1; return Promise.reject(new Error('blocked: fetch')); };
  trap(require('node:http'), ['request', 'get'], 'http');
  trap(require('node:https'), ['request', 'get'], 'https');
  trap(require('node:http2'), ['connect'], 'http2');
  trap(require('node:net'), ['connect', 'createConnection'], 'net');
  trap(require('node:tls'), ['connect'], 'tls');
  trap(require('node:dns'), ['lookup', 'resolve', 'resolve4', 'resolve6'], 'dns');
  trap(require('node:dgram'), ['createSocket'], 'dgram');
  trap(require('node:child_process'), ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'], 'child_process');
  require('node:net').Socket.prototype.connect = function trapped() { state.trapped += 1; throw new Error('blocked: net.Socket.connect'); };
}

async function main() {
  const commands = JSON.parse(fs.readFileSync(file, 'utf8'));
  const perCommand = [];
  let stdoutBytes = 0;
  if (mode === 'classify') {
    const { classifyTool } = require(path.join(root, 'dist/hook-pre-action.js'));
    for (const command of commands) {
      const before = state.calls;
      classifyTool({ tool_name: 'Bash', tool_input: { command } });
      perCommand.push(state.calls - before);
    }
  } else if (mode === 'post') {
    // The handler as the host runs it. A spy on classifyTool proves each row reached the classification (a handler that returned early
    // would count 0 and pass for nothing); it passes every call through unchanged.
    const preAction = require(path.join(root, 'dist/hook-pre-action.js'));
    const classify = preAction.classifyTool;
    preAction.classifyTool = function spied(...args) { state.classifyCalls += 1; return classify.apply(this, args); };
    const { runHookCommand } = require(path.join(root, 'dist/hook.js'));
    const write = process.stdout.write;
    let index = 0;
    for (const command of commands) {
      const before = state.calls;
      index += 1;
      process.stdout.write = function counted(chunk) { stdoutBytes += Buffer.byteLength(String(chunk)); return true; };
      try {
        await runHookCommand({
          hook_event_name: eventName,
          session_id: 'envdump-post-count',
          tool_use_id: `toolu_count_${index}`,
          tool_name: 'Bash',
          tool_input: { command },
          ...(eventName === 'PostToolUseFailure' ? { error: 'exit 1' } : { tool_response: { stdout: '', stderr: '', exit_code: 0 } }),
        });
      } finally {
        process.stdout.write = write;
      }
      perCommand.push(state.calls - before);
    }
  } else {
    throw new Error('mode must be classify or post');
  }
  process.stdout.write(`${JSON.stringify({ loads: state.loads, calls: state.calls, classifyCalls: state.classifyCalls, trapped: state.trapped, stdoutBytes, perCommand })}\n`);
}

main().then(() => fs.rmSync(scratch, { recursive: true, force: true }), (error) => {
  fs.rmSync(scratch, { recursive: true, force: true });
  process.stderr.write(`env-filter-count failed: ${String(error && error.name)}\n`);
  process.exitCode = 1;
});
