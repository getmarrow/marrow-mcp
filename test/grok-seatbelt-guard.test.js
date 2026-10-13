'use strict';

// Audit M1 (abf9926b): the installed Grok guard (installer f72085d, GROK_PRE_ACTION_GUARD_SOURCE) passes
// on only `{"decision":"allow"}` or the fixed denial; any other output is its launch failure. A seatbelt
// stop on Grok therefore emits exactly the fixed denial. The guard below is the f72085d source with one
// change: it starts this checkout's hook (node dist/cli.js) instead of `npx marrow-mcp`. Keyless
// temporary home; nothing reaches a server.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const { GROK_FIXED_DENIAL } = require('../dist/hook-pre-action.js');
const INSTALLER_GROK_FIXED_DENIAL = 'Marrow blocked this protected action.';
const GROK_LAUNCH_FAILURE = 'Marrow governance adapter was unavailable; this action is blocked.';

const GUARD = [
  'const {spawn}=require("node:child_process");',
  `const valid=new Set([${JSON.stringify('{"decision":"allow"}')},${JSON.stringify(`{"decision":"deny","reason":"${INSTALLER_GROK_FIXED_DENIAL}"}`)}]);`,
  'let child=null,timer=null,done=false,input=[],inputBytes=0,output="",outputBytes=0;',
  `const fail=()=>{if(done)return;done=true;if(timer)clearTimeout(timer);if(child&&!child.killed)child.kill("SIGKILL");process.stderr.write(${JSON.stringify(`${GROK_LAUNCH_FAILURE}\n`)});process.exitCode=2;process.stdin.destroy();};`,
  'process.stdin.on("error",fail);',
  'process.stdin.on("data",chunk=>{const value=Buffer.from(chunk);inputBytes+=value.length;if(inputBytes>65536){fail();return;}input.push(value);});',
  'process.stdin.on("end",()=>{if(done)return;try{',
  // f72085d: spawn(npx, ["-y", "--package=<spec>", "marrow-mcp", "grok-pre-action-hook"]); here: this checkout.
  `child=spawn(process.execPath,${JSON.stringify(['--require', PRELOAD, CLI, 'grok-pre-action-hook'])},{stdio:["pipe","pipe","ignore"]});`,
  'timer=setTimeout(fail,5000);',
  'child.stdout.on("data",chunk=>{if(done)return;outputBytes+=chunk.length;if(outputBytes>512){fail();return;}output+=chunk.toString("utf8");});',
  'child.on("error",fail);child.stdin.on("error",fail);',
  'child.on("close",code=>{if(done)return;if(code!==0||!valid.has(output)){fail();return;}done=true;if(timer)clearTimeout(timer);process.stdout.write(output);});',
  'child.stdin.end(Buffer.concat(input));}catch{fail();}});',
].join('');

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-m1-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.mkdirSync(path.join(home, '.ssh'), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function guarded(sb, toolName, toolInput) {
  const event = { hookEventName: 'PreToolUse', sessionId: `m1-${crypto.randomBytes(6).toString('hex')}`, toolUseId: 't', toolName, toolInput, cwd: sb.proj };
  const r = spawnSync(process.execPath, ['-e', GUARD], {
    cwd: sb.proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  return { status: r.status, out: r.stdout, err: r.stderr };
}

test('M1: the hook\'s Grok denial is the installer\'s fixed denial', () => {
  assert.equal(GROK_FIXED_DENIAL, INSTALLER_GROK_FIXED_DENIAL);
});

test('M1: through the installed Grok guard (f72085d), every keyless seatbelt stop is the fixed denial, never the guard\'s launch failure', () => {
  const sb = sandbox();
  try {
    const fixed = JSON.stringify({ decision: 'deny', reason: INSTALLER_GROK_FIXED_DENIAL });
    const stops = [
      ['run_terminal_command', { command: 'npm publish' }],
      ['run_terminal_command', { command: 'cat ~/.ssh/id_ed25519' }],
      ['run_terminal_command', { command: 'git push --force origin main' }],
      ['write', { path: path.join(sb.home, '.bashrc'), content: 'alias git=true' }],
      ['search_replace', { path: path.join(sb.home, '.marrow', 'control.json'), old_string: 'a', new_string: 'b' }],
    ];
    for (const [tool, input] of stops) {
      const r = guarded(sb, tool, input);
      assert.equal(r.status, 0, `${tool} ${JSON.stringify(input)}: ${r.err}`);
      assert.equal(r.out, fixed, `${tool} ${JSON.stringify(input)}`);
      assert.ok(!r.err.includes(GROK_LAUNCH_FAILURE), r.err);
    }
    // Every other keyless answer also passes the guard: the allow, or the fixed denial for an action 3.9.103
    // held (Grok has no neutral answer). Never the launch failure.
    for (const command of ['ls -la', 'npm test', 'git status', 'mkdir -p build/out']) {
      const r = guarded(sb, 'run_terminal_command', { command });
      assert.equal(r.status, 0, `${command}: ${r.err}`);
      assert.ok(['{"decision":"allow"}', fixed].includes(r.out), `${command}: ${r.out}`);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});
