'use strict';
// PL12 (pack row 12, MCP 3.9.116; test only). A keyless listing of a credential or Marrow-state folder answers as 3.9.114 (X3), and the
// rows below turn red when the PL-12 plants remove that rule. The X3 test (client-misses-miss3-r3.test.js) compares only the hook's stdout
// and exit code: it is red under the plants at its `cd ...; ls` rows (the FX-3 reading holds those), but for a plain listing such as
// `ls ~/.aws` the FX-3 reading changes neither stdout nor exit code on the keyless path (the answer stays "no stop, no call"). What it
// changes there is the entry the hook's local loop guard writes for the call: kind `read` as 3.9.114 gave, `mutation` with the FX-3
// reading. So every row here compares the whole answer: decision word, exit code, stdout against the plain `ls` row, loopback calls, and
// the loop-guard kind.
// Plants (scratch copy only, never committed): PL-12a removes `withMasterListing` at src/hook-pre-action.ts:723; PL-12b removes
// `!masterListing &&` at src/hook-tool-policy.ts:673. Both turn K1, K3, AB1 (the in-folder link row) and AB3 red; K2 (keyed, FX-3 kept)
// and AB2 (stopped before any classification) stay green under them; K2 turns red when the keyed reading is lost or the keyless one leaks.
// Recorded answers: the 3.9.114 build (48b1fbec80ab) and BASE d3dea44c4b21 (3.9.115) agree on every keyless row below; ids and closed
// words only. Folders, symlinks and dummy keys live under a private HOME made at run time; no command runs (the hook only classifies);
// no credential store is read. The one state file read is the loop guard's, and only its entry kinds are kept (never printed).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { execFileSync, spawn } = require('node:child_process');

const DIST = path.join(__dirname, '..', 'dist');
const hook = require(path.join(DIST, 'hook-pre-action.js'));

const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
// A dummy key: a fixed non-key prefix plus run-time hex; no real key shape can come out of it.
const newDummyKey = () => {
  const key = `dummy-keyless-listing-${hex(12)}`;
  assert.ok(/^dummy-keyless-listing-[0-9a-f]{24}$/.test(key) && !/(?:^|[^a-z])(?:sk|pk|rk)_|ghp_|xox/.test(key), 'a dummy key is never key-shaped');
  return key;
};

const POSIX = process.platform !== 'win32';
let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }
const SKIP = !opensslOk || !POSIX;
const LOOP_KINDS = ['poll', 'verification', 'read', 'mutation'];
const KEYLESS_MODES = ['seatbelt', 'claimed', 'strict'];

// The real hook entrypoint (dist/cli.js claude-pre-action-hook, event JSON on stdin) with a private HOME per row and a self-signed
// https loopback recorder that lists every call the hook makes. Keyless modes: seatbelt (no account evidence), claimed (a Marrow
// folder under the private HOME) and strict (MARROW_SEATBELT_STRICT=1); `keyed` has a dummy key in the environment.
async function withRecorder(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-pl12-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const calls = [];
  const server = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) }, (req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      calls.push({ url: req.url, raw });
      const reply = (data) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data })); };
      if (req.url === '/v1/agent/runtime') return reply({ decision_id: 'decision-one', gate_receipt_id: 'gate-one', risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] } });
      return reply({ accepted: true });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const run = async (command, { mode = 'seatbelt', eventExtra = {}, toolInputExtra = {}, envExtra = {}, setup = null } = {}) => {
    const home = fs.mkdtempSync(path.join(dir, 'home-'));
    if (mode === 'claimed') fs.mkdirSync(path.join(home, '.marrow', 'host-approvals'), { recursive: true, mode: 0o700 });
    if (setup) setup(home);
    const env = {
      PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: path.join(home, 'pw'), MARROW_AUTO_HOOK: 'true',
      MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`, NODE_EXTRA_CA_CERTS: path.join(dir, 'c.pem'),
      MARROW_AGENT_ID: 'agent-one', MARROW_SESSION_ID: 'session-one', MARROW_EVENT_SPOOL_PATH: path.join(home, 'spool.json'),
      ...envExtra,
    };
    const key = newDummyKey();
    if (mode === 'keyed') env.MARROW_API_KEY = key;
    if (mode === 'strict') env.MARROW_SEATBELT_STRICT = '1';
    fs.mkdirSync(env.SBT_PASSWD_HOME, { recursive: true, mode: 0o700 });
    calls.length = 0;
    const child = spawn(process.execPath, [path.join(DIST, 'cli.js'), 'claude-pre-action-hook'], { cwd: home, env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.end(JSON.stringify({ session_id: 'session-one', tool_use_id: 'tool-one', hook_event_name: 'PreToolUse', tool_name: 'Bash',
      tool_input: { command, ...toolInputExtra }, cwd: home, permission_mode: 'auto', ...eventExtra }));
    const code = await new Promise((resolve) => child.on('close', resolve));
    const spool = fs.existsSync(env.MARROW_EVENT_SPOOL_PATH) ? fs.readFileSync(env.MARROW_EVENT_SPOOL_PATH, 'utf8') : '';
    // Every dummy key of the row (the configured one and the forged claims) carries the fixed prefix: none is in any output, spool or request.
    assert.ok(!`${stdout}\n${stderr}\n${spool}\n${calls.map((call) => call.raw).join('\n')}`.includes('dummy-keyless-listing-'), 'no dummy key is in any output, spool or request');    const result = { code, stdout: stdout.split(home).join('<HOME>'), urls: calls.map((call) => call.url), kind: loopGuardKinds(home) };
    fs.rmSync(home, { recursive: true, force: true });
    return result;
  };
  try { return await fn(run); } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The kinds of the loop-guard entries the hook wrote under a private HOME (closed words; the state file also holds a local secret, which
// is never read out, kept or printed). 'nostate' and 'noentry' are failures of the harness itself and never equal a recorded answer.
function loopGuardKinds(home) {
  let state;
  try { state = JSON.parse(fs.readFileSync(path.join(home, '.marrow', 'session-loop-guard', 'state.json'), 'utf8')); } catch { return 'nostate'; }
  const kinds = Object.values(state.sessions || {}).flatMap((session) => Object.values(session.entries || {}).map((entry) => entry.kind)).filter((kind) => LOOP_KINDS.includes(kind));
  return kinds.length ? kinds.join('+') : 'noentry';
}

const decision = (stdout) => { try { return JSON.parse(stdout).hookSpecificOutput?.permissionDecision ?? 'none'; } catch { return stdout.trim() ? 'unparsed' : 'empty'; } };
const answerOf = (result) => ({ decision: decision(result.stdout), code: result.code, calls: result.urls, kind: result.kind });

// Recorded answers (3.9.114 build 48b1fbec80ab = BASE d3dea44c4b21 for every keyless row; ids and closed words only).
const LOCAL_ANSWER = { decision: 'none', code: 0, calls: [], kind: 'read' }; // a plain local listing: no stop, no call, a read in the loop guard
const STOPPED_ANSWER = { decision: 'deny', code: 0, calls: [], kind: 'mutation' }; // stopped locally by the seatbelt, no call
// Keyed (3.9.115): the listing goes to the server (one /v1/agent/runtime call; a lifecycle-events call may also land, so only the runtime calls are counted).
const FX3_ANSWER = { decision: 'none', code: 0, runtimeCalls: 1, kind: 'mutation' };
const KEYED_LOCAL_ANSWER = { decision: 'none', code: 0, runtimeCalls: 0, kind: 'read' };
const keyedAnswerOf = (result) => ({ decision: decision(result.stdout), code: result.code, runtimeCalls: result.urls.filter((url) => url === '/v1/agent/runtime').length, kind: result.kind });

// K1 rows: a listing of a credential or Marrow-state folder.
const K1_ROWS = { 'K1-aws': 'ls ~/.aws', 'K1-ssh': 'ls -la ~/.ssh', 'K1-marrow': 'find ~/.marrow -maxdepth 1' };
// AB2: the same listings inside a quoted shell: stopped keyless as 3.9.114.
const AB2_ROWS = { 'AB2-aws': "bash -c 'ls ~/.aws'", 'AB2-ssh': 'sh -c "ls -la ~/.ssh"', 'AB2-marrow': "bash -c 'find ~/.marrow -maxdepth 1'" };
// AB3: the same listings piped on: local as 3.9.114.
const AB3_ROWS = { 'AB3-aws': 'ls ~/.aws | grep -c x', 'AB3-ssh': 'ls -la ~/.ssh | grep config', 'AB3-marrow': 'find ~/.marrow -maxdepth 1 | head -3' };

// In-process readings under a private HOME (set for the call, restored after; the real HOME is never looked at).
function inPrivateHome(fn) {
  const before = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-pl12-home-'));
  process.env.HOME = home;
  const classify = (command, options) => hook.classifyTool({ session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 't', cwd: home }, options);
  try { return fn(classify); } finally {
    if (before === undefined) delete process.env.HOME; else process.env.HOME = before;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// The control: a plain `ls`. Its keyless stdout is the answer every K1-shaped row must give.
async function plainAnswer(run, mode) {
  const plain = await run('ls', { mode });
  assert.deepEqual(answerOf(plain), LOCAL_ANSWER, `${mode}: a plain listing is a local read with no call`);
  return plain;
}

test('K1 real hook: a keyless listing of a credential folder answers as 3.9.114 (local, no call, a read in the loop guard) in all three keyless modes', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    for (const mode of KEYLESS_MODES) {
      const plain = await plainAnswer(run, mode);
      for (const [id, command] of Object.entries(K1_ROWS)) {
        const result = await run(command, { mode });
        assert.deepEqual(answerOf(result), LOCAL_ANSWER, `${mode} ${id}: answer as 3.9.114`);
        assert.equal(result.stdout, plain.stdout, `${mode} ${id}: stdout as the plain listing`);
      }
    }
  });
  // The same reading in process: no key (keyed false) is a read-only, low-risk listing.
  inPrivateHome((classify) => {
    for (const [id, command] of Object.entries(K1_ROWS)) {
      const keyless = classify(command, { keyed: false });
      assert.equal(keyless.readOnly, true, `${id}: keyless is read-only as 3.9.114`);
      assert.equal(keyless.risk, 'low', `${id}: keyless risk as 3.9.114`);
    }
  });
});

test('K2 real hook: with a key configured a credential-folder listing keeps the FX-3 reading (goes to the server, a mutation in the loop guard) as 3.9.115', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    const plain = await run('ls', { mode: 'keyed' });
    assert.deepEqual(keyedAnswerOf(plain), KEYED_LOCAL_ANSWER, 'keyed: a plain listing stays local, no runtime call');
    for (const [id, command] of Object.entries(K1_ROWS)) {
      const result = await run(command, { mode: 'keyed' });
      assert.deepEqual(keyedAnswerOf(result), FX3_ANSWER, `keyed ${id}: the FX-3 listing reading`);
      assert.notEqual(result.stdout, plain.stdout, `keyed ${id}: not the plain listing's stdout`);
    }
  });
  // In process, after the keyless readings of K1 ran in this process: the keyless reading never leaks into a keyed or PostToolUse call.
  inPrivateHome((classify) => {
    for (const [id, command] of Object.entries(K1_ROWS)) {
      classify(command, { keyed: false }); // the keyless reading runs first and is not asserted here (K1 does): only a leak out of it can fail the keyed rows
      assert.equal(classify(command, { keyed: true }).readOnly, false, `${id}: keyed is not read-only (FX-3)`);
      assert.equal(classify(command, { postTool: true }).readOnly, false, `${id}: PostToolUse (keyed not given) keeps the FX-3 reading`);
      assert.equal(classify(command, { keyed: true }).risk, 'medium', `${id}: keyed risk (FX-3)`);
    }
  });
});

// K3: event, tool-input and environment fields that claim a key. Only the hook's own key read counts; every claim changes nothing.
test('K3 real hook: forged fields that claim a key (event, tool input, environment) give the keyless answer of K1', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    const forged = () => {
      const claim = newDummyKey();
      return [
        ['event-fields', { eventExtra: { keyed: true, apiKey: claim, api_key: claim, marrow_api_key: claim, has_key: true, account: { keyed: true } } }],
        ['tool-input-fields', { toolInputExtra: { keyed: true, apiKey: claim, programs: ['ls'] } }],
        ['both', { eventExtra: { keyed: true, apiKey: claim }, toolInputExtra: { keyed: true, apiKey: claim, env: { MARROW_API_KEY: claim } } }],
        ['env-lookalikes', { envExtra: { MARROW_KEYED: '1', MARROW_API_KEY_SET: 'true' } }],
        ['empty-key-variable', { envExtra: { MARROW_API_KEY: '' } }],
      ];
    };
    for (const mode of KEYLESS_MODES) {
      const plain = await plainAnswer(run, mode);
      for (const [id, command] of Object.entries(K1_ROWS)) {
        for (const [claim, extra] of forged()) {
          const result = await run(command, { mode, ...extra });
          assert.deepEqual(answerOf(result), LOCAL_ANSWER, `${mode} ${id} (${claim}): answer as 3.9.114`);
          assert.equal(result.stdout, plain.stdout, `${mode} ${id} (${claim}): stdout as the plain listing`);
        }
      }
    }
  });
});

test('AB1 real hook: a symlinked credential folder answers as 3.9.114 (a folder that is a link: local; a link to a credential folder: stopped)', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    for (const mode of KEYLESS_MODES) {
      const plain = await plainAnswer(run, mode);
      // ~/.ssh is itself a link to a folder inside the private HOME: a local listing, as the plain K1 row.
      const into = await run('ls ~/.ssh', { mode, setup: (home) => { fs.mkdirSync(path.join(home, 'elsewhere')); fs.symlinkSync(path.join(home, 'elsewhere'), path.join(home, '.ssh')); } });
      assert.deepEqual(answerOf(into), LOCAL_ANSWER, `${mode} AB1-in: answer as 3.9.114`);
      assert.equal(into.stdout, plain.stdout, `${mode} AB1-in: stdout as the plain listing`);
      // ~/shortcut is a link to ~/.aws: stopped keyless as 3.9.114, with and without the trailing slash.
      for (const [id, command] of Object.entries({ 'AB1-out': 'ls ~/shortcut', 'AB1-out-slash': 'ls -la ~/shortcut/' })) {
        const out = await run(command, { mode, setup: (home) => { fs.mkdirSync(path.join(home, '.aws')); fs.symlinkSync(path.join(home, '.aws'), path.join(home, 'shortcut')); } });
        assert.deepEqual(answerOf(out), STOPPED_ANSWER, `${mode} ${id}: stopped as 3.9.114`);
      }
    }
  });
});

test('AB2 real hook: a credential-folder listing inside bash -c or sh -c is stopped keyless as 3.9.114', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    for (const mode of KEYLESS_MODES) {
      for (const [id, command] of Object.entries(AB2_ROWS)) {
        const result = await run(command, { mode });
        assert.deepEqual(answerOf(result), STOPPED_ANSWER, `${mode} ${id}: stopped as 3.9.114`);
      }
    }
  });
});

test('AB3 real hook: a credential-folder listing piped to another command answers as 3.9.114 (local, a read in the loop guard)', { skip: SKIP, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    for (const mode of KEYLESS_MODES) {
      const plain = await plainAnswer(run, mode);
      for (const [id, command] of Object.entries(AB3_ROWS)) {
        const result = await run(command, { mode });
        assert.deepEqual(answerOf(result), LOCAL_ANSWER, `${mode} ${id}: answer as 3.9.114`);
        assert.equal(result.stdout, plain.stdout, `${mode} ${id}: stdout as the plain listing`);
      }
    }
  });
});
