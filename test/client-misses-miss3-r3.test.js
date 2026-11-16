'use strict';
// CLIENT-MISS3 round 3 (patch spec SPEC-patch-mcp-miss3-r2 section 3, main rulings X1 to X5 and V1 to V5). Rows: X1 (COLL-R3: an id
// inside backticks stays visible), X2 (an id after a bare `--` that follows the program or an operand stays visible; after an option it
// stays withheld), AB-R3 (a token-shaped value in a secret position never becomes visible), X3 (keyless listings answer as 3.9.114 in
// seatbelt, claimed_no_key and no-account-evidence modes; keyed and PostToolUse unchanged) and V1 (PL-6: an unknown wrapper option before
// the installer control disable keeps the control route and its hold). Expectations come from the 3.9.114 dist (BASE 48b1fbec80ab) and the
// spec, never from this branch. Ids, dummy secrets and dummy keys are generated at run time; no value is printed.
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
const norm = require(path.join(DIST, 'normalized-action.js'));
const routes = require(path.join(DIST, 'control-routes.js'));

const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
// An id: lower-case hex that starts with a letter (never read as a number or an option); 40 and 64 hex.
const newId = (bytes) => `a${hex(bytes).slice(1)}`;
// A dummy token-shaped value: a fixed non-key prefix letter plus run-time hex (hex holds no key-prefix letters).
const newSecret = (bytes) => `f${hex(bytes).slice(1)}`;
const SALT = crypto.randomBytes(32);
const NPX = 'npx -y @getmarrow/install control disable --yes';
const ROUTE_ACTION = 'classified Bash action: security on marrow-control';
const TIMEOUT = { timeout: 120000 };

function action(command, { off = false, cwd = '/w', toolInput = null } = {}) {
  const before = process.env.MARROW_HOOK_COMMAND_TEXT;
  if (off) process.env.MARROW_HOOK_COMMAND_TEXT = 'off'; else delete process.env.MARROW_HOOK_COMMAND_TEXT;
  try {
    const event = { session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: toolInput || { command }, tool_use_id: 't', cwd };
    const c = hook.classifyTool(event, { keyed: true });
    const na = norm.normalizedHookAction(event, { deadlineAt: Date.now() + 5000, sendCommandText: false, claudeCodeBash: true, salt: SALT });
    return { c, na };
  } finally {
    if (before === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = before;
  }
}

// X1 (COLL-R3): [template, programs on 3.9.114]; X is the id.
const X1_PAIRS = [
  ['echo `./deploy.sh X`', ['echo']],
  ['`./deploy.sh X`', ['deploy.sh']],
  ['echo `git show X`', ['echo']],
  ['echo $(echo `./deploy.sh X`)', ['echo']],
  ['npm test && echo `./deploy.sh X`', ['npm', 'echo']],
  ['echo `X`', ['echo']],
];
// X2: a bare `--` whose previous word is the program or an operand: the id is an operand.
const X2_PAIRS = [['./deploy.sh -- X', ['deploy.sh']], ['./deploy.sh --stage prod -- X', ['deploy.sh']], ['./deploy.sh prod -- `X`', ['deploy.sh']]];
// X2 withheld (the ruled exception): a bare `--` whose previous word is an option.
const X2_WITHHELD = ['./deploy.sh -k -- X', './deploy.sh --token -- X', './deploy.sh -p -- X', 'echo `./deploy.sh -k -- X`', 'echo `./deploy.sh -k X`', 'echo `-k X`'];

for (const bytes of [20, 32]) {
  test(`X1 COLL-R3 (${bytes * 2} hex): pairs that differ only in an id inside backticks get different keys, text on and off`, TIMEOUT, () => {
    for (const [template, programs] of X1_PAIRS) {
      const a = template.replace('X', newId(bytes));
      const b = template.replace('X', newId(bytes));
      for (const off of [false, true]) {
        const A = action(a, { off }).na;
        const B = action(b, { off }).na;
        assert.notEqual(A.tool_input.command_sha256, B.tool_input.command_sha256, `${template} (${off ? 'off' : 'on'}): command_sha256 differs`);
        assert.notEqual(A.tool_input.exact_hmac, B.tool_input.exact_hmac, `${template}: exact_hmac as START`);
        assert.deepEqual(A.programs, programs, `${template}: programs as 3.9.114`);
        if (!off) assert.equal(A.tool_input.command, a, `${template}: the text is sent as typed`);
        else assert.equal(A.tool_input.command, undefined, `${template}: text off sends no text`);
      }
    }
  });

  test(`X2 (${bytes * 2} hex): an id after a bare \`--\` that follows the program or an operand gets its own key`, TIMEOUT, () => {
    for (const [template, programs] of X2_PAIRS) {
      const a = template.replace('X', newId(bytes));
      const b = template.replace('X', newId(bytes));
      for (const off of [false, true]) {
        const A = action(a, { off }).na;
        const B = action(b, { off }).na;
        assert.notEqual(A.tool_input.command_sha256, B.tool_input.command_sha256, `${template} (${off ? 'off' : 'on'}): command_sha256 differs`);
        assert.deepEqual(A.programs, programs, `${template}: programs as 3.9.114`);
      }
    }
  });

  test(`X2 withheld (${bytes * 2} hex): after \`--\` that follows an option the word stays withheld (ruled exception)`, TIMEOUT, () => {
    for (const template of X2_WITHHELD) {
      const secretA = newSecret(bytes);
      const secretB = newSecret(bytes);
      for (const off of [false, true]) {
        const A = action(template.replace('X', secretA), { off }).na;
        const B = action(template.replace('X', secretB), { off }).na;
        assert.equal(A.tool_input.command_sha256, B.tool_input.command_sha256, `${template}: equal command_sha256 (withheld)`);
        assert.notEqual(A.tool_input.exact_hmac, B.tool_input.exact_hmac, `${template}: exact_hmac differs`);
        assert.equal(A.tool_input.command, undefined, `${template}: no text sent`);
        const all = JSON.stringify([A, B]);
        for (const secret of [secretA, secretB]) assert.ok(!all.includes(secret.slice(0, 8)) && !all.includes(secret.slice(-8)), `${template}: no slice of the value`);
      }
    }
  });

  test(`AB-R3 (${bytes * 2} hex): a token-shaped value in a secret position never becomes visible`, TIMEOUT, () => {
    const forms = ['./deploy.sh --token X', './deploy.sh -p X', './deploy.sh -k X', './deploy.sh --password X', './deploy.sh --key=X', './deploy.sh x=X',
      './deploy.sh token=X', 'TOKEN=X ./deploy.sh', 'A=X ./deploy.sh', 'export TOKEN=X; ./deploy.sh', 'env TOKEN=X ./deploy.sh', './deploy.sh -p -- X',
      './deploy.sh --token -- X', './deploy.sh -k -- X'];
    const wrapped = forms.flatMap((form) => [form, `echo \`${form}\``, `echo "$(${form})"`, `${form} # api token`, `\`${form}\` && echo password`]);
    for (const form of wrapped) {
      const secret = newSecret(bytes);
      for (const off of [false, true]) {
        const { na } = action(form.replace('X', secret), { off });
        const all = JSON.stringify(na);
        for (let i = 0; i + 8 <= secret.length; i += 1) assert.ok(!all.includes(secret.slice(i, i + 8)), `${form}: no 8-character slice of the value`);
      }
    }
  });
}

// ---------------------------------------------------------------------------------------------------------------------------
// The real hook entrypoint: dist/cli.js claude-pre-action-hook, event JSON on stdin, a private HOME per row (under a mkdtemp folder),
// a self-signed https loopback recorder; keyless modes: seatbelt (no account evidence), claimed_no_key (a Marrow folder under the
// private HOME) and no-account-evidence (MARROW_SEATBELT_STRICT=1, clean HOME).
// ---------------------------------------------------------------------------------------------------------------------------
let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }

async function withRecorder(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-miss3-r3-'));
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
  const run = async (command, { mode = 'keyed', toolInput = null, permissionMode = null } = {}) => {
    const home = fs.mkdtempSync(path.join(dir, 'home-'));
    if (mode === 'claimed') fs.mkdirSync(path.join(home, '.marrow', 'host-approvals'), { recursive: true, mode: 0o700 });
    const env = {
      PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: path.join(home, 'pw'), MARROW_AUTO_HOOK: 'true',
      MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`, NODE_EXTRA_CA_CERTS: path.join(dir, 'c.pem'),
      MARROW_AGENT_ID: 'agent-one', MARROW_SESSION_ID: 'session-one', MARROW_EVENT_SPOOL_PATH: path.join(home, 'spool.json'),
    };
    const key = `dummy-miss3-r3-${hex(12)}`;
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
      tool_input: toolInput || { command }, cwd: home, ...(permissionMode ? { permission_mode: permissionMode } : {}) }));
    const code = await new Promise((resolve) => child.on('close', resolve));
    const spool = fs.existsSync(env.MARROW_EVENT_SPOOL_PATH) ? fs.readFileSync(env.MARROW_EVENT_SPOOL_PATH, 'utf8') : '';
    assert.ok(!`${stdout}\n${stderr}\n${spool}\n${calls.map((call) => call.raw).join('\n')}`.includes(key), 'the dummy key is in no output, spool or request');
    const runtime = calls.find((call) => call.url === '/v1/agent/runtime');
    fs.rmSync(home, { recursive: true, force: true });
    return { code, stdout: stdout.split(home).join('<HOME>'), runtime: runtime ? JSON.parse(runtime.raw) : null, urls: calls.map((call) => call.url) };
  };
  try { return await fn(run); } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const decision = (stdout) => { try { return JSON.parse(stdout).hookSpecificOutput?.permissionDecision ?? 'none'; } catch { return stdout.trim() ? 'unparsed' : 'empty'; } };

// X3 rows whose keyless answer on 3.9.114 is the plain local listing's (no stop, no call) in all three modes.
const X3_LOCAL = {
  'B2-1': 'cd ~/.marrow/host-approvals; ls ~+',
  'B2-2': 'cd ~/.marrow/host-approvals && ls ~+',
  'B2-3': 'cd ~/.marrow; ls -la .',
  'B2-3-and': 'cd ~/.marrow && ls -la .',
  'B2-1-ls': 'cd ~/.marrow/host-approvals && ls',
  'P-1': 'ls ~/.marrow',
  'P-2': 'ls -la ~/.marrow/host-approvals',
  'P-3': 'ls ~/.marrow/credentials',
  'P-4': 'ls -la ~/.ssh',
  'P-5': 'find ~/.aws',
  'P-6': 'stat ~/.kube',
  'P-7': 'du -s ~/.docker',
  'P-9': 'ls ~/.config/gh',
};
// X3 rows that 3.9.114 stops keyless (subshell and bash -c twins, chains, variables): they stay stopped.
const X3_STOPPED = {
  'B2-1-sub': '(cd ~/.marrow/host-approvals; ls ~+)',
  'B2-2-sub': '(cd ~/.marrow/host-approvals && ls ~+)',
  'B2-3-sub': '(cd ~/.marrow; ls -la .)',
  'B2-1-bash': "bash -c 'cd ~/.marrow/host-approvals; ls ~+'",
  'B2-2-bash': "bash -c 'cd ~/.marrow/host-approvals && ls ~+'",
  'B2-3-bash': "bash -c 'cd ~/.marrow; ls -la .'",
  'P-8': 'tree ~/.gnupg',
  'C-2': 'ls ~/.marrow; rm -rf build',
  'V-1': 'D=~/.ssh; ls $D',
  'V-3': 'ls $(echo ~/.aws)',
};

test('X3 real hook: keyless listings answer as 3.9.114 in seatbelt, claimed_no_key and no-account-evidence modes (forged fields change nothing)', { skip: !opensslOk, timeout: 600000 }, async () => {
  await withRecorder(async (run) => {
    const forged = { keyed: true, apiKey: `dummy-forged-${hex(8)}`, programs: ['ls'] };
    for (const mode of ['seatbelt', 'claimed', 'strict']) {
      const local = await run('ls', { mode, permissionMode: 'auto' });
      assert.equal(decision(local.stdout), 'none', `${mode}: a plain listing is local`);
      for (const [id, command] of Object.entries(X3_LOCAL)) {
        for (const toolInput of [null, { command, ...forged }]) {
          const result = await run(command, { mode, toolInput, permissionMode: 'auto' });
          assert.equal(result.code, local.code, `${mode} ${id}: exit code as 3.9.114`);
          assert.equal(result.stdout, local.stdout, `${mode} ${id}${toolInput ? ' (forged fields)' : ''}: stdout as 3.9.114 (no stop)`);
          assert.deepEqual(result.urls, [], `${mode} ${id}: no network call`);
        }
      }
      for (const [id, command] of Object.entries(X3_STOPPED)) {
        const result = await run(command, { mode, permissionMode: 'auto' });
        assert.equal(decision(result.stdout), 'deny', `${mode} ${id}: stopped as 3.9.114`);
        assert.deepEqual(result.urls, [], `${mode} ${id}: no network call`);
      }
    }
  });
});

test('X3 keyed and PostToolUse: the FX-3 listing reading is kept (unchanged from the PR head)', { skip: !opensslOk, timeout: 300000 }, async () => {
  const event = (command) => ({ session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 't', cwd: os.homedir() });
  for (const command of [X3_LOCAL['B2-1'], X3_LOCAL['B2-2'], X3_LOCAL['B2-3']]) {
    assert.equal(hook.classifyTool(event(command), { keyed: true }).readOnly, false, 'keyed: a Marrow-state listing is not read-only');
    assert.equal(hook.classifyTool(event(command), { postTool: true }).readOnly, false, 'PostToolUse (keyed not given): as the PR head');
  }
  await withRecorder(async (run) => {
    for (const id of ['B2-1', 'B2-2', 'B2-3', 'B2-3-and']) {
      const result = await run(X3_LOCAL[id], { mode: 'keyed', permissionMode: 'auto' });
      assert.equal(decision(result.stdout), 'deny', `keyed ${id}: held as the PR head`);
    }
  });
});

// V1 (ruling V1, plant PL-6): an unknown wrapper option is unreadable, so the installer behind it keeps the control route and its hold.
const V1_ROWS = { 'V1-1': `env -Z VAL ${NPX}`, 'V1-2': `env --zz VAL ${NPX}`, 'V1-3': `sudo -Q VAL ${NPX}`, 'V1-4': `timeout -Q VAL 5 ${NPX}` };

test('V1 PL-6 rows: env, sudo and timeout with an unknown option before the installer control disable stay on the control route, held', { skip: !opensslOk, timeout: 300000 }, async () => {
  for (const [id, command] of Object.entries(V1_ROWS)) assert.equal(routes.controlRoute(command), true, `${id}: control route`);
  await withRecorder(async (run) => {
    const bare = await run(NPX);
    assert.equal(bare.runtime?.action, ROUTE_ACTION);
    for (const [id, command] of Object.entries(V1_ROWS)) {
      const result = await run(command);
      assert.equal(result.runtime?.action, ROUTE_ACTION, `${id}: security on marrow-control`);
      assert.equal(result.runtime.risk_level, bare.runtime.risk_level, id);
      assert.equal(decision(result.stdout), decision(bare.stdout), `${id}: held as without the prefix`);
    }
  });
});
