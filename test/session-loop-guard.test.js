const assert = require('node:assert/strict');
const {
  chmodSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  advanceSessionInstructionEpoch,
  clearSessionLoopGuard,
  consultSessionLoopGuard,
  recordSessionLoopOutcome,
  runSessionLoopGuardSelfTest,
  sessionLoopGuardEnabled,
  sessionLoopGuardPath,
  UnsafeLoopGuardStateError,
} = require('../dist/session-loop-guard.js');
const { localLoopGuardDenyOutput, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { runHookCommand } = require('../dist/hook.js');

function home() {
  return mkdtempSync(join(tmpdir(), 'marrow-loop-guard-'));
}

function operation(overrides = {}) {
  return {
    sessionId: 'session-one',
    agentId: 'agent-one',
    harness: 'codex',
    toolName: 'functions.exec',
    toolInput: { cmd: 'npm test', private: 'raw-secret-command' },
    readOnly: true,
    ...overrides,
  };
}

test('successful verification is denied on the next unchanged repeat without retaining raw data', () => {
  const root = home();
  try {
    const first = operation({ invocationId: 'tool-one' });
    assert.equal(consultSessionLoopGuard(first, { home: root }).allow, true);
    recordSessionLoopOutcome(operation({ invocationId: 'tool-one', toolInput: {} }), true, { output: 'raw-private-result' }, { home: root });
    const denied = consultSessionLoopGuard(operation({ invocationId: 'tool-two' }), { home: root });
    assert.equal(denied.allow, false);
    assert.match(denied.reason, /already passed.*Reuse the recorded result.*lgr_/i);
    const raw = readFileSync(sessionLoopGuardPath(root), 'utf8');
    assert.doesNotMatch(raw, /raw-secret-command|raw-private-result|npm test|tool-one|session-one|agent-one/);
    assert.equal(lstatSync(sessionLoopGuardPath(root)).mode & 0o777, 0o600);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('unchanged polls and failures allow two attempts and deny the third', () => {
  const root = home();
  try {
    const poll = operation({ toolInput: { cmd: 'git status' } });
    assert.equal(consultSessionLoopGuard({ ...poll, invocationId: 'poll-one' }, { home: root }).allow, true);
    recordSessionLoopOutcome({ ...poll, invocationId: 'poll-one', toolInput: {} }, true, { clean: true }, { home: root });
    assert.equal(consultSessionLoopGuard({ ...poll, invocationId: 'poll-two' }, { home: root }).allow, true);
    recordSessionLoopOutcome({ ...poll, invocationId: 'poll-two', toolInput: {} }, true, { clean: true }, { home: root });
    assert.equal(consultSessionLoopGuard({ ...poll, invocationId: 'poll-three' }, { home: root }).allow, false);

    const failed = operation({ toolInput: { cmd: 'npm run check' }, sessionId: 'failure-session' });
    assert.equal(consultSessionLoopGuard({ ...failed, invocationId: 'fail-one' }, { home: root }).allow, true);
    recordSessionLoopOutcome({ ...failed, invocationId: 'fail-one', toolInput: {} }, false, { code: 1 }, { home: root });
    assert.equal(consultSessionLoopGuard({ ...failed, invocationId: 'fail-two' }, { home: root }).allow, true);
    recordSessionLoopOutcome({ ...failed, invocationId: 'fail-two', toolInput: {} }, false, { code: 1 }, { home: root });
    const failureDenied = consultSessionLoopGuard({ ...failed, invocationId: 'fail-three' }, { home: root });
    assert.equal(failureDenied.allow, false);
    assert.match(failureDenied.reason, /already failed/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('successful mutation, new owner prompt, and session end reset only the isolated session', () => {
  const root = home();
  try {
    const verify = operation();
    consultSessionLoopGuard(verify, { home: root });
    recordSessionLoopOutcome(verify, true, { passed: true }, { home: root });
    assert.equal(consultSessionLoopGuard(verify, { home: root }).allow, false);

    const mutation = operation({ toolName: 'functions.apply_patch', toolInput: { patch: 'raw-patch' }, readOnly: false });
    assert.equal(consultSessionLoopGuard(mutation, { home: root }).allow, true);
    recordSessionLoopOutcome(mutation, true, { changed: true }, { home: root });
    assert.equal(consultSessionLoopGuard(verify, { home: root }).allow, true);
    recordSessionLoopOutcome(verify, true, { passed: true }, { home: root });
    assert.equal(consultSessionLoopGuard(verify, { home: root }).allow, false);

    advanceSessionInstructionEpoch(verify, { home: root });
    assert.equal(consultSessionLoopGuard(verify, { home: root }).allow, true);
    recordSessionLoopOutcome(verify, true, { passed: true }, { home: root });
    assert.equal(consultSessionLoopGuard(operation({ agentId: 'agent-two' }), { home: root }).allow, true);
    assert.equal(consultSessionLoopGuard(operation({ sessionId: 'session-two' }), { home: root }).allow, true);
    clearSessionLoopGuard(verify, { home: root });
    assert.equal(consultSessionLoopGuard(verify, { home: root }).allow, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('unsafe state paths and modes fail closed', () => {
  const root = home();
  try {
    consultSessionLoopGuard(operation(), { home: root });
    chmodSync(sessionLoopGuardPath(root), 0o644);
    assert.throws(() => consultSessionLoopGuard(operation(), { home: root }), UnsafeLoopGuardStateError);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  const linked = home();
  const target = home();
  try {
    mkdirSync(join(linked, '.marrow'), { mode: 0o700 });
    symlinkSync(target, join(linked, '.marrow', 'session-loop-guard'));
    assert.throws(() => consultSessionLoopGuard(operation(), { home: linked }), UnsafeLoopGuardStateError);
  } finally {
    rmSync(linked, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test('owner opt-outs and every supported host denial format stay explicit', () => {
  assert.equal(sessionLoopGuardEnabled('false', true), false);
  assert.equal(sessionLoopGuardEnabled('true', false), false);
  assert.equal(sessionLoopGuardEnabled(undefined, true), true);
  const reason = 'Operation already passed unchanged. Reuse the recorded result. Receipt: lgr_0123456789abcdef01234567.';
  assert.equal(localLoopGuardDenyOutput('cursor', reason).permission, 'deny');
  assert.equal(localLoopGuardDenyOutput('cline', reason).cancel, true);
  assert.equal(localLoopGuardDenyOutput('gemini', reason).decision, 'deny');
  assert.equal(localLoopGuardDenyOutput('grok', reason).decision, 'deny');
  for (const harness of ['claude-code', 'codex', 'mcp-client']) {
    assert.equal(localLoopGuardDenyOutput(harness, reason).hookSpecificOutput.permissionDecision, 'deny');
  }
  assert.equal(localLoopGuardDenyOutput('windsurf', reason), null);
});

test('routine read-only pre/post hooks stay local and offline self-test touches isolated state only', async () => {
  const root = home();
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    HOME: process.env.HOME,
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_AUTO_HOOK: process.env.MARROW_AUTO_HOOK,
  };
  let fetches = 0;
  let output = '';
  globalThis.fetch = async () => { fetches += 1; throw new Error('network must stay unused'); };
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  process.env.HOME = root;
  process.env.MARROW_API_KEY = 'synthetic-key';
  process.env.MARROW_AUTO_HOOK = 'true';
  const event = { session_id: 'read-session', tool_use_id: 'read-one', tool_name: 'functions.exec', tool_input: { cmd: 'git status' } };
  try {
    await runPreActionHookCommand(event);
    await runHookCommand({ ...event, hook_event_name: 'PostToolUse', success: true, tool_result: { clean: true } });
    assert.equal(fetches, 0);
    assert.deepEqual(JSON.parse(output), {});
    assert.deepEqual(runSessionLoopGuardSelfTest(), {
      pass: true,
      isolated: true,
      live_hook_observed: false,
      repeat_denied: true,
      mutation_reset: true,
      owner_disabled_bypass: true,
    });
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(root, { recursive: true, force: true });
  }
});

test('UserPromptSubmit advances the instruction epoch without credentials', () => {
  const root = home();
  try {
    const guarded = operation({ sessionId: 'prompt-session', agentId: undefined, harness: 'mcp-client' });
    consultSessionLoopGuard(guarded, { home: root });
    recordSessionLoopOutcome(guarded, true, { passed: true }, { home: root });
    assert.equal(consultSessionLoopGuard(guarded, { home: root }).allow, false);
    const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'context-hook'], {
      cwd: root,
      env: {
        ...process.env,
        HOME: root,
        MARROW_API_KEY: '',
        MARROW_KEY: '',
        MARROW_AGENT_ID: '',
        MARROW_FLEET_AGENT_ID: '',
        MARROW_AUTO_HOOK: 'true',
      },
      input: JSON.stringify({ session_id: 'prompt-session', prompt: 'Run the requested bounded check again.' }),
      encoding: 'utf8',
      timeout: 5_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {});
    assert.equal(consultSessionLoopGuard(guarded, { home: root }).allow, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a local denial emits one compact client-reported block marker and no raw operation data', async () => {
  const root = home();
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    HOME: process.env.HOME,
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AUTO_HOOK: process.env.MARROW_AUTO_HOOK,
  };
  const calls = [];
  let output = '';
  process.env.HOME = root;
  process.env.MARROW_API_KEY = 'synthetic-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AUTO_HOOK = 'true';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: JSON.parse(String(init.body || '{}')) });
    return Response.json({ data: { accepted: true } });
  };
  const rawSecret = 'customer-private-file-name';
  try {
    const first = { session_id: 'block-session', tool_use_id: 'read-one', tool_name: 'Read', tool_input: { path: rawSecret } };
    await runPreActionHookCommand(first);
    output = '';
    await runHookCommand({ ...first, hook_event_name: 'PostToolUse', tool_result: { content: 'private-result' }, success: true });
    await runPreActionHookCommand({ ...first, tool_use_id: 'read-two' });
    const denial = JSON.parse(output);
    assert.equal(denial.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(denial.hookSpecificOutput.permissionDecisionReason, /Reuse the recorded result.*lgr_/i);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].pathname, '/v1/agent/integrations/events');
    assert.equal(calls[0].body.event_type, 'pre_action_checked');
    assert.equal(calls[0].body.target, 'marrow:loop-guard');
    assert.equal(calls[0].body.intervention_disposition, 'followed');
    assert.equal(calls[0].body.action_changed, true);
    assert.equal(calls[0].body.source, 'client_self_reported');
    assert.ok(calls[0].body.session_id);
    assert.ok(calls[0].body.correlation_id);
    assert.doesNotMatch(JSON.stringify(calls), new RegExp(`${rawSecret}|private-result`));
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(root, { recursive: true, force: true });
  }
});

test('setup idempotently reports configured loop guard without claiming live enforcement', () => {
  const root = home();
  try {
    mkdirSync(join(root, '.claude'), { mode: 0o700 });
    const run = () => spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'setup'], {
      cwd: root,
      env: { ...process.env, HOME: root, MARROW_API_KEY: '', MARROW_KEY: '' },
      encoding: 'utf8',
      timeout: 8_000,
    });
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /Configured private local session loop guard/);
    assert.match(first.stdout, /does not prove enforcement/);
    const settingsPath = join(root, '.claude', 'settings.json');
    const settings = readFileSync(settingsPath, 'utf8');
    const second = run();
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /Configured private local session loop guard/);
    assert.equal(readFileSync(settingsPath, 'utf8'), settings);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('offline loop-guard CLI self-test is deterministic and leaves the supplied home untouched', () => {
  const root = home();
  try {
    const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'loop-guard-self-test'], {
      cwd: root,
      env: { ...process.env, HOME: root, MARROW_API_KEY: '', MARROW_KEY: '' },
      encoding: 'utf8',
      timeout: 5_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      pass: true,
      isolated: true,
      live_hook_observed: false,
      repeat_denied: true,
      mutation_reset: true,
      owner_disabled_bypass: true,
    });
    assert.equal(require('node:fs').existsSync(join(root, '.marrow')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
