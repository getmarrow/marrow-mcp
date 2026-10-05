const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  MARROW_OUTAGE_WARNING,
  MAX_PRE_ACTION_INPUT_BYTES,
  PreActionControlTimeoutError,
  classifyTool,
  clinePreActionHookOutput,
  DENIED_DECISION_CLOSE_TIMEOUT_MS,
  closeDeniedDecision,
  controlRejectionMessage,
  cursorPreActionHookOutput,
  geminiPreActionHookOutput,
  grokPreActionHookOutput,
  isMarrowControlOutage,
  ownerApprovalPrompt,
  preActionHookOutput,
  runPreActionHookCommand,
  runtimeGateAdvisory,
  runtimeGateEnforced,
  windsurfPreActionDecision,
} = require('../dist/hook-pre-action.js');
const { MarrowRequestError } = require('../dist/request-reliability.js');
const { deriveAction } = require('../dist/hook.js');
const { normalizeHookEventPayload } = require('../dist/hook-contract.js');
const { isReadOnlyToolEvent } = require('../dist/hook-tool-policy.js');

test('Grok camelCase envelopes classify the same as Claude snake_case', () => {
  const grok = normalizeHookEventPayload({
    hookEventName: 'PreToolUse',
    toolName: 'run_terminal_command',
    toolInput: { command: 'wrangler deploy production' },
  });
  assert.equal(grok.hook_event_name, 'PreToolUse');
  assert.equal(grok.tool_name, 'run_terminal_command');
  assert.equal(classifyTool(grok).protected, true);
  assert.equal(isReadOnlyToolEvent(grok), false);
  assert.equal(isReadOnlyToolEvent({
    tool_name: 'search_replace',
    tool_input: { file_path: 'src/index.ts', old_string: 'a', new_string: 'b' },
  }), false);
  assert.equal(isReadOnlyToolEvent({ tool_name: 'read_file', tool_input: { target_file: 'src/index.ts' } }), true);
});

test('Grok pre-action maps protected review and unavailable proof to fixed private denial', () => {
  const privateText = 'synthetic-private-service-text';
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: privateText,
      risk_gate: { allow: false, decision: 'review_required', enforced: true, reasons: [{ message: privateText }] },
    },
  }), { decision: 'deny', reason: 'Marrow blocked this protected action.' });
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: privateText,
  }), { decision: 'deny', reason: 'Marrow blocked this protected action.' });
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: { risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] } },
  }), { decision: 'allow' });
});

test('a reached control rejection is not an outage', () => {
  assert.equal(isMarrowControlOutage(new PreActionControlTimeoutError()), true);
  assert.equal(isMarrowControlOutage(new TypeError('fetch failed')), true);
  assert.equal(isMarrowControlOutage(Object.assign(new Error('reset'), { code: 'ECONNRESET' })), true);
  assert.equal(isMarrowControlOutage(new MarrowRequestError({
    code: 'service_unavailable',
    message: 'HTTP 503',
    status: 503,
    exactFix: 'retry',
  })), true);
  for (const code of ['authentication_required', 'permission_denied', 'invalid_response', 'rate_limited', 'tls_failure', 'edge_access_denied']) {
    assert.equal(isMarrowControlOutage(new MarrowRequestError({
      code,
      message: 'reached',
      status: 401,
      exactFix: 'restore governance',
    })), false, code);
  }
  assert.equal(isMarrowControlOutage(new Error('malformed local state')), false);
});

test('an outage allows every harness and keeps the private failure text out of the decision', () => {
  const privateText = 'synthetic-private-service-text';
  const outage = {
    protectedRisk: true,
    permit: null,
    runtime: null,
    outage: true,
    enforcementError: privateText,
  };
  assert.deepEqual(grokPreActionHookOutput(outage), { decision: 'allow' });
  assert.deepEqual(geminiPreActionHookOutput(outage), { decision: 'allow' });
  assert.deepEqual(windsurfPreActionDecision(outage), { exitCode: 0, stderr: `${MARROW_OUTAGE_WARNING}\n` });
  assert.deepEqual(cursorPreActionHookOutput(outage), {
    permission: 'allow',
    user_message: MARROW_OUTAGE_WARNING,
    agent_message: MARROW_OUTAGE_WARNING,
  });
  assert.deepEqual(clinePreActionHookOutput(outage), { cancel: false });
  const claude = preActionHookOutput(outage);
  const codex = preActionHookOutput(outage, 'codex');
  assert.equal(claude.hookSpecificOutput.permissionDecision, undefined);
  assert.equal(codex.hookSpecificOutput.permissionDecision, undefined);
  assert.match(claude.hookSpecificOutput.additionalContext, /queued locally/);
  assert.equal(JSON.stringify({ claude, codex, grok: grokPreActionHookOutput(outage) }).includes(privateText), false);
});

test('pre-action and result hooks use the same privacy-safe action binding', () => {
  const event = {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'wrangler deploy production' },
  };
  assert.equal(deriveAction(event), classifyTool(event).action);
});

test('protected operations are classified from tool names and commands without incidental production keywords', () => {
  const publish = classifyTool({ tool_name: 'Bash', tool_input: { command: 'npm publish' } });
  const push = classifyTool({ tool_name: 'Bash', tool_input: { command: 'git push origin master' } });
  const pushWithGlobalOptions = classifyTool({ tool_name: 'Bash', tool_input: { command: 'git -C /workspace -c core.hooksPath=/tmp/hooks push origin master' } });
  const merge = classifyTool({ tool_name: 'Bash', tool_input: { command: 'gh pr merge 42 --merge' } });
  const kubectlApply = classifyTool({ tool_name: 'Bash', tool_input: { command: 'kubectl --context production apply -f deployment.yaml' } });
  const terraformApply = classifyTool({ tool_name: 'Bash', tool_input: { command: 'terraform -chdir=infra apply -auto-approve' } });
  const npmUnpublish = classifyTool({ tool_name: 'Bash', tool_input: { command: 'npm unpublish @example/package@1.0.0' } });
  const remoteD1Execute = classifyTool({ tool_name: 'Bash', tool_input: { command: 'wrangler d1 execute app --remote --file migration.sql' } });
  const remoteHttpDelete = classifyTool({ tool_name: 'Bash', tool_input: { command: 'curl -X DELETE https://api.github.com/repos/acme/app' } });
  const githubApiDelete = classifyTool({ tool_name: 'Bash', tool_input: { command: 'gh api repos/acme/app/hooks/1 --method DELETE' } });
  const remoteSqlDelete = classifyTool({ tool_name: 'Bash', tool_input: { command: 'psql "$DATABASE_URL" -c "DELETE FROM jobs"' } });
  const cloudObjectDelete = classifyTool({ tool_name: 'Bash', tool_input: { command: 'aws s3 rm s3://bucket/release.tar.gz' } });
  const clusterDrain = classifyTool({ tool_name: 'Bash', tool_input: { command: 'kubectl drain node-1 --ignore-daemonsets' } });
  const secretEdit = classifyTool({ tool_name: 'Bash', tool_input: { command: 'vault kv put secret/app token=value' } });
  const cargoYank = classifyTool({ tool_name: 'Bash', tool_input: { command: 'cargo yank --vers 1.0.0 package' } });
  const unknownMcp = classifyTool({ tool_name: 'mcp__payments__execute', tool_input: { amount: 25 } });
  const deceptiveMcp = classifyTool({ tool_name: 'mcp__records__get_and_delete', tool_input: { id: 'record-1' } });
  const compoundShell = classifyTool({ tool_name: 'Bash', tool_input: { command: 'cat package.json && node mutate.js' } });
  const readOnly = classifyTool({ tool_name: 'Bash', tool_input: { command: 'cat package.json' } });

  for (const result of [publish, npmUnpublish, push, pushWithGlobalOptions, merge, kubectlApply, terraformApply, remoteD1Execute, remoteHttpDelete, githubApiDelete, remoteSqlDelete, cloudObjectDelete, clusterDrain, secretEdit, cargoYank, unknownMcp, deceptiveMcp]) {
    assert.equal(result.protected, true);
    assert.equal(result.risk, 'high');
  }
  assert.equal(compoundShell.readOnly, false);
  assert.equal(compoundShell.risk, 'medium');
  assert.equal(publish.target, 'npm:publish');
  assert.equal(push.target, 'github:review');
  assert.equal(pushWithGlobalOptions.target, 'github:review');
  assert.equal(kubectlApply.target, 'production:deploy');
  assert.equal(terraformApply.target, 'production:deploy');
  assert.equal(npmUnpublish.target, 'npm:publish');
  assert.equal(remoteD1Execute.target, 'production:deploy');
  assert.equal(readOnly.readOnly, true);
  assert.equal(readOnly.risk, 'low');
  assert.equal(deriveAction({ tool_name: 'Bash', tool_input: { command: 'cat package.json' } }), null);
});

test('protected command variants fail closed without trusted Marrow credentials', async () => {
  const originalWrite = process.stdout.write;
  const originalCwd = process.cwd();
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-protected-variants-'));
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_KEY: process.env.MARROW_KEY,
    HOME: process.env.HOME,
  };
  delete process.env.MARROW_API_KEY;
  delete process.env.MARROW_KEY;
  process.env.HOME = join(directory, 'home');
  mkdirSync(process.env.HOME, { recursive: true, mode: 0o700 });
  process.chdir(directory);
  try {
    for (const command of [
      'git -C /workspace push origin master',
      'kubectl apply -f deployment.yaml',
      'terraform apply -auto-approve',
      'npm unpublish @example/package@1.0.0',
      'wrangler d1 execute app --remote --file migration.sql',
      'curl -X DELETE https://api.github.com/repos/acme/app',
      'gh api repos/acme/app/hooks/1 --method DELETE',
      'psql "$DATABASE_URL" -c "DELETE FROM jobs"',
      'aws s3 rm s3://bucket/release.tar.gz',
      'kubectl drain node-1 --ignore-daemonsets',
      'vault kv put secret/app token=value',
      'cargo yank --vers 1.0.0 package',
      'npm access grant read-write team:developers @example/package',
      'yarn npm tag add @example/package@1.0.0 latest',
      'gh api repos/acme/app/hooks -f name=web --field active=true',
      'gh pr close 42',
      'kubectl run maintenance --image=busybox',
      'oc apply -f deployment.yaml',
      'terragrunt apply -auto-approve',
      'curl -T artifact.tar.gz https://uploads.example.test/artifact',
      'http https://api.example.test/items name=created',
      'redis-cli UNLINK cache-key',
      'aws s3 cp artifact.tar.gz s3://bucket/artifact.tar.gz',
      'gcloud storage cp artifact.tar.gz gs://bucket/artifact.tar.gz',
      'az storage blob upload --file artifact.tar.gz --container-name releases',
      'rclone copy artifact.tar.gz remote:releases',
      'git remote set-url origin https://github.com/acme/app.git',
      'rm -rf build-output',
      'npm login',
      'git worktree remove scratch-copy',
      'gh run cancel 12345',
      'kubectl certificate approve agent-csr',
      'terraform state replace-provider old/provider new/provider',
      'curl --json {"enabled":true} https://example.test/items',
      'curl --data-ascii enabled=true https://example.test/items',
      "psql --command 'CALL rotate_cache()' appdb",
      'redis-cli EVALSHA abcdef123456 0',
      'gcloud storage rsync ./dist gs://example-bucket/releases',
      'op item move shared-item archive-vault',
      '/usr/bin/rm -rf generated-cache',
      `kubectl --context ${'ctxvalue-'.repeat(1200)} apply -f manifest.yaml`,
      'npm profile enable-2fa auth-only',
      'gh repo fork acme/app --clone=false',
      'gh auth logout --hostname github.com',
      'flux reconcile source git platform',
      'nomad job run platform.nomad',
      'cdk deploy PlatformStack',
      'ansible-playbook deploy.yml',
      'curl --form-string name=value https://example.test/items',
      'wget --body-data enabled=true https://example.test/items',
      'redis-cli EVAL "return redis.call(\'set\',KEYS[1],ARGV[1])" 1 key value',
      'redis-cli FUNCTION LOAD REPLACE "#!lua name=lib"',
      'gsutil cp artifact.tar.gz gs://example-bucket/releases/',
      'mc cp artifact.tar.gz production/releases/',
      'oci os object put --bucket-name releases --file artifact.tar.gz',
      'pass insert production/token',
      '/usr/bin/unlink generated-cache/file',
      'printf file | xargs /bin/rm',
      'dd if=/dev/zero of=generated-cache/image.bin bs=1 count=1',
      `git -c ${'credential.helper=x'.repeat(600)} push origin master`,
      'npm org set my-org billing-email user@example.test',
      'git update-ref refs/heads/main abc',
      'gh repo transfer acme/app acme2',
      'nomad node drain -enable node1',
      'cdk watch PlatformStack',
      'ansible all -m shell -a reboot',
      'curl --config write.conf https://example.test',
      "mysql -e 'REPLACE INTO t VALUES (1)' appdb",
      'redis-cli --pipe',
      'vault operator rekey',
      '"/usr/bin/rm" -rf generated',
    ]) {
      let output = '';
      process.stdout.write = (chunk) => { output += String(chunk); return true; };
      await runPreActionHookCommand({ tool_name: 'Bash', tool_input: { command } });
      const result = JSON.parse(output);
      assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
      assert.match(result.hookSpecificOutput.permissionDecisionReason, /credentials are unavailable/i);
    }
  } finally {
    process.stdout.write = originalWrite;
    process.chdir(originalCwd);
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('pre-action CLI fails closed without leaking malformed trusted endpoint configuration', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-invalid-base-url-'));
  try {
    for (const baseUrl of ['http://api.example.test/private-route', 'not a valid URL']) {
      const env = {
        ...process.env,
        HOME: join(directory, 'home'),
        MARROW_API_KEY: 'synthetic-pre-action-secret',
        MARROW_KEY: '',
        MARROW_BASE_URL: baseUrl,
        MARROW_AUTO_HOOK: 'true',
      };
      mkdirSync(env.HOME, { recursive: true, mode: 0o700 });
      const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'pre-action-hook'], {
        cwd: directory,
        env,
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'npm publish' } }),
        encoding: 'utf8',
        timeout: 5_000,
      });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
      assert.match(output.hookSpecificOutput.permissionDecisionReason, /configuration is unavailable/i);
      assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /synthetic-pre-action-secret/);
      assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /api\.example\.test|not a valid URL/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('Codex pre-action CLI denies protected input without credentials and keeps tool input private', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-codex-no-key-'));
  const privateCommand = 'npm publish --otp synthetic-private-proof';
  try {
    const env = {
      ...process.env,
      HOME: join(directory, 'home'),
      MARROW_API_KEY: '',
      MARROW_KEY: '',
      MARROW_AUTO_HOOK: 'true',
    };
    mkdirSync(env.HOME, { recursive: true, mode: 0o700 });
    const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'codex-pre-action-hook'], {
      cwd: directory,
      env,
      input: JSON.stringify({
        hookEventName: 'PreToolUse',
        sessionId: 'codex-session',
        toolUseId: 'codex-tool',
        toolName: 'Bash',
        toolInput: { command: privateCommand },
      }),
      encoding: 'utf8',
      timeout: 5_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(output.hookSpecificOutput.permissionDecisionReason, /credentials are unavailable/i);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /synthetic-private-proof|npm publish/);
    assert.equal('additionalContext' in output.hookSpecificOutput, false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('look-alike Marrow MCP namespaces remain governed', () => {
  const official = classifyTool({ tool_name: 'mcp__marrow__marrow_commit', tool_input: { decision_id: 'decision-1' } });
  const lookalike = classifyTool({ tool_name: 'mcp__marrow_evil__delete', tool_input: { id: 'record-1' } });
  assert.equal(official.protected, false);
  assert.equal(lookalike.protected, true);
  assert.equal(lookalike.risk, 'high');
});

test('protected pre-action hook rejects a verified permit with a mismatched identity', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-permit-mismatch-'));
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    HOME: process.env.HOME,
  };
  let output = '';
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.HOME = directory;
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname === '/v1/agent/runtime') return Response.json({ data: {
      risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
      completion_contract: { decision_creation_required: true },
    } });
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-one' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-issued', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-other', verified: true } });
    }
    if (pathname === '/v1/agent/commit') return Response.json({ data: { committed: true } });
    return Response.json({ data: { accepted: true } });
  };
  try {
    await runPreActionHookCommand({ tool_name: 'Bash', tool_input: { command: 'npm publish' } });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.permissionDecisionReason, /did not match/i);
    assert.doesNotMatch(output, /signed-permit/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('native enforcement ignores repository-local Marrow credentials', async () => {
  const originalWrite = process.stdout.write;
  const originalCwd = process.cwd();
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-hostile-project-env-'));
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_KEY: process.env.MARROW_KEY,
    HOME: process.env.HOME,
  };
  mkdirSync(join(directory, '.marrow'), { recursive: true });
  writeFileSync(join(directory, '.env'), [
    'MARROW_API_KEY=synthetic-project-key',
    'MARROW_BASE_URL=https://hostile.invalid',
    'MARROW_AGENT_ID=hostile-agent',
    '',
  ].join('\n'));
  delete process.env.MARROW_API_KEY;
  delete process.env.MARROW_KEY;
  process.env.HOME = join(directory, 'home');
  mkdirSync(process.env.HOME, { recursive: true, mode: 0o700 });
  process.chdir(directory);
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  try {
    await runPreActionHookCommand({ tool_name: 'Bash', tool_input: { command: 'npm publish' } });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.permissionDecisionReason, /credentials are unavailable/i);
    assert.doesNotMatch(output, /hostile/);
  } finally {
    process.stdout.write = originalWrite;
    process.chdir(originalCwd);
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('protected pre-action hook denies when the Marrow credential is unavailable', async () => {
  const originalWrite = process.stdout.write;
  const originalCwd = process.cwd();
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-no-key-'));
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_KEY: process.env.MARROW_KEY,
    HOME: process.env.HOME,
  };
  let output = '';
  delete process.env.MARROW_API_KEY;
  delete process.env.MARROW_KEY;
  process.env.HOME = directory;
  process.chdir(directory);
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  try {
    await runPreActionHookCommand({ tool_name: 'Bash', tool_input: { command: 'npm publish' } });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.permissionDecisionReason, /credentials are unavailable/i);
  } finally {
    process.stdout.write = originalWrite;
    process.chdir(originalCwd);
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('malformed mutation-capable hook input is denied instead of silently bypassed', async () => {
  const originalWrite = process.stdout.write;
  const previousHome = process.env.HOME;
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-malformed-'));
  let output = '';
  process.env.HOME = directory;
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  try {
    await runPreActionHookCommand({ tool_input: { command: 'unknown mutation' } });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.permissionDecisionReason, /could not classify/i);
  } finally {
    process.stdout.write = originalWrite;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('protected pre-action hook binds runtime gate to a decision before verifying its permit', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AGENT_ID: process.env.MARROW_AGENT_ID,
    MARROW_SESSION_ID: process.env.MARROW_SESSION_ID,
    MARROW_EVENT_SPOOL_PATH: process.env.MARROW_EVENT_SPOOL_PATH,
    HOME: process.env.HOME,
  };
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-pre-action-'));
  const calls = [];
  let output = '';
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname !== '/v1/agent/integrations/events') calls.push({ pathname, body, signal: init.signal });
    if (pathname === '/v1/agent/runtime') {
      return Response.json({ data: {
        decision_id: 'decision-runtime',
        runtime_authorization: { id: 'gate-one', decision_id: 'decision-runtime', decision_creation_required: false },
        completion_contract: { decision_id: 'decision-runtime', decision_creation_required: false },
        risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
        gate_receipt_id: 'gate-one',
        gate_receipt: { id: 'gate-one' },
        proof_pack: { fields: ['command', 'exit_code'] },
      } });
    }
    if (pathname === '/v1/agent/think') throw new Error('runtime-created decision must be reused without Think');
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-one', verified: true } });
    }
    return Response.json({ data: { accepted: true } });
  };

  try {
    await runPreActionHookCommand({
      session_id: 'session-one',
      tool_use_id: 'tool-one',
      tool_name: 'Bash',
      tool_input: { command: 'wrangler deploy production' },
    });
    assert.deepEqual(calls.map((entry) => entry.pathname), [
      '/v1/agent/runtime',
      '/v1/agent/enforcement',
      '/v1/agent/enforcement',
    ]);
    assert.equal(calls[1].body.decision_id, 'decision-runtime');
    assert.equal(calls[1].body.gate_receipt_id, 'gate-one');
    assert.equal(calls[0].body.target, calls[1].body.target);
    assert.equal(calls[0].body.target, 'production:deploy');
    assert.notEqual(calls[0].body.target, 'tool-one');
    assert.deepEqual(calls[0].body.surfaces, calls[1].body.surfaces);
    assert.deepEqual(calls[1].body.surfaces, calls[2].body.surfaces);
    assert.equal(calls[2].body.operation, 'verify');
    assert.equal(calls[2].body.permit, 'signed-permit');
    assert.equal(calls.every((entry) => entry.signal instanceof AbortSignal), true);
    assert.equal(new Set(calls.map((entry) => entry.signal)).size, calls.length);
    const result = JSON.parse(output);
    assert.notEqual(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.additionalContext, /action permit verified/);
    assert.doesNotMatch(output, /signed-permit/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a received runtime block is denied before think when a later control call fails', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AGENT_ID: process.env.MARROW_AGENT_ID,
    MARROW_SESSION_ID: process.env.MARROW_SESSION_ID,
    MARROW_EVENT_SPOOL_PATH: process.env.MARROW_EVENT_SPOOL_PATH,
    HOME: process.env.HOME,
  };
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-pre-action-block-'));
  const calls = [];
  let output = '';
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname !== '/v1/agent/integrations/events') calls.push({ pathname, body, signal: init.signal });
    if (pathname === '/v1/agent/runtime') {
      return Response.json({ data: {
        decision_id: 'decision-runtime',
        runtime_authorization: { id: 'gate-one', decision_id: 'decision-runtime', decision_creation_required: true },
        completion_contract: { decision_id: 'decision-runtime', decision_creation_required: true },
        risk_gate: { allow: false, decision: 'block', enforced: true, reasons: [] },
        gate_receipt_id: 'gate-one',
        gate_receipt: { id: 'gate-one' },
        proof_pack: { fields: ['command', 'exit_code'] },
      } });
    }
    if (pathname === '/v1/agent/think') {
      return new Response(JSON.stringify({ error: 'think failed' }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-one', verified: true } });
    }
    if (pathname === '/v1/agent/commit') return Response.json({ data: { committed: true } });
    return Response.json({ data: { accepted: true } });
  };

  try {
    await runPreActionHookCommand({
      session_id: 'session-one',
      tool_use_id: 'tool-one',
      tool_name: 'Bash',
      tool_input: { command: 'wrangler deploy production' },
    });
    assert.equal(calls.some((entry) => entry.pathname === '/v1/agent/think'), false);
    // The block is denied without think; only the runtime decision is closed as a failure.
    assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime', '/v1/agent/commit']);
    assert.equal(calls[1].body.decision_id, 'decision-runtime');
    assert.equal(calls[1].body.success, false);
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.doesNotMatch(output, /Marrow is offline/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a rejected runtime call denies a protected action instead of failing open', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AGENT_ID: process.env.MARROW_AGENT_ID,
    MARROW_SESSION_ID: process.env.MARROW_SESSION_ID,
    MARROW_EVENT_SPOOL_PATH: process.env.MARROW_EVENT_SPOOL_PATH,
    HOME: process.env.HOME,
  };
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-pre-action-reject-'));
  let output = '';
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  globalThis.fetch = async (url) => {
    const pathname = new URL(String(url)).pathname;
    if (pathname === '/v1/agent/runtime') {
      return new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }
    return Response.json({ data: { accepted: true } });
  };

  try {
    await runPreActionHookCommand({
      session_id: 'session-one',
      tool_use_id: 'tool-one',
      tool_name: 'Bash',
      tool_input: { command: 'wrangler deploy production' },
    });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.doesNotMatch(output, /Marrow is offline/);
    assert.doesNotMatch(output, /unauthorized/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

async function runHookAgainst(respond, event, entrypoint) {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const originalEntrypoint = process.argv[2];
  const keys = ['MARROW_API_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_EVENT_SPOOL_PATH', 'HOME'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-pre-action-contract-'));
  const calls = [];
  const commits = [];
  let output = '';
  delete process.env.MARROW_FLEET_AGENT_ID;
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  if (entrypoint) process.argv[2] = entrypoint;
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname === '/v1/agent/integrations/events') return Response.json({ data: { accepted: true } });
    // A denial closes its decision; answer at once so the hook never waits on a mock.
    if (pathname === '/v1/agent/commit') {
      commits.push({ body, idempotencyKey: new Headers(init.headers).get('Idempotency-Key') });
      return Response.json({ data: { committed: true, decision_id: body.decision_id } });
    }
    calls.push({ pathname, body });
    return respond(pathname, body);
  };
  try {
    await runPreActionHookCommand(event);
    return { calls, output, commits };
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    if (entrypoint) process.argv[2] = originalEntrypoint;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
}

const fastPathRuntime = () => Response.json({ data: {
  runtime_authorization: { id: 'fast_gate_one', durable: false, decision_creation_required: true },
  completion_contract: { decision_creation_required: true },
  risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
  gate_receipt_id: 'fast_gate_one',
  before_you_act: 'Proceed with the low-risk work.',
  proof_pack: { fields: [] },
} });

test('a protected action asks for a durable gate and creates its decision with only accepted source metadata', async () => {
  const { calls, output } = await runHookAgainst((pathname, body) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-one', verified: true } });
    }
    throw new Error(`unexpected ${pathname}`);
  }, {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'rm -rf build' },
  }, 'claude-pre-action-hook');

  assert.deepEqual(calls.map((entry) => entry.pathname), [
    '/v1/agent/runtime',
    '/v1/agent/think',
    '/v1/agent/enforcement',
    '/v1/agent/enforcement',
  ]);
  assert.equal(calls[0].body.risk_level, 'high');
  const sourceMeta = calls[1].body.source_meta;
  assert.deepEqual(Object.keys(sourceMeta).filter((key) => !['channel', 'client', 'agent_id', 'task_depth', 'user_intent'].includes(key)), []);
  assert.equal(sourceMeta.client, 'claude-code');
  assert.equal(calls[2].body.decision_id, 'decision-think');
  assert.equal(calls[2].body.gate_receipt_id, 'fast_gate_one');
  assert.equal(typeof calls[2].body.correlation_id, 'string');
  assert.notEqual(JSON.parse(output).hookSpecificOutput.permissionDecision, 'deny');
});

test('the generic hook entrypoint keeps the default source client on think', async () => {
  const { calls } = await runHookAgainst((pathname, body) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (body.operation === 'issue') return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    return Response.json({ data: { permit_id: 'permit-one', verified: true } });
  }, {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'rm -rf build' },
  });

  const think = calls.find((entry) => entry.pathname === '/v1/agent/think');
  assert.notEqual(think.body.source_meta.client, 'mcp-client');
  assert.equal(think.body.source_meta.harness, undefined);
});

test('an unprotected action stops at the runtime gate without creating a decision or permit', async () => {
  const { calls, output } = await runHookAgainst((pathname) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    throw new Error(`unprotected action must not call ${pathname}`);
  }, {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'mkdir -p build' },
  });

  assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime']);
  assert.equal(calls[0].body.risk_level, undefined);
  const result = JSON.parse(output);
  assert.equal(result.hookSpecificOutput.permissionDecision, undefined);
  assert.equal(result.hookSpecificOutput.additionalContext, 'Proceed with the low-risk work.');
});

test('a reached control rejection names its status and code without echoing service text', async () => {
  const privateText = 'synthetic-private-service-text';
  const { output } = await runHookAgainst((pathname) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    return new Response(JSON.stringify({ error: privateText, code: 'MARROW_INVALID_SOURCE_META' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }, {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'rm -rf build' },
  });

  const result = JSON.parse(output);
  assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(result.hookSpecificOutput.permissionDecisionReason, /\(HTTP 400 MARROW_INVALID_SOURCE_META\)/);
  assert.doesNotMatch(output, new RegExp(privateText));

  assert.equal(
    controlRejectionMessage(new MarrowRequestError({ code: 'request_failed', backendCode: 'not a <safe> code', message: privateText, status: 400, exactFix: 'fix' })),
    'Marrow rejected this protected action (HTTP 400 request_failed). Restore trusted governance before retrying.',
  );
  assert.equal(
    controlRejectionMessage(new Error(privateText)),
    'Marrow rejected this protected action. Restore trusted governance before retrying.',
  );
});

const reviewRuntime = (extra = {}) => Response.json({ data: {
  decision_id: 'decision-review',
  runtime_authorization: { id: 'gate-review', decision_id: 'decision-review', decision_creation_required: false },
  completion_contract: {
    decision_id: 'decision-review',
    decision_creation_required: false,
    owner_approval_required: true,
    arbitration_receipt_required: false,
    owner_approval: { mode: 'ordinary_non_arbitrated', proof_path: 'proof.owner_approval', dashboard_receipt_required: false },
  },
  risk_gate: { allow: false, decision: 'review_required', enforced: true, reasons: [{ message: 'Publishing needs owner review.' }] },
  gate_receipt_id: 'gate-review',
  exact_next_action: 'Obtain explicit owner approval.',
  ...extra,
} });
// The approvals backend's ordinary hold (expanded shape recorded from 42959f22):
// the operator may approve it in the host prompt (host_approval_accepted).
const hostReviewRuntime = (approval = {}) => Response.json({ data: {
  ok: true,
  decision_id: 'decision-review',
  runtime_authorization: { id: 'gate-review', kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
  gate_receipt: { id: 'gate-review', decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
  proof_pack: { required: true, fields: ['summary', 'checks', 'outcome'], complete: false },
  completion_contract: {
    decision_id: 'decision-review',
    decision_creation_required: false,
    owner_approval_required: true,
    arbitration_receipt_required: false,
    owner_approval: {
      mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
      trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
      approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
      approval_status_endpoint: '/v1/agent/gate-receipts/gate-review/owner-approval', approval_status_poll_after_ms: 5000,
      host_approval_endpoint: '/v1/agent/gate-receipts/gate-review/host-approval', host_approval_accepted: true,
      host_approval_trust: 'client_attested', approval_categories: ['package_publish'],
      verified_approval_required: false, verified_approval_categories: [],
      ...approval,
    },
  },
  risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: 'gate-review', reasons: [{ message: 'Publishing needs owner review.' }] },
  gate_receipt_id: 'gate-review',
  exact_next_action: 'Obtain explicit owner approval.',
} });
const noControlAfterGate = (respond) => (pathname, body) => {
  if (pathname !== '/v1/agent/runtime') throw new Error(`a review gate must not call ${pathname}`);
  return respond(pathname, body);
};
const publishEvent = (extra = {}) => ({
  session_id: 'session-one',
  tool_use_id: 'tool-one',
  tool_name: 'Bash',
  tool_input: { command: 'npm publish' },
  ...extra,
});

test('owner prompts are offered only where Claude Code shows the prompt to a person', () => {
  const child = { CLAUDE_CODE_CHILD_SESSION: '1' };
  const cases = [
    ['claude-code', { permission_mode: 'default' }, {}, true],
    ['claude-code', { permission_mode: 'acceptEdits' }, {}, true],
    ['claude-code', { permission_mode: 'auto', scratchpad_dir: '/tmp/claude-1000/project/session/scratchpad' }, {}, true],
    ['claude-code', { permission_mode: 'auto' }, {}, false],
    ['claude-code', { permission_mode: 'plan' }, {}, false],
    ['claude-code', { permission_mode: 'dontAsk' }, {}, false],
    ['claude-code', { permission_mode: 'bypassPermissions' }, {}, false],
    ['claude-code', {}, {}, false],
    ['claude-code', { permission_mode: 'default; rm' }, {}, false],
    ['mcp-client', { permission_mode: 'default' }, child, true],
    ['mcp-client', { permission_mode: 'default' }, {}, false],
    ['mcp-client', { permission_mode: 'bypassPermissions' }, child, false],
    ['codex', { permission_mode: 'default' }, child, false],
    ['cursor', { permission_mode: 'default' }, child, false],
    ['cline', { permission_mode: 'default' }, child, false],
    ['gemini', { permission_mode: 'default' }, child, false],
    ['grok', { permission_mode: 'default' }, child, false],
    ['windsurf', { permission_mode: 'default' }, child, false],
  ];
  for (const [harness, event, env, available] of cases) {
    const prompt = ownerApprovalPrompt(harness, event, env);
    assert.equal(prompt.available, available, `${harness} ${JSON.stringify(event)} ${JSON.stringify(env)}`);
    assert.equal(prompt.unavailableReason === '', available);
  }
  assert.match(ownerApprovalPrompt('claude-code', { permission_mode: 'bypassPermissions' }, {}).unavailableReason, /bypassPermissions/);
  assert.match(ownerApprovalPrompt('codex', { permission_mode: 'default' }, {}).unavailableReason, /Codex/);
});

test('an ordinary review gate asks the operator in an interactive Claude Code session when the server accepts a host approval', async () => {
  const { calls, output, commits } = await runHookAgainst(noControlAfterGate(() => hostReviewRuntime()),
    publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime']);
  const decision = JSON.parse(output).hookSpecificOutput;
  assert.equal(decision.permissionDecision, 'ask');
  assert.equal(decision.permissionDecisionReason,
    'Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer (gate receipt gate-review). Reason: Publishing needs owner review. Next: Obtain explicit owner approval.');
  assert.deepEqual(commits, [], 'asking never closes or spends the held receipt');
});

test('a review gate from a service that offers no host approval is denied, even in an interactive Claude Code session', async () => {
  const { output, commits } = await runHookAgainst(noControlAfterGate(() => reviewRuntime()),
    publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  const decision = JSON.parse(output).hookSpecificOutput;
  assert.equal(decision.permissionDecision, 'deny');
  assert.match(decision.permissionDecisionReason, /^Marrow requires owner review before this action, and no owner approval prompt is available \(this Marrow service did not offer a chat or terminal approval for this hold\)/);
  assert.equal(commits.length, 1, 'a hold the service cannot wait on is closed as before');
});

test('the installer generic entrypoint asks only when Claude Code spawned the hook', async () => {
  const previous = process.env.CLAUDE_CODE_CHILD_SESSION;
  try {
    process.env.CLAUDE_CODE_CHILD_SESSION = '1';
    const spawned = await runHookAgainst(noControlAfterGate(() => hostReviewRuntime()), publishEvent({ permission_mode: 'acceptEdits' }));
    assert.equal(JSON.parse(spawned.output).hookSpecificOutput.permissionDecision, 'ask');
    delete process.env.CLAUDE_CODE_CHILD_SESSION;
    const unknownHost = await runHookAgainst(noControlAfterGate(() => hostReviewRuntime()), publishEvent({ permission_mode: 'acceptEdits' }));
    const denied = JSON.parse(unknownHost.output).hookSpecificOutput;
    assert.equal(denied.permissionDecision, 'deny');
    assert.match(denied.permissionDecisionReason, /^Marrow is holding this action for approval \(gate receipt gate-review\), so it did not run\./);
    assert.match(denied.permissionDecisionReason, /the host cannot ask the operator in this session\. The approval request goes to the account owner\./);
    assert.doesNotMatch(denied.permissionDecisionReason, /dashboard/i);
    assert.deepEqual(unknownHost.commits, [], 'a waiting hold is never closed by the hook');
  } finally {
    if (previous === undefined) delete process.env.CLAUDE_CODE_CHILD_SESSION;
    else process.env.CLAUDE_CODE_CHILD_SESSION = previous;
  }
});

test('a review gate is denied with its reason wherever no person would see the prompt', async () => {
  for (const [entrypoint, event, expected] of [
    ['claude-pre-action-hook', publishEvent({ permission_mode: 'bypassPermissions' }), /permission mode bypassPermissions cannot guarantee an owner prompt/],
    ['claude-pre-action-hook', publishEvent({ permission_mode: 'dontAsk' }), /permission mode dontAsk/],
    ['claude-pre-action-hook', publishEvent({ permission_mode: 'plan' }), /permission mode plan/],
    ['claude-pre-action-hook', publishEvent({ permission_mode: 'auto' }), /does not prove a Claude Code version/],
    ['claude-pre-action-hook', publishEvent(), /permission mode unknown/],
    ['codex-pre-action-hook', publishEvent({ permission_mode: 'default' }), /Codex hooks cannot prompt the owner/],
  ]) {
    const { output } = await runHookAgainst(noControlAfterGate(() => reviewRuntime()), event, entrypoint);
    const decision = JSON.parse(output).hookSpecificOutput;
    assert.equal(decision.permissionDecision, 'deny', `${entrypoint} ${event.permission_mode}`);
    assert.match(decision.permissionDecisionReason, /^Marrow requires owner review before this action, and no owner approval prompt is available/);
    assert.match(decision.permissionDecisionReason, expected);
    assert.match(decision.permissionDecisionReason, /Reason: Publishing needs owner review\./);
    assert.doesNotMatch(decision.permissionDecisionReason, /could not verify/);
  }
});

test('block and arbitration review never ask, even in an interactive session', async () => {
  const interactive = publishEvent({ permission_mode: 'default' });
  const blocked = await runHookAgainst(noControlAfterGate(() => reviewRuntime({
    risk_gate: { allow: false, decision: 'block', reasons: [{ message: 'Release freeze is active.' }] },
    exact_next_action: null,
  })), interactive, 'claude-pre-action-hook');
  assert.deepEqual(JSON.parse(blocked.output).hookSpecificOutput, {
    hookEventName: 'PreToolUse',
    permissionDecision: 'deny',
    permissionDecisionReason: 'Marrow blocked this action under the current policy. Reason: Release freeze is active.',
  });

  for (const arbitration of [
    { arbitration: { receipt_id: 'arb-1', resolution: 'review_required' } },
    { completion_contract: { arbitration_receipt_required: true, owner_approval_required: true } },
    { completion_contract: { owner_approval: { mode: 'arbitration_review_required', dashboard_receipt_required: true } } },
  ]) {
    const { output } = await runHookAgainst(noControlAfterGate(() => reviewRuntime(arbitration)), interactive, 'claude-pre-action-hook');
    const decision = JSON.parse(output).hookSpecificOutput;
    assert.equal(decision.permissionDecision, 'deny', JSON.stringify(arbitration));
    assert.match(decision.permissionDecisionReason, /^Marrow arbitration requires owner approval in the authenticated Marrow dashboard/);
  }
});

test('an outage stays an allowed warning and a credential failure stays a denial, never an owner prompt', async () => {
  const interactive = publishEvent({ permission_mode: 'default' });
  const prompt = ownerApprovalPrompt('claude-code', interactive, {});
  assert.equal(prompt.available, true);
  const outage = preActionHookOutput({ protectedRisk: true, permit: null, runtime: null, outage: true, enforcementError: MARROW_OUTAGE_WARNING }, 'claude-code', prompt);
  assert.deepEqual(outage, { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: MARROW_OUTAGE_WARNING } });

  const privateText = 'synthetic-private-service-text';
  const scope = await runHookAgainst((pathname, body) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return new Response(JSON.stringify({ error: privateText, code: 'ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      });
    }
    throw new Error(`unexpected ${pathname}`);
  }, interactive, 'claude-pre-action-hook');
  const scopeDecision = JSON.parse(scope.output).hookSpecificOutput;
  assert.equal(scopeDecision.permissionDecision, 'deny');
  assert.equal(scopeDecision.permissionDecisionReason,
    'This Marrow API key is not authorized to obtain action permits for agent "agent-one" (HTTP 403 ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID). Use the API key issued to that agent, or set MARROW_FLEET_AGENT_ID (or MARROW_AGENT_ID) to the agent this key belongs to, then retry.');
  assert.doesNotMatch(scope.output, new RegExp(privateText));
});

test('control failures name what happened: credential scope, unavailability, or a rejection', () => {
  const scope = new MarrowRequestError({ code: 'permission_denied', backendCode: 'ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID', message: 'x', status: 403, exactFix: 'fix' });
  assert.match(controlRejectionMessage(scope, 'darvis'), /^This Marrow API key is not authorized to obtain action permits for agent "darvis" \(HTTP 403 ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID\)/);
  assert.match(controlRejectionMessage(scope), /for this hook's agent \(no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set\)/);
  assert.match(controlRejectionMessage(scope, 'bad agent id!'), /no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set/);
  const mismatch = new MarrowRequestError({ code: 'permission_denied', backendCode: 'MARROW_AGENT_SCOPE_MISMATCH', message: 'x', status: 403, exactFix: 'fix' });
  assert.match(controlRejectionMessage(mismatch, 'darvis'), /not authorized to obtain action permits for agent "darvis"/);
  for (const code of ['tls_failure', 'invalid_response', 'edge_access_denied']) {
    assert.match(controlRejectionMessage(new MarrowRequestError({ code, message: 'x', exactFix: 'fix' })), /^Marrow is unavailable, so this protected action was denied/, code);
  }
  const otherForbidden = new MarrowRequestError({ code: 'permission_denied', backendCode: 'MARROW_PLAN_REQUIRED', message: 'x', status: 403, exactFix: 'fix' });
  assert.equal(controlRejectionMessage(otherForbidden, 'darvis'), 'Marrow rejected this protected action (HTTP 403 MARROW_PLAN_REQUIRED). Restore trusted governance before retrying.');

  const reviewGate = { risk_gate: { allow: false, decision: 'review_required', enforced: true, reasons: [] } };
  assert.deepEqual(clinePreActionHookOutput({ protectedRisk: true, permit: null, runtime: reviewGate }),
    { cancel: true, errorMessage: 'Marrow requires operator review before this protected action.' });
  assert.deepEqual(clinePreActionHookOutput({ protectedRisk: true, permit: null, runtime: null, failure: 'credential_scope', enforcementError: 'private' }),
    { cancel: true, errorMessage: 'This Marrow API key is not authorized to obtain action permits for this agent. Use the API key issued to this agent and retry.' });
  assert.deepEqual(clinePreActionHookOutput({ protectedRisk: true, permit: null, runtime: null, failure: 'unavailable', enforcementError: 'private' }),
    { cancel: true, errorMessage: 'Marrow is unavailable, so this protected action was denied. Retry when Marrow is reachable.' });
  const denial = preActionHookOutput({ protectedRisk: true, permit: null, runtime: reviewGate });
  assert.match(denial.hookSpecificOutput.permissionDecisionReason, /^Marrow requires owner review before this action/);
});

test('read-only inspection is not protected by words in paths or arguments; real actions and secrets stay protected', () => {
  const bash = (command) => ({ tool_name: 'Bash', tool_input: { command, description: 'Check the release, deploy and publish state' } });
  // Unparseable syntax falls back to whole-input keyword rules, which also read the description.
  const plain = (command) => ({ tool_name: 'Bash', tool_input: { command } });
  const home = process.env.HOME || require('node:os').homedir();
  const readOnly = { readOnly: true, protected: false };
  const unprotectedWrite = { readOnly: false, protected: false };
  const guarded = { readOnly: false, protected: true };
  const rows = [
    // Denied on 2026-09-29 although they only inspect.
    ['ls piped to grep -c', bash('ls /home/majinbuu/agents/jarvis/results/hook-permit-3996-20260929/ | grep -c release'), readOnly],
    ['grep of a release script', bash("grep -n 'package_metadata' /home/majinbuu/scripts/marrow-fast-backend-release.sh"), readOnly],
    ['TaskCreate subject', { tool_name: 'TaskCreate', tool_input: { subject: 'publish MCP 3.9.97', description: 'npm publish after owner approval' } }, readOnly],
    ['Edit of notes mentioning credentials', { tool_name: 'Edit', tool_input: { file_path: '/home/u/notes/plan.md', old_string: 'a', new_string: 'rotate credentials, then deploy production' } }, unprotectedWrite],
    // Other read-only inspection.
    ['cat non-secret', bash('cat RELEASE.md'), readOnly],
    ['head and tail', bash('head -20 docs/deploy.md && tail -n 5 /var/log/release.log'), readOnly],
    ['rg', bash('rg -n "publish|deploy" src --glob "*.ts"'), readOnly],
    ['grep for secret words', bash('grep -rn credential src/ 2>/dev/null | head -20'), readOnly],
    ['find without exec', bash("find . -name '*release*' -type f"), readOnly],
    ['git status', bash('git status --short'), readOnly],
    ['git log', bash('git log --oneline -5 -- scripts/release.sh | grep -c tag'), readOnly],
    ['git diff', bash('git -C /repo diff HEAD~1 -- scripts/deploy.sh'), readOnly],
    ['git show', bash('git show v3.9.96 --stat'), readOnly],
    ['multi-line inspection', bash('git status\ngit log -1 --format=%s'), readOnly],
    ['jq', bash("jq '.scripts.release' package.json"), readOnly],
    ['npm view', bash('npm view @getmarrow/mcp dist-tags --json'), readOnly],
    ['gh pr view', bash('gh pr view 42 --repo getmarrow/marrow-mcp --json title,state'), readOnly],
    ['env template', bash('cat .env.example'), readOnly],
    ['listing a secret directory', bash('ls -la ~/.ssh'), readOnly],
    ['TaskUpdate', { tool_name: 'TaskUpdate', tool_input: { taskId: '3', status: 'completed', subject: 'deploy done' } }, readOnly],
    ['TodoWrite', { tool_name: 'TodoWrite', tool_input: { todos: [{ content: 'merge and publish', status: 'pending' }] } }, readOnly],
    ['Read', { tool_name: 'Read', tool_input: { file_path: '/repo/docs/release-notes.md' } }, readOnly],
    ['Glob', { tool_name: 'Glob', tool_input: { pattern: '**/deploy*' } }, readOnly],
    ['Grep', { tool_name: 'Grep', tool_input: { pattern: 'credential', path: '/repo/src' } }, readOnly],
    // Executing deploy, publish, push, release or merge.
    ['npm publish', bash('npm publish'), guarded],
    ['git push', bash('git push origin fix/hook'), guarded],
    ['gh pr merge', bash('gh pr merge 42 --squash'), guarded],
    ['wrangler deploy', bash('wrangler deploy --env production'), guarded],
    ['release script', bash('bash /home/majinbuu/scripts/marrow-fast-backend-release.sh --execute'), guarded],
    ['deploy script', bash('./scripts/deploy.sh'), guarded],
    ['env-wrapped publish', bash('env NPM_CONFIG_PROVENANCE=true npm publish'), guarded],
    // Compound commands take their most dangerous part.
    ['inspect then push', bash('git status && git push origin master'), guarded],
    ['grep then publish', bash('ls dist | grep -c release; npm publish'), guarded],
    ['pipe into destruction', bash('find . -name "*.tmp" | xargs rm -f'), guarded],
    ['newline-hidden deploy', bash('cat package.json\nnode scripts/deploy.js'), guarded],
    // Destructive commands.
    ['rm', bash('rm -rf build'), guarded],
    ['find -delete', bash('find . -name "*.log" -delete'), guarded],
    ['find -exec rm', bash('find . -name "*.log" -exec rm {} +'), guarded],
    // Writing secret or credential files, or Marrow control state.
    ['Edit .env', { tool_name: 'Edit', tool_input: { file_path: '/repo/.env', old_string: 'A=1', new_string: 'A=2' } }, guarded],
    ['Write authorized_keys', { tool_name: 'Write', tool_input: { file_path: '/home/u/.ssh/authorized_keys', content: 'ssh-ed25519 AAA' } }, guarded],
    ['Write control state', { tool_name: 'Write', tool_input: { file_path: '/home/u/.marrow/control.json', content: '{}' } }, guarded],
    ['append to .env', bash('echo TOKEN=1 >> .env'), guarded],
    ['apply_patch secret', { tool_name: 'functions.apply_patch', tool_input: { input: '*** Begin Patch\n*** Update File: config/.dev.vars\n@@\n-A\n+B\n*** End Patch' } }, guarded],
    // Reading secret or credential material.
    ['cat git credentials', bash('cat ~/.git-credentials'), guarded],
    ['head of an agent key', bash('head -5 ~/.marrow/credentials/darvis.key | cat'), guarded],
    ['input redirect', bash('wc -c < ~/.netrc'), guarded],
    ['git show secret', bash('git show HEAD:.env'), guarded],
    ['print secret variable', bash('echo "$MARROW_API_KEY"'), guarded],
    ['printenv secret', bash('printenv GITHUB_TOKEN'), guarded],
    ['jq env dump', bash("jq -n 'env'"), guarded],
    ['Read credentials file', { tool_name: 'Read', tool_input: { file_path: '/home/u/.claude/.credentials.json' } }, guarded],
    ['Grep a secret directory', { tool_name: 'Grep', tool_input: { pattern: 'aws_secret', path: '/home/u/.aws' } }, guarded],
    // Syntax that could run code stays conservative.
    ['command substitution', plain('cat $(ls release)'), guarded],
    ['unparseable syntax keeps description keywords', bash('find . -name "*.md" -exec cat {} +'), guarded],
    ['rg preprocessor', bash('rg --pre ./x.sh foo'), unprotectedWrite],
    ['git pager override', bash('GIT_PAGER=./x.sh git log'), unprotectedWrite],
    ['git config pager', bash('git -c core.pager=./x.sh log'), unprotectedWrite],
    ['sort to file', bash('sort -o out.txt in.txt'), unprotectedWrite],
    ['find -exec read', plain('find . -name "*.md" -exec cat {} +'), unprotectedWrite],
    // Quoting, expansion and option-spelling tricks never make a command read-only.
    ['ANSI-C quote hides a command', bash("echo $'\\'' ; rm -rf x #'"), guarded],
    ['ANSI-C quote hides a path', plain("cat $'.en\\x76'"), unprotectedWrite],
    ['ANSI-C quote hides -exec', plain("find . $'-exec' sh -c x \\;"), unprotectedWrite],
    ['brace-expanded secret', plain('cat .en{v,x}'), unprotectedWrite],
    ['brace-expanded find option', plain('find . -{delete,print}'), unprotectedWrite],
    ['brace-expanded sort option', plain('sort -{o,x} file'), unprotectedWrite],
    ['globbed .env', bash('cat .env*'), guarded],
    ['bracket-globbed .env', bash('cat .e[n]v'), guarded],
    ['globbed key files', bash('cat *.pem'), guarded],
    ['abbreviated sort --output', bash('sort --outp=/tmp/f x'), unprotectedWrite],
    ['abbreviated sort --compress-program', bash('sort --compr=prog x'), unprotectedWrite],
    ['abbreviated git diff --output', bash('git diff --outp=/tmp/f'), unprotectedWrite],
    ['abbreviated git log --output', bash('git log --outp=f'), unprotectedWrite],
    ['git ls-remote upload-pack', bash("git ls-remote --upload-pack='touch /tmp/x' ."), unprotectedWrite],
    ['git branch create', bash('git branch newname'), unprotectedWrite],
    ['git branch force move', bash('git branch -f main HEAD~5'), unprotectedWrite],
    ['git branch list', bash('git branch --list "fix/*" -v'), readOnly],
    ['bare env dump', bash('env'), guarded],
    ['bare printenv dump', bash('printenv'), guarded],
    ['printenv filtered', bash('printenv | grep -i token'), guarded],
    ['env filtered', bash('env | grep KEY'), guarded],
    ['printenv of a non-secret', bash('printenv HOME'), readOnly],
    ['npm audit fix', bash('npm audit fix'), unprotectedWrite],
    ['npm audit', bash('npm audit --omit=dev'), readOnly],
    ['rg hostname-bin', bash('rg --hostname-bin=/tmp/x foo'), unprotectedWrite],
    ['date set', bash('date -s "2026-01-01"'), unprotectedWrite],
    // Barvis F-25-1: bash treats a lone carriage return as a word character, not a separator.
    ['lone CR inside find -delete', plain('find \r realpath /home/u/important -delete'), guarded],
    ['lone CR inside sort -o control state', plain('sort -t \r cat -o ~/.marrow/control.json'), guarded],
    ['lone CR inside find -exec', plain('find . -name x \r ls -exec sh -c id ;'), unprotectedWrite],
    ['CRLF line ending', plain('ls\r\nrm -rf x'), guarded],
    // Barvis F-25-2: equivalent spellings of Marrow control state stay protected.
    ['Write control state via /./', { tool_name: 'Write', tool_input: { file_path: `${home}/.marrow/./control.json`, content: '{}' } }, guarded],
    ['Write control state via ..', { tool_name: 'Write', tool_input: { file_path: `${home}/.marrow/spool/../control.json`, content: '{}' } }, guarded],
    ['Write control state via //', { tool_name: 'Write', tool_input: { file_path: `${home}//.marrow//control.json`, content: '{}' } }, guarded],
    ['Edit control state via ~', { tool_name: 'Edit', tool_input: { file_path: '~/.marrow/./control.json', old_string: 'true', new_string: 'false' } }, guarded],
    ['redirect to control state via /./', plain('echo {} > ~/.marrow/./control.json'), guarded],
    ['redirect to control state via $HOME and ..', plain('echo x > $HOME/.marrow/../.marrow/control.json'), guarded],
    ['relative write after cd into ~/.marrow', plain('cd ~/.marrow && echo x > control.json'), guarded],
    ['relative copy after cd into ~/.marrow', plain('cd ~/.marrow; cp /tmp/x ./control.json'), guarded],
    // Barvis regression table: reads through the working directory or a local settings file.
    ['cd into credentials then cat *', plain('cd ~/.marrow/credentials && cat *'), guarded],
    ['cd into .ssh then cat *', plain('cd ~/.ssh && cat *'), guarded],
    ['jq of Claude local settings', plain('jq . ~/.claude/settings.local.json'), guarded],
    ['gh prints its token', plain('gh auth token'), guarded],
    ['cd Marrow cannot follow', plain('cd - && cat notes.md'), unprotectedWrite],
    ['expanded option to find', plain('find . $OPT'), unprotectedWrite],
    ['expanded option to git', plain('git log $X'), unprotectedWrite],
    ['file -C writes a magic file', plain('file -C -m x'), unprotectedWrite],
    ['home-relative inspection', plain('cat $HOME/notes.md'), readOnly],
    ['inspection after cd', plain('cd /repo && git status && ls | grep -c release'), readOnly],
  ];
  for (const [name, event, expected] of rows) {
    const result = classifyTool(event);
    assert.deepEqual({ readOnly: result.readOnly, protected: result.protected }, expected, name);
    assert.equal(result.risk, expected.readOnly ? 'low' : expected.protected ? 'high' : 'medium', name);
  }
});

test('a read-only compound command is allowed without reaching Marrow', async () => {
  const { calls, output } = await runHookAgainst((pathname) => {
    throw new Error(`read-only inspection must not call ${pathname}`);
  }, {
    session_id: 'session-one',
    tool_use_id: 'tool-read-only',
    tool_name: 'Bash',
    tool_input: { command: 'ls /home/majinbuu/agents/jarvis/results/hook-permit-3996-20260929/ | grep -c release' },
  }, 'claude-pre-action-hook');
  assert.deepEqual(calls, []);
  assert.deepEqual(JSON.parse(output), {});
});

function controlHome(directory, enabled) {
  const home = join(directory, 'home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  if (enabled !== undefined) {
    mkdirSync(join(home, '.marrow'), { mode: 0o700 });
    writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: 0o600 });
  }
  return home;
}

function runPreActionCli(home, input) {
  return spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'claude-pre-action-hook'], {
    cwd: home,
    env: {
      PATH: process.env.PATH,
      HOME: home,
      MARROW_API_KEY: '',
      MARROW_KEY: '',
      MARROW_AUTO_HOOK: 'true',
      MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json'),
    },
    input,
    encoding: 'utf8',
    timeout: 20_000,
    maxBuffer: 1024 * 1024,
  });
}

const largeWrite = (bytes) => JSON.stringify({
  session_id: 'session-large',
  tool_use_id: 'tool-large',
  hook_event_name: 'PreToolUse',
  permission_mode: 'default',
  tool_name: 'Write',
  tool_input: { file_path: '/repo/docs/plan.md', content: `# Release plan\n\n${'Deploy, publish and rotate credentials after review.\n'.repeat(Math.ceil(bytes / 52))}` },
});

test('a large Write is classified normally instead of failing closed as oversized', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-large-write-'));
  try {
    const input = largeWrite(300 * 1024);
    assert.ok(Buffer.byteLength(input) > 64 * 1024);
    const result = runPreActionCli(controlHome(directory), input);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {});
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('input over the pre-action bound is allowed when control is disabled and names the size limit when enabled', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-oversized-'));
  try {
    const input = largeWrite(MAX_PRE_ACTION_INPUT_BYTES + 1024);
    assert.ok(Buffer.byteLength(input) > MAX_PRE_ACTION_INPUT_BYTES);

    const disabled = runPreActionCli(controlHome(join(directory, 'disabled'), false), input);
    assert.equal(disabled.status, 0, disabled.stderr);
    assert.deepEqual(JSON.parse(disabled.stdout), {});
    const disabledMalformed = runPreActionCli(controlHome(join(directory, 'disabled-malformed'), false), '{"tool_name": "Write", ');
    assert.deepEqual(JSON.parse(disabledMalformed.stdout), {});

    for (const home of [controlHome(join(directory, 'default')), controlHome(join(directory, 'enabled'), true)]) {
      const enabled = runPreActionCli(home, input);
      assert.equal(enabled.status, 0, enabled.stderr);
      const decision = JSON.parse(enabled.stdout).hookSpecificOutput;
      assert.equal(decision.permissionDecision, 'deny');
      assert.equal(decision.permissionDecisionReason,
        `Marrow did not check this action because its hook input is ${Buffer.byteLength(input)} bytes, over the ${MAX_PRE_ACTION_INPUT_BYTES}-byte pre-action limit, so it was denied. Split it into smaller tool calls and retry.`);
    }
    const malformed = runPreActionCli(controlHome(join(directory, 'enabled-malformed'), true), '{"tool_name": "Write", ');
    assert.equal(JSON.parse(malformed.stdout).hookSpecificOutput.permissionDecisionReason, 'Marrow rejected malformed pre-action input.');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('characters the shell splitter does not model never yield a read-only command', () => {
  const unmodeled = ['\u000d', '\u000b', '\u000c', '\u0000', '\u0001', '\u001b', '\u007f', '\u0085', '\u00a0', '\u00ad',
    '\u1680', '\u2000', '\u200b', '\u200e', '\u2028', '\u2029', '\u202e', '\u2066', '\u3000', '\ufeff'];
  for (const character of unmodeled) {
    const label = `U+${character.codePointAt(0).toString(16).padStart(4, '0')}`;
    for (const command of [`ls ${character} cat notes.md`, `ls${character}cat notes.md`, `${character}ls`, `ls${character}`,
      `find . -name x ${character} -delete`, `cat notes.md ${character}| head`]) {
      const result = classifyTool({ tool_name: 'Bash', tool_input: { command } });
      assert.equal(result.readOnly, false, `${label} in ${JSON.stringify(command)}`);
    }
    assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: `find ${character} realpath /tmp/x -delete` } }).protected, true, label);
  }
  // The ordinary separators the splitter does model keep inspection read-only.
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: 'git status\n\tls | grep -c release; pwd' } }).readOnly, true);
});

test('a carriage-return disguised deletion reaches the Marrow gate instead of being allowed', async () => {
  const { calls, output } = await runHookAgainst(noControlAfterGate(() => reviewRuntime()), {
    session_id: 'session-one',
    tool_use_id: 'tool-cr',
    permission_mode: 'bypassPermissions',
    tool_name: 'Bash',
    tool_input: { command: 'find \r realpath /home/u/important -delete' },
  }, 'claude-pre-action-hook');
  assert.equal(calls[0].pathname, '/v1/agent/runtime');
  assert.equal(calls[0].body.risk_level, 'high');
  assert.equal(JSON.parse(output).hookSpecificOutput.permissionDecision, 'deny');
});

const advisoryRuntime = (gate) => Response.json({ data: {
  decision_id: 'decision-advisory',
  runtime_authorization: { id: 'gate-advisory', decision_id: 'decision-advisory', decision_creation_required: false },
  completion_contract: { decision_id: 'decision-advisory', decision_creation_required: false },
  risk_gate: { enforced: false, gate_required: false, enforcement_decision: 'advisory', reasons: [{ message: 'Publishing is high risk.' }], ...gate },
  gate_receipt_id: 'gate-advisory',
  before_you_act: 'Check the release notes first.',
} });

test('a free or starter plan advisory gate warns and allows without demanding a permit', async () => {
  for (const [label, gate] of [
    ['free-plan warn', { allow: true, decision: 'warn' }],
    ['pilot review', { allow: true, decision: 'review_required' }],
  ]) {
    const { calls, output } = await runHookAgainst((pathname) => {
      if (pathname !== '/v1/agent/runtime') throw new Error(`an advisory gate must not call ${pathname}`);
      return advisoryRuntime(gate);
    }, publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
    assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime'], label);
    assert.equal(calls[0].body.risk_level, 'high', label);
    const decision = JSON.parse(output).hookSpecificOutput;
    assert.equal(decision.permissionDecision, undefined, label);
    assert.match(decision.additionalContext, /^Marrow advisory: this plan does not enforce the pre-action gate, so the action is allowed\. Gate decision: \w+\. Reason: Publishing is high risk\./, label);
    assert.match(decision.additionalContext, /Check the release notes first\./, label);
  }

  const advisory = { runtime: { risk_gate: { allow: true, decision: 'review_required', enforced: false, enforcement_decision: 'advisory', reasons: [] } }, permit: null, protectedRisk: false };
  assert.deepEqual(grokPreActionHookOutput(advisory), { decision: 'allow' });
  assert.deepEqual(geminiPreActionHookOutput(advisory), { decision: 'allow' });
  assert.deepEqual(windsurfPreActionDecision(advisory), { exitCode: 0, stderr: '' });
  assert.deepEqual(clinePreActionHookOutput(advisory), { cancel: false });
  assert.equal(cursorPreActionHookOutput(advisory).permission, 'allow');
  assert.match(cursorPreActionHookOutput(advisory).agent_message, /^Marrow advisory/);
});

test('an enforced review asks the owner and an enforced or advisory block denies', async () => {
  const review = await runHookAgainst(noControlAfterGate(() => hostReviewRuntime()), publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.equal(JSON.parse(review.output).hookSpecificOutput.permissionDecision, 'ask');

  for (const enforced of [true, false]) {
    const blocked = await runHookAgainst(noControlAfterGate(() => reviewRuntime({
      risk_gate: { allow: false, decision: 'block', enforced, reasons: [{ message: 'Release freeze is active.' }] },
      exact_next_action: null,
    })), publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
    const decision = JSON.parse(blocked.output).hookSpecificOutput;
    assert.equal(decision.permissionDecision, 'deny', `enforced=${enforced}`);
    assert.equal(decision.permissionDecisionReason, 'Marrow blocked this action under the current policy. Reason: Release freeze is active.');
  }
  const blockedResult = { runtime: { risk_gate: { allow: false, decision: 'block', enforced: false, enforcement_decision: 'advisory', reasons: [] } }, permit: null, protectedRisk: true };
  assert.deepEqual(grokPreActionHookOutput(blockedResult), { decision: 'deny', reason: 'Marrow blocked this protected action.' });
  assert.equal(windsurfPreActionDecision(blockedResult).exitCode, 2);
});

test('permit verify declares the issued protocol version', async () => {
  for (const [issuedVersion, expected] of [[undefined, 1], [1, 1], [2, 2], ['2', 1]]) {
    const { calls } = await runHookAgainst((pathname, body) => {
      if (pathname === '/v1/agent/runtime') return fastPathRuntime();
      if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
      if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
        return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit', ...(issuedVersion === undefined ? {} : { protocol_version: issuedVersion }) } });
      }
      if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
        return Response.json({ data: { permit_id: 'permit-one', verified: true } });
      }
      throw new Error(`unexpected ${pathname}`);
    }, publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
    const verify = calls.find((entry) => entry.pathname === '/v1/agent/enforcement' && entry.body.operation === 'verify');
    assert.equal(verify.body.protocol_version, expected, `issued ${issuedVersion}`);
  }
});

test('a denied action closes its held decision as a failure with the gate receipt', async () => {
  const review = await runHookAgainst(noControlAfterGate(() => reviewRuntime()),
    publishEvent({ permission_mode: 'bypassPermissions' }), 'claude-pre-action-hook');
  assert.equal(JSON.parse(review.output).hookSpecificOutput.permissionDecision, 'deny');
  assert.deepEqual(review.calls.map((entry) => entry.pathname), ['/v1/agent/runtime']);
  assert.equal(review.commits.length, 1);
  const [closed] = review.commits;
  assert.equal(closed.body.decision_id, 'decision-review');
  assert.equal(closed.body.success, false);
  assert.equal(closed.body.gate_receipt_id, 'gate-review');
  assert.match(closed.body.outcome, /^denied by Marrow pre-action gate: Marrow requires owner review before this action, and no owner approval prompt is available/);
  assert.equal(closed.body.proof, undefined, 'a denial never claims owner approval');
  assert.match(closed.idempotencyKey, /^mcp-hook-deny:[a-f0-9]{40}$/);

  const blocked = await runHookAgainst(noControlAfterGate(() => reviewRuntime({
    risk_gate: { allow: false, decision: 'block', enforced: true, reasons: [{ message: 'Release freeze is active.' }] },
  })), publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.equal(blocked.commits.length, 1);
  assert.match(blocked.commits[0].body.outcome, /^denied by Marrow pre-action gate: Marrow blocked this action under the current policy/);

  const scope = await runHookAgainst((pathname, body) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return new Response(JSON.stringify({ code: 'ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID' }), { status: 403, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected ${pathname}`);
  }, publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.equal(scope.commits.length, 1);
  assert.equal(scope.commits[0].body.decision_id, 'decision-think');
  assert.equal(scope.commits[0].body.gate_receipt_id, undefined, 'a Think decision is not bound to the runtime receipt');
  assert.match(scope.commits[0].body.outcome, /not authorized to obtain action permits for agent "agent-one"/);
});

test('an owner prompt, an advisory gate and an allowed action never close the decision', async () => {
  const asked = await runHookAgainst(noControlAfterGate(() => hostReviewRuntime()),
    publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.equal(JSON.parse(asked.output).hookSpecificOutput.permissionDecision, 'ask');
  assert.deepEqual(asked.commits, []);

  const advisory = await runHookAgainst(noControlAfterGate(() => advisoryRuntime({ allow: true, decision: 'review_required' })),
    publishEvent({ permission_mode: 'bypassPermissions' }), 'claude-pre-action-hook');
  assert.equal(JSON.parse(advisory.output).hookSpecificOutput.permissionDecision, undefined);
  assert.deepEqual(advisory.commits, []);

  const allowed = await runHookAgainst((pathname, body) => {
    if (pathname === '/v1/agent/runtime') return fastPathRuntime();
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (body.operation === 'issue') return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    return Response.json({ data: { permit_id: 'permit-one', verified: true } });
  }, publishEvent({ permission_mode: 'default' }), 'claude-pre-action-hook');
  assert.notEqual(JSON.parse(allowed.output).hookSpecificOutput.permissionDecision, 'deny');
  assert.deepEqual(allowed.commits, []);
});

test('closing a denied decision is bounded and never throws', async () => {
  const originalFetch = globalThis.fetch;
  const held = { decisionId: 'decision-slow', gateReceiptId: 'gate-slow' };
  try {
    globalThis.fetch = () => new Promise(() => {});
    const started = Date.now();
    assert.equal(await closeDeniedDecision('test-key', 'https://api.example.test', held, 'Marrow blocked this action.', 'session-one', 'agent-one'), false);
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= DENIED_DECISION_CLOSE_TIMEOUT_MS - 50 && elapsed < DENIED_DECISION_CLOSE_TIMEOUT_MS + 2_000, `elapsed ${elapsed}`);

    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'conflict', code: 'MARROW_IDEMPOTENCY_CONFLICT' }), { status: 409, headers: { 'content-type': 'application/json' } });
    assert.equal(await closeDeniedDecision('test-key', 'https://api.example.test', held, 'denied', 'session-one', 'agent-one'), false);

    // Enforcing plans record a denied gate's failure only as an unverified observation.
    globalThis.fetch = async () => Response.json({ data: {
      accepted: true, committed: false, outcome_state: 'observed_unverified', authorization_granted: false,
      trusted_learning_applied: false, decision_id: 'decision-slow', exact_next_action: 'none',
    } }, { status: 202 });
    assert.equal(await closeDeniedDecision('test-key', 'https://api.example.test', held, 'denied', 'session-one', 'agent-one'), false);

    assert.equal(await closeDeniedDecision('test-key', 'https://api.example.test', { decisionId: null, gateReceiptId: null }, 'denied', 'session-one'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('only a positive advisory contract skips enforcement; every other gate shape fails closed', async () => {
  const advisoryGate = { allow: true, decision: 'review_required', enforced: false, enforcement_decision: 'advisory', gate_required: false, reasons: [] };
  const review = { allow: false, decision: 'review_required', reasons: [] };
  const shapes = [
    // Barvis F-27-1 table: each was allowed by the first version of F4.
    ['hard gate declared outside risk_gate', { risk_gate: review, authorization_state: 'hard_gate', hard_gate_obtained: true }, false],
    ['required gate receipt', { risk_gate: review, gate_receipt: { id: 'g', required: true } }, false],
    ['slim risk_gate_enforced true', { response_mode: 'slim', risk_gate: review, risk_gate_enforced: true }, false],
    ['authorization unverified', { risk_gate: { ...advisoryGate }, authorization_state: 'unverified' }, false],
    ['no enforcement flags', { risk_gate: review }, false],
    ['owner approval required without flags', { risk_gate: { ...review, decision: 'owner_approval_required', owner_approval_required: true } }, false],
    ['hard enforcement decision without enforced', { risk_gate: { ...review, enforcement_decision: 'hard_enforcement' } }, false],
    ['enforced as a string', { risk_gate: { ...review, enforced: 'true' } }, false],
    ['enforced false without the advisory decision', { risk_gate: { ...advisoryGate, enforcement_decision: undefined } }, false],
    ['advisory decision without enforced false', { risk_gate: { ...advisoryGate, enforced: undefined } }, false],
    ['expanded advisory that disallows', { risk_gate: { ...advisoryGate, allow: false } }, false],
    ['advisory with a required gate', { risk_gate: { ...advisoryGate, gate_required: true } }, false],
    ['advisory with owner approval guidance', { risk_gate: advisoryGate, completion_contract: { owner_approval: { mode: 'ordinary_non_arbitrated' } } }, false],
    ['advisory with arbitration', { risk_gate: advisoryGate, arbitration: { receipt_id: 'arb' } }, false],
    ['advisory on an enforcing plan', { risk_gate: advisoryGate, plan_capability: { mode: 'enforced', production_enforcement_entitled: true } }, false],
    ['slim advisory missing risk_gate_enforced', { response_mode: 'slim', risk_gate: { ...advisoryGate, allow: false } }, false],
    ['advisory block', { risk_gate: { ...advisoryGate, allow: false, decision: 'block' } }, false],
    // The shapes the backend sends on a plan without production_action_enforcement.
    ['expanded advisory', { risk_gate: advisoryGate, authorization_state: 'advisory_only' }, true],
    ['expanded advisory warn', { risk_gate: { ...advisoryGate, decision: 'warn' } }, true],
    ['slim advisory', { response_mode: 'slim', risk_gate: { ...advisoryGate, allow: false }, risk_gate_enforced: false, enforcement_decision: 'advisory', authorization_state: 'advisory_only' }, true],
  ];
  for (const [label, runtime, advisory] of shapes) {
    assert.equal(runtimeGateAdvisory(runtime), advisory, label);
    assert.equal(runtimeGateEnforced(runtime), !advisory, label);
    // control() returns an advisory gate as unprotected and every other protected gate as protected.
    const output = preActionHookOutput({ runtime, permit: null, protectedRisk: !advisory }, 'claude-code');
    if (advisory) {
      assert.equal(output.hookSpecificOutput.permissionDecision, undefined, label);
    } else {
      assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', label);
    }
  }
});

test('the slim runtime shape the MCP client receives is enforced unless it says advisory', async () => {
  const slim = (fields) => Response.json({ data: {
    response_mode: 'slim',
    ok: true,
    action: 'classified Bash action: publish on npm',
    decision_id: 'decision-slim',
    risk_level: 'high',
    gate_receipt_id: 'gate-slim',
    gate_required: false,
    proof_required: false,
    proof_complete: true,
    exact_next_action: 'Get owner review.',
    ...fields,
  } });
  for (const [label, fields, advisory] of [
    ['slim advisory pilot review', { decision: 'review_required', risk_gate_enforced: false, enforcement_decision: 'advisory' }, true],
    ['slim advisory warn', { decision: 'warn', risk_gate_enforced: false, enforcement_decision: 'advisory' }, true],
    ['slim enforced review', { decision: 'review_required', risk_gate_enforced: true, enforcement_decision: 'owner_approval_required', gate_required: true }, false],
    ['slim review without enforcement fields', { decision: 'review_required' }, false],
    ['slim advisory decision but enforced null', { decision: 'review_required', risk_gate_enforced: null, enforcement_decision: 'advisory' }, false],
  ]) {
    const { calls, output } = await runHookAgainst(noControlAfterGate(() => slim(fields)),
      publishEvent({ permission_mode: 'bypassPermissions' }), 'claude-pre-action-hook');
    assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime'], label);
    const decision = JSON.parse(output).hookSpecificOutput;
    if (advisory) {
      assert.equal(decision.permissionDecision, undefined, label);
      assert.match(decision.additionalContext, /^Marrow advisory: this plan does not enforce the pre-action gate/, label);
    } else {
      assert.equal(decision.permissionDecision, 'deny', label);
      assert.match(decision.permissionDecisionReason, /^Marrow requires owner review before this action/, label);
    }
  }
});
