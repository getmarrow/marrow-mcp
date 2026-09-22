const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  MARROW_OUTAGE_WARNING,
  PreActionControlTimeoutError,
  classifyTool,
  clinePreActionHookOutput,
  cursorPreActionHookOutput,
  geminiPreActionHookOutput,
  grokPreActionHookOutput,
  isMarrowControlOutage,
  preActionHookOutput,
  runPreActionHookCommand,
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
      risk_gate: { allow: false, decision: 'review_required', reasons: [{ message: privateText }] },
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
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
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
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      completion_contract: { decision_creation_required: true },
    } });
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-one' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-issued', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-other', verified: true } });
    }
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
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  try {
    await runPreActionHookCommand({ tool_input: { command: 'unknown mutation' } });
    const result = JSON.parse(output);
    assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.permissionDecisionReason, /could not classify/i);
  } finally {
    process.stdout.write = originalWrite;
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
        risk_gate: { allow: true, decision: 'allow', reasons: [] },
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
        risk_gate: { allow: false, decision: 'block', reasons: [] },
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
    assert.deepEqual(calls.map((entry) => entry.pathname), ['/v1/agent/runtime']);
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
