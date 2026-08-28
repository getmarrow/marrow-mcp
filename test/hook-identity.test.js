const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  clientReportedHookLifecycleIdentity,
  resolveNativeHookIdentity,
} = require('../dist/hook-contract.js');

function resolve(entrypoint, extraEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), 'marrow-hook-identity-'));
  try {
    return resolveNativeHookIdentity(entrypoint, {
      cwd: home,
      home,
      env: {
        MARROW_API_KEY: 'fixture-hook-key',
        MARROW_BASE_URL: 'https://api.example.test',
        ...extraEnv,
      },
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('public Claude, Cline, Codex, Cursor, Gemini, Grok, and Windsurf entrypoints provide display labels, not trusted provenance', () => {
  for (const entrypoint of ['claude-context-hook', 'claude-pre-action-hook', 'claude-hook', 'claude-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'claude-code');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['codex-context-hook', 'codex-pre-action-hook', 'codex-hook', 'codex-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'codex');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['grok-context-hook', 'grok-pre-action-hook', 'grok-hook', 'grok-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'grok');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['cursor-pre-action-hook', 'cursor-hook', 'cursor-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'cursor');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['cline-pre-action-hook', 'cline-hook', 'cline-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'cline');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['windsurf-pre-action-hook', 'windsurf-hook', 'windsurf-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'windsurf');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['gemini-pre-action-hook', 'gemini-hook', 'gemini-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'gemini');
    assert.equal(identity.identity_source, 'public_cli_entrypoint');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
});

test('manual public, legacy, unknown, and custom entrypoints cannot emit certified coverage fields', () => {
  for (const entrypoint of [
    'claude-context-hook', 'claude-pre-action-hook', 'claude-hook', 'claude-session-hook',
    'codex-context-hook', 'codex-pre-action-hook', 'codex-hook', 'codex-session-hook',
    'grok-context-hook', 'grok-pre-action-hook', 'grok-hook', 'grok-session-hook',
    'cursor-pre-action-hook', 'cursor-hook', 'cursor-session-hook',
    'cline-pre-action-hook', 'cline-hook', 'cline-session-hook',
    'windsurf-pre-action-hook', 'windsurf-hook', 'windsurf-session-hook',
    'gemini-pre-action-hook', 'gemini-hook', 'gemini-session-hook',
    'hook', 'context-hook', 'custom-hook', '', 'grok-lookalike-hook',
  ]) {
    const identity = resolve(entrypoint);
    const fields = clientReportedHookLifecycleIdentity(identity);
    assert.equal(fields.harness, identity.harness);
    assert.equal(fields.source, 'client_self_reported');
    assert.equal(fields.capability_level, undefined);
    assert.equal(fields.adapter_version, undefined);
    assert.equal(fields.config_fingerprint, undefined);
    assert.equal(fields.expected_hooks, undefined);
    assert.equal(fields.observed_hook, undefined);
  }
});

test('forged hook payload evidence is not copied into the lifecycle identity', () => {
  const callerPayload = { harness: 'claude-code', agent_id: 'caller-owned-agent', capability_level: 'native_hooks' };
  const lifecycle = clientReportedHookLifecycleIdentity(
    resolve('grok-hook', { MARROW_FLEET_AGENT_ID: 'credential-bound-agent' }),
  );
  assert.equal(lifecycle.harness, 'grok');
  assert.equal(lifecycle.agent_id, 'credential-bound-agent');
  assert.equal(lifecycle.source, 'client_self_reported');
  assert.equal(lifecycle.capability_level, undefined);
  assert.equal(lifecycle.config_fingerprint, undefined);
  assert.equal(lifecycle.expected_hooks, undefined);
  assert.equal(lifecycle.observed_hook, undefined);
  assert.equal(callerPayload.capability_level, 'native_hooks');
});

test('missing agent identity stays absent for server derivation instead of being invented', () => {
  const missing = resolve('claude-hook');
  assert.equal(missing.agent_id, undefined);
  assert.equal(clientReportedHookLifecycleIdentity(missing).agent_id, undefined);
});
