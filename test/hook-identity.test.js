const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  nativeHookLifecycleIdentity,
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

test('setup-owned Claude and Grok entrypoints resolve distinct trusted harnesses', () => {
  for (const entrypoint of ['claude-context-hook', 'claude-pre-action-hook', 'claude-hook', 'claude-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'claude-code');
    assert.equal(identity.trusted_native_adapter, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
  for (const entrypoint of ['grok-context-hook', 'grok-pre-action-hook', 'grok-hook', 'grok-session-hook']) {
    const identity = resolve(entrypoint, { MARROW_FLEET_AGENT_ID: 'bound-agent' });
    assert.equal(identity.harness, 'grok');
    assert.equal(identity.trusted_native_adapter, true);
    assert.equal(identity.agent_id, 'bound-agent');
  }
});

test('legacy, unknown, and custom entrypoints cannot claim native-hook coverage', () => {
  for (const entrypoint of ['hook', 'context-hook', 'custom-hook', '', 'grok-lookalike-hook']) {
    const fields = nativeHookLifecycleIdentity(resolve(entrypoint), 'action_result');
    assert.equal(fields.harness, 'mcp-client');
    assert.equal(fields.capability_level, undefined);
    assert.equal(fields.adapter_version, undefined);
    assert.equal(fields.observed_hook, undefined);
  }
});

test('caller payload identity cannot override the trusted adapter or bound agent', () => {
  const callerPayload = { harness: 'claude-code', agent_id: 'caller-owned-agent', capability_level: 'native_hooks' };
  const trusted = nativeHookLifecycleIdentity(
    resolve('grok-hook', { MARROW_FLEET_AGENT_ID: 'credential-bound-agent' }),
    'action_result',
  );
  const event = { ...callerPayload, ...trusted };
  assert.equal(event.harness, 'grok');
  assert.equal(event.agent_id, 'credential-bound-agent');
  assert.equal(event.capability_level, 'native_hooks');
});

test('missing agent identity stays absent for server derivation instead of being invented', () => {
  const missing = resolve('claude-hook');
  assert.equal(missing.agent_id, undefined);
  assert.equal(nativeHookLifecycleIdentity(missing, 'action_result').agent_id, undefined);
});
