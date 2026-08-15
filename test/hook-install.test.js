const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { installPostToolUseHook } = require('../dist/hook.js');
const { installUserPromptSubmitHook } = require('../dist/hook-context.js');
const { installPreActionHook } = require('../dist/hook-pre-action.js');
const { installSessionEndHook } = require('../dist/hook-session.js');
const {
  ACTION_RESULT_HOOK_COMMAND,
  CONTEXT_HOOK_COMMAND,
  NATIVE_HOOK_MATCHER,
  PRE_ACTION_HOOK_COMMAND,
  SESSION_END_HOOK_COMMAND,
  nativeHookConfigurationFingerprint,
} = require('../dist/hook-contract.js');

test('native matcher exempts only the exact official Marrow MCP namespace', () => {
  const matcher = new RegExp(`^(?:${NATIVE_HOOK_MATCHER})$`);
  assert.equal(matcher.test('mcp__marrow__marrow_commit'), false);
  assert.equal(matcher.test('mcp__marrow_evil__delete'), true);
  assert.equal(matcher.test('mcp__payments__refund'), true);
});

function withSettings(value, callback) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-hooks-'));
  const settingsDir = join(directory, '.claude');
  const settingsPath = join(settingsDir, 'settings.json');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(settingsPath, typeof value === 'string' ? value : JSON.stringify(value, null, 2));
  try {
    return callback({ directory, settingsPath });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function installAll(directory) {
  installPostToolUseHook(directory);
  installUserPromptSubmitHook(directory);
  installPreActionHook(directory);
  installSessionEndHook(directory);
}

function commandHandlers(settings, eventName, subcommand) {
  const pattern = new RegExp(`^npx\\s+(?:-y\\s+)?(?:--package=@getmarrow/mcp(?:@[^\\s]+)?\\s+marrow-mcp|@getmarrow/mcp(?:@[^\\s]+)?)\\s+${subcommand}$`);
  return (settings.hooks?.[eventName] || []).flatMap((entry) =>
    (entry.hooks || [])
      .filter((handler) => handler.type === 'command' && pattern.test(String(handler.command).trim()))
      .map((handler) => ({ entry, handler })),
  );
}

test('setup upgrades legacy and old pinned hooks to one exact certified handler', () => {
  withSettings({
    permissions: { allow: ['Read'] },
    hooks: {
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp context-hook', timeout: 11 }] }],
      PreToolUse: [{ matcher: NATIVE_HOOK_MATCHER, hooks: [
        { type: 'command', command: 'npx -y @getmarrow/mcp@3.9.49 pre-action-hook', timeout: 12 },
        { type: 'command', command: 'npx -y @getmarrow/mcp@3.9.49 hook', timeout: 99 },
      ] }],
      PostToolUse: [{ matcher: NATIVE_HOOK_MATCHER, hooks: [
        { type: 'command', command: 'npx -y @getmarrow/mcp hook', timeout: 13 },
        { type: 'command', command: 'printf unrelated' },
      ] }],
      PostToolUseFailure: [
        { matcher: NATIVE_HOOK_MATCHER, hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.48 hook' }] },
        { matcher: NATIVE_HOOK_MATCHER, hooks: [{ type: 'command', command: ACTION_RESULT_HOOK_COMMAND, timeout: 14 }] },
      ],
      Stop: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp session-hook', timeout: 15 }] }],
    },
  }, ({ directory, settingsPath }) => {
    installAll(directory);
    const first = readFileSync(settingsPath, 'utf8');
    const settings = JSON.parse(first);
    const expected = [
      ['UserPromptSubmit', 'context-hook', CONTEXT_HOOK_COMMAND],
      ['PreToolUse', 'pre-action-hook', PRE_ACTION_HOOK_COMMAND],
      ['PostToolUse', 'hook', ACTION_RESULT_HOOK_COMMAND],
      ['PostToolUseFailure', 'hook', ACTION_RESULT_HOOK_COMMAND],
      ['Stop', 'session-hook', SESSION_END_HOOK_COMMAND],
    ];
    for (const [eventName, subcommand, command] of expected) {
      const handlers = commandHandlers(settings, eventName, subcommand);
      assert.equal(handlers.length, 1, `${eventName} has one Marrow handler`);
      assert.equal(handlers[0].handler.command, command);
    }
    assert.deepEqual(settings.permissions, { allow: ['Read'] });
    assert.equal(settings.hooks.PostToolUse[0].hooks[0].command, 'printf unrelated');
    assert.equal(commandHandlers(settings, 'PostToolUseFailure', 'hook')[0].handler.timeout, 14);
    const activeMarrowHandlers = Object.values(settings.hooks).flatMap((entries) => entries)
      .flatMap((entry) => entry.hooks || [])
      .filter((handler) => /^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+/.test(handler.command || ''));
    assert.equal(activeMarrowHandlers.length, 5);

    installAll(directory);
    assert.equal(readFileSync(settingsPath, 'utf8'), first);
  });
});

test('setup fails closed and preserves malformed or non-object settings', () => {
  for (const value of ['{broken', '[]']) {
    withSettings(value, ({ directory, settingsPath }) => {
      const before = readFileSync(settingsPath, 'utf8');
      assert.throws(() => installPostToolUseHook(directory), /Cannot update Claude hook settings/);
      assert.equal(readFileSync(settingsPath, 'utf8'), before);
    });
  }
});

test('fingerprint includes unexpected active legacy and duplicate Marrow handlers', () => {
  withSettings({ hooks: {} }, ({ directory, settingsPath }) => {
    installAll(directory);
    const certified = nativeHookConfigurationFingerprint(directory);
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    settings.hooks.PreToolUse.push({
      matcher: NATIVE_HOOK_MATCHER,
      hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp pre-action-hook', timeout: 99 }],
    });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    assert.notEqual(nativeHookConfigurationFingerprint(directory), certified);

    const repaired = JSON.parse(readFileSync(settingsPath, 'utf8'));
    repaired.hooks.PreToolUse = repaired.hooks.PreToolUse.filter((entry) =>
      !entry.hooks?.some((handler) => handler.command === 'npx -y @getmarrow/mcp pre-action-hook'));
    writeFileSync(settingsPath, JSON.stringify(repaired, null, 2));
    const expectedOnly = nativeHookConfigurationFingerprint(directory);
    repaired.hooks.PreToolUse.push({
      matcher: NATIVE_HOOK_MATCHER,
      hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.49 hook', timeout: 77 }],
    });
    writeFileSync(settingsPath, JSON.stringify(repaired, null, 2));
    assert.notEqual(nativeHookConfigurationFingerprint(directory), expectedOnly);
  });
});
