const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
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
  GROK_ACTION_RESULT_HOOK_COMMAND,
  GROK_CONTEXT_HOOK_COMMAND,
  GROK_NATIVE_HOOK_MATCHER,
  GROK_PRE_ACTION_GUARD_COMMAND,
  GROK_SESSION_END_HOOK_COMMAND,
  NATIVE_HOOK_MATCHER,
  PRE_ACTION_HOOK_COMMAND,
  SESSION_END_HOOK_COMMAND,
  installGrokNativeHooks,
  localHookConfigurationFingerprint,
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
  const pattern = new RegExp(`^npx\\s+(?:-y\\s+)?(?:--package=@getmarrow/mcp(?:@[^\\s]+)?\\s+marrow-mcp|@getmarrow/mcp(?:@[^\\s]+)?)\\s+(?:claude-)?${subcommand}$`);
  return (settings.hooks?.[eventName] || []).flatMap((entry) =>
    (entry.hooks || [])
      .filter((handler) => handler.type === 'command' && pattern.test(String(handler.command).trim()))
      .map((handler) => ({ entry, handler })),
  );
}

test('setup upgrades legacy and old pinned hooks to one exact configured handler', () => {
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

test('local diagnostic fingerprint includes unexpected active legacy and duplicate Marrow handlers', () => {
  withSettings({ hooks: {} }, ({ directory, settingsPath }) => {
    installAll(directory);
    const configured = localHookConfigurationFingerprint(directory);
    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    settings.hooks.PreToolUse.push({
      matcher: NATIVE_HOOK_MATCHER,
      hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp pre-action-hook', timeout: 99 }],
    });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    assert.notEqual(localHookConfigurationFingerprint(directory), configured);

    const repaired = JSON.parse(readFileSync(settingsPath, 'utf8'));
    repaired.hooks.PreToolUse = repaired.hooks.PreToolUse.filter((entry) =>
      !entry.hooks?.some((handler) => handler.command === 'npx -y @getmarrow/mcp pre-action-hook'));
    writeFileSync(settingsPath, JSON.stringify(repaired, null, 2));
    const expectedOnly = localHookConfigurationFingerprint(directory);
    repaired.hooks.PreToolUse.push({
      matcher: NATIVE_HOOK_MATCHER,
      hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.49 hook', timeout: 77 }],
    });
    writeFileSync(settingsPath, JSON.stringify(repaired, null, 2));
    assert.notEqual(localHookConfigurationFingerprint(directory), expectedOnly);
  });
});

test('Grok native hooks install under ~/.grok/hooks with Grok tool matchers', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-grok-hooks-'));
  try {
    const hooksDir = join(home, '.grok', 'hooks');
    mkdirSync(hooksDir, { recursive: true });
    writeFileSync(join(hooksDir, 'marrow.json'), JSON.stringify({
      owner: true,
      hooks: {
        OwnerEvent: [{ hooks: [{ type: 'command', command: 'printf owner' }] }],
        SessionEnd: [{ hooks: [
          { type: 'command', command: 'printf owner-session' },
          { type: 'command', command: GROK_SESSION_END_HOOK_COMMAND },
        ] }],
      },
    }, null, 2));
    const result = installGrokNativeHooks(home);
    const settings = JSON.parse(readFileSync(result.settingsPath, 'utf8'));
    const first = readFileSync(result.settingsPath, 'utf8');
    assert.equal(result.settingsPath, join(home, '.grok', 'hooks', 'marrow.json'));
    assert.equal(settings.owner, true);
    assert.equal(settings.hooks.OwnerEvent[0].hooks[0].command, 'printf owner');
    assert.equal(settings.hooks.UserPromptSubmit[0].hooks[0].command, GROK_CONTEXT_HOOK_COMMAND);
    assert.equal(settings.hooks.PreToolUse[0].matcher, GROK_NATIVE_HOOK_MATCHER);
    assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, GROK_PRE_ACTION_GUARD_COMMAND);
    assert.match(GROK_PRE_ACTION_GUARD_COMMAND, /^node -e /);
    assert.match(GROK_PRE_ACTION_GUARD_COMMAND, /grok-pre-action-hook/);
    assert.doesNotMatch(GROK_PRE_ACTION_GUARD_COMMAND, /\btimeout\b/);
    assert.equal(settings.hooks.PreToolUse[0].hooks[0].timeout, 7);
    assert.equal(settings.hooks.PostToolUse[0].matcher, GROK_NATIVE_HOOK_MATCHER);
    assert.equal(settings.hooks.PostToolUse[0].hooks[0].command, GROK_ACTION_RESULT_HOOK_COMMAND);
    assert.equal(settings.hooks.PostToolUse[0].hooks[0].timeout, 5);
    assert.equal(settings.hooks.PostToolUseFailure[0].hooks[0].command, GROK_ACTION_RESULT_HOOK_COMMAND);
    assert.deepEqual(settings.hooks.SessionEnd, [{ hooks: [{ type: 'command', command: 'printf owner-session' }] }]);
    assert.equal(settings.hooks.Stop[0].hooks[0].command, GROK_SESSION_END_HOOK_COMMAND);
    assert.equal(settings.hooks.Stop[0].hooks[0].timeout, 3);
    assert.equal(installGrokNativeHooks(home).installed, false);
    assert.equal(readFileSync(result.settingsPath, 'utf8'), first);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('Grok native hook install rejects invalid and symlinked target components without rewriting outside its global path', () => {
  for (const unsafe of ['invalid', 'target-symlink', 'grok-parent-symlink', 'hooks-parent-symlink']) {
    const home = mkdtempSync(join(tmpdir(), `marrow-grok-${unsafe}-`));
    const outside = mkdtempSync(join(tmpdir(), 'marrow-grok-outside-'));
    try {
      const grokDir = join(home, '.grok');
      const hooksDir = join(grokDir, 'hooks');
      const target = join(hooksDir, 'marrow.json');
      if (unsafe === 'grok-parent-symlink') {
        symlinkSync(outside, grokDir);
      } else if (unsafe === 'hooks-parent-symlink') {
        mkdirSync(grokDir);
        symlinkSync(outside, hooksDir);
      } else {
        mkdirSync(hooksDir, { recursive: true });
      }
      if (unsafe === 'invalid') writeFileSync(target, '{broken');
      if (unsafe === 'target-symlink') {
        const outsideFile = join(outside, 'marrow.json');
        writeFileSync(outsideFile, '{"owner":true}\n');
        symlinkSync(outsideFile, target);
      }
      assert.throws(() => installGrokNativeHooks(home), /Cannot update Grok hook settings/);
      if (unsafe === 'invalid') assert.equal(readFileSync(target, 'utf8'), '{broken');
      else if (unsafe === 'target-symlink') assert.equal(readFileSync(join(outside, 'marrow.json'), 'utf8'), '{"owner":true}\n');
      else {
        assert.equal(require('node:fs').existsSync(join(outside, 'hooks', 'marrow.json')), false);
        assert.equal(require('node:fs').existsSync(join(outside, 'marrow.json')), false);
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  }
});
