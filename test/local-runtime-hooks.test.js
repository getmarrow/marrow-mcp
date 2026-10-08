const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const contract = require('../dist/hook-contract.js');
const { delocalizeMarrowHookCommand, isMarrowHookCommand, MCP_ADAPTER_VERSION } = contract;
const installer = require('./support/installer-local-runtime-forms.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const V = MCP_ADAPTER_VERSION;
const ALL_COMMANDS = Object.entries(contract).filter(([name, value]) => /_COMMAND$/.test(name) && typeof value === 'string');

test('every Marrow hook command: the installer\'s local form maps back to exactly that command', () => {
  assert.ok(ALL_COMMANDS.length >= 20);
  for (const [name, command] of ALL_COMMANDS) {
    const local = installer.localizeHookCommand(command, V);
    assert.notEqual(local, command, `${name}: the installer has a local form`);
    assert.equal(delocalizeMarrowHookCommand(local), command, `${name}: maps back`);
    assert.equal(isMarrowHookCommand(local, command), true, name);
    assert.equal(installer.delocalizeHookCommand(local), command, `${name}: the installer agrees`);
  }
  // Inside an sh -c wrapper (Windsurf, Gemini).
  const wrapped = `sh -c 'cat | ${contract.GEMINI_PRE_ACTION_HOOK_COMMAND}'`;
  const local = installer.localizeHookCommand(wrapped, V);
  assert.notEqual(local, wrapped);
  assert.equal(delocalizeMarrowHookCommand(local), wrapped);
});

// Abuse cases for the recognizer: each must NOT be taken as Marrow's command.
function abuseCases() {
  const plain = installer.localizeHookCommand(contract.PRE_ACTION_HOOK_COMMAND, V);
  const guard = installer.localizeHookCommand(contract.GROK_PRE_ACTION_GUARD_COMMAND, V);
  const inner = installer.localizeHookCommand(`sh -c 'cat | ${contract.GEMINI_PRE_ACTION_HOOK_COMMAND}'`, V);
  const other = '9.9.9';
  return [
    ['plain: run path version differs from the package', plain.replace(`/mcp/${V}/run`, `/mcp/${other}/run`)],
    ['plain: package version differs in the npx fallback', plain.replace(new RegExp(`exec npx -y --package=@getmarrow/mcp@${V.replace(/\./g, '\\.')}`), `exec npx -y --package=@getmarrow/mcp@${other}`)],
    ['plain: owner suffix after the command', `${plain}; echo done`],
    ['plain: owner prefix', `echo start; ${plain}`],
    ['plain: another runtime path', plain.replace('$HOME/.marrow/runtime/mcp/', '/tmp/evil/runtime/mcp/')],
    ['plain: another package', plain.replace(/@getmarrow\/mcp@/g, '@evil/mcp@')],
    ['plain: extra space', plain.replace('; if [', ';  if [')],
    ['plain: another entrypoint in the fallback', plain.replace(/marrow-mcp claude-pre-action-hook'$/, "marrow-mcp claude-hook'")],
    ['guard: node path version differs', guard.replace(`/mcp/${V}/node`, `/mcp/${other}/node`)],
    ['guard: spawn run path version differs', guard.replace(`/mcp/${V}/run`, `/mcp/${other}/run`)],
    ['guard: spawn package version differs', guard.replace(`--package=@getmarrow/mcp@${V}","marrow-mcp`, `--package=@getmarrow/mcp@${other}","marrow-mcp`)],
    ['guard: owner suffix', `${guard} || true`],
    ['inner: run path version differs', inner.replace(`/mcp/${V}/run`, `/mcp/${other}/run`)],
    ['inner: owner suffix', `${inner}; echo done`],
  ];
}

test('the recognizer is strict: look-alikes, suffixes, other paths and mixed versions are not Marrow\'s', () => {
  const canonical = {
    plain: contract.PRE_ACTION_HOOK_COMMAND,
    guard: contract.GROK_PRE_ACTION_GUARD_COMMAND,
    inner: `sh -c 'cat | ${contract.GEMINI_PRE_ACTION_HOOK_COMMAND}'`,
  };
  for (const [label, command] of abuseCases()) {
    const kind = label.split(':')[0];
    assert.equal(isMarrowHookCommand(command, canonical[kind]), false, label);
    const mapped = delocalizeMarrowHookCommand(command);
    assert.equal(Object.values(canonical).includes(mapped), false, `${label}: never maps to a Marrow command`);
  }
});

function project() {
  const root = mkdtempSync(join(tmpdir(), 'marrow-local-hooks-'));
  const home = join(root, 'home');
  const work = join(root, 'project');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(join(work, '.claude'), { recursive: true });
  const setup = () => {
    const result = spawnSync(process.execPath, [CLI, 'setup'], {
      cwd: work, encoding: 'utf8', timeout: 30_000,
      env: { PATH: process.env.PATH, HOME: home, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
    });
    assert.equal(result.status, 0, result.stderr);
  };
  const files = {
    claude: join(work, '.claude', 'settings.json'),
    grok: join(home, '.grok', 'hooks', 'marrow.json'),
  };
  const read = (file) => (existsSync(file) ? readFileSync(file, 'utf8') : null);
  const localize = (file, version = V) => writeFileSync(file, installer.localizeHookSettingsText(read(file), version));
  return { root, home, work, setup, files, read, localize, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

const commandsOf = (text) => {
  const out = [];
  const walk = (value) => {
    if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === 'object') for (const [key, entry] of Object.entries(value)) (key === 'command' && typeof entry === 'string' ? out.push(entry) : walk(entry));
  };
  walk(JSON.parse(text));
  return out;
};
const marrowEntriesPerEvent = (text) => Object.fromEntries(Object.entries(JSON.parse(text).hooks || {}).map(([event, entries]) => [
  event,
  entries.flatMap((entry) => entry.hooks || []).filter((hook) => /marrow-mcp|@getmarrow\/mcp/.test(String(hook.command))).length,
]));

test('Claude Code and Grok, installer first: setup keeps the local form, one Marrow entry per event, the person\'s hooks kept', () => {
  const p = project();
  try {
    // The person's own hooks, before anything else.
    writeFileSync(p.files.claude, `${JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }], Stop: [{ hooks: [{ type: 'command', command: 'echo bye' }] }] } }, null, 2)}\n`);
    p.setup();
    // The installer then switches Marrow's entries to its local runtime.
    p.localize(p.files.claude);
    p.localize(p.files.grok);
    const claudeLocal = p.read(p.files.claude);
    const grokLocal = p.read(p.files.grok);
    assert.ok(commandsOf(claudeLocal).some((command) => command.startsWith('/bin/sh -c \'M="$HOME/.marrow/runtime/mcp/')));
    assert.ok(commandsOf(grokLocal).some((command) => command.startsWith('N="$HOME/.marrow/runtime/mcp/')));
    // Setup again (any order after this): nothing changes.
    p.setup();
    assert.equal(p.read(p.files.claude), claudeLocal, 'Claude settings unchanged');
    assert.equal(p.read(p.files.grok), grokLocal, 'Grok hooks unchanged');
    for (const [event, count] of Object.entries(marrowEntriesPerEvent(claudeLocal))) assert.ok(count <= 1, `Claude ${event}: ${count} Marrow entries`);
    for (const [event, count] of Object.entries(marrowEntriesPerEvent(grokLocal))) assert.ok(count <= 1, `Grok ${event}: ${count} Marrow entries`);
    assert.ok(commandsOf(claudeLocal).includes('echo mine'));
    assert.ok(commandsOf(claudeLocal).includes('echo bye'));
  } finally { p.cleanup(); }
});

test('Claude Code and Grok, setup first then installer then setup: one Marrow entry per event; an older local form is replaced by this version', () => {
  const p = project();
  try {
    p.setup();
    const npxClaude = p.read(p.files.claude);
    const npxGrok = p.read(p.files.grok);
    p.setup();
    assert.equal(p.read(p.files.claude), npxClaude, 'setup twice: unchanged (npx form kept)');
    assert.equal(p.read(p.files.grok), npxGrok);
    // An installer pinned to an older MCP left its local form for that version.
    const older = '3.9.98';
    writeFileSync(p.files.claude, npxClaude.replace(new RegExp(`@getmarrow/mcp@${V.replace(/\./g, '\\.')}`, 'g'), `@getmarrow/mcp@${older}`));
    p.localize(p.files.claude, older);
    assert.ok(p.read(p.files.claude).includes(`/mcp/${older}/run`));
    p.setup();
    const upgraded = p.read(p.files.claude);
    assert.equal(upgraded.includes(older), false, 'the older form is gone');
    for (const [event, count] of Object.entries(marrowEntriesPerEvent(upgraded))) assert.ok(count <= 1, `Claude ${event}: ${count}`);
    assert.equal(upgraded, npxClaude, 'back to this version\'s entries');
  } finally { p.cleanup(); }
});

test('Look-alike local commands are the person\'s: setup keeps them as they are and adds its own entry', () => {
  for (const [label, command] of abuseCases().filter(([name]) => name.startsWith('plain'))) {
    const p = project();
    try {
      writeFileSync(p.files.claude, `${JSON.stringify({ hooks: { PreToolUse: [{ matcher: contract.NATIVE_HOOK_MATCHER, hooks: [{ type: 'command', command }] }] } }, null, 2)}\n`);
      p.setup();
      const commands = commandsOf(p.read(p.files.claude));
      assert.ok(commands.includes(command), `${label}: kept`);
      assert.ok(commands.includes(contract.PRE_ACTION_HOOK_COMMAND), `${label}: Marrow's own entry added`);
    } finally { p.cleanup(); }
  }
});

test('Codex, Cursor, Gemini and Windsurf: setup never writes their hook files, in either order', () => {
  const p = project();
  try {
    const hostFiles = {
      codex: [join(p.home, '.codex', 'hooks.json'), { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: installer.localizeHookCommand(contract.PRE_ACTION_HOOK_COMMAND.replace('claude-', 'codex-'), V) }] }] } }],
      cursor: [join(p.work, '.cursor', 'hooks.json'), { version: 1, hooks: { beforeShellExecution: [{ command: installer.localizeHookCommand(contract.CURSOR_PRE_ACTION_HOOK_COMMAND, V) }] } }],
      gemini: [join(p.home, '.gemini', 'settings.json'), { hooks: { BeforeTool: [{ matcher: '.*', hooks: [{ type: 'command', command: installer.localizeHookCommand(`sh -c 'cat | ${contract.GEMINI_PRE_ACTION_HOOK_COMMAND}'`, V) }] }] } }],
      windsurf: [join(p.home, '.codeium', 'windsurf', 'hooks.json'), { hooks: { pre_run_command: [{ command: installer.localizeHookCommand(`sh -c 'cat | ${contract.WINDSURF_PRE_ACTION_HOOK_COMMAND}'`, V) }] } }],
    };
    const write = () => {
      for (const [file, body] of Object.values(hostFiles)) {
        mkdirSync(join(file, '..'), { recursive: true });
        writeFileSync(file, `${JSON.stringify(body, null, 2)}\n`);
      }
    };
    const snapshot = () => Object.fromEntries(Object.entries(hostFiles).map(([host, [file]]) => [host, p.read(file)]));
    // Installer first, then setup.
    write();
    const before = snapshot();
    p.setup();
    assert.deepEqual(snapshot(), before);
    // Setup first, then the installer, then setup again.
    for (const [file] of Object.values(hostFiles)) rmSync(file, { force: true });
    p.setup();
    write();
    const after = snapshot();
    p.setup();
    assert.deepEqual(snapshot(), after);
  } finally { p.cleanup(); }
});
