'use strict';

// Push class: every git push and gh merge the hook can read as words is a protected `review on github` call, whatever
// its spelling (quote-split or escaped program, global options before the subcommand, a shell or eval wrapper, a
// subshell or a text the parser cannot read). Every other call keeps the answer of MCP master 8cbe1a8 (recorded in
// fixtures/hook-pushclass/master-8cbe1a8-classification.json). No command in this file is ever run: each one is a string
// handed to classifyTool.

const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { stableToolCorrelation } = require('../dist/hook-contract.js');
const policy = require('../dist/hook-tool-policy.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { consultSessionLoopGuard, recordSessionLoopOutcome } = require('../dist/session-loop-guard.js');

const rows = require('./fixtures/hook-pushclass/rows.json');
const master = require('./fixtures/hook-pushclass/master-8cbe1a8-classification.json');

const FIELDS = ['action', 'target', 'type', 'role', 'surfaces', 'risk', 'protected', 'readOnly'];
const PUSH_CLASS = {
  action: 'classified Bash action: review on github',
  target: 'github:review',
  type: 'review',
  role: 'review',
  surfaces: ['github'],
  risk: 'high',
  protected: true,
  readOnly: false,
};
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const answer = (command) => {
  const classified = classifyTool(bash(command));
  return Object.fromEntries(FIELDS.map((field) => [field, classified[field]]));
};
// A device salt made at run time (never a real key); the normalized action is keyed with it.
const SALT = randomBytes(32);
const normalized = (command) => normalizedHookAction(bash(command), { salt: SALT, deadlineAt: Date.now() + 10_000 });
const payload = (command) => {
  const classified = classifyTool(bash(command));
  return { action: classified.action, fields: { risk_level: classified.risk, normalized_action: normalized(command) }, classified };
};

// The backend stop-gap (backend src/services/hook-protected-push.ts), loaded from the one file the harness names; absent in CI.
function loadStopGap() {
  const file = process.env.PUSHCLASS_BACKEND_STOPGAP;
  if (!file) return null;
  const ts = require('typescript');
  const { outputText } = ts.transpileModule(readFileSync(file, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } });
  const loaded = { exports: {} };
  new Function('module', 'exports', outputText)(loaded, loaded.exports);
  return loaded.exports;
}
const stopGap = loadStopGap();
const needsStopGap = stopGap ? {} : { skip: 'PUSHCLASS_BACKEND_STOPGAP names no backend stop-gap file (GitHub CI has none)' };

// The shape the stop-gap reads, pinned here so CI checks it too: the class text grammar, class word review, surface github, risk high.
const HOOK_CLASS_TEXT = /^classified [A-Za-z0-9_.:-]{1,64} action: ([a-z]+) on ([a-z, ]{1,160})$/;
function stopGapShape({ action, fields }) {
  const match = HOOK_CLASS_TEXT.exec(action);
  return Boolean(match) && match[1] === 'review' && match[2].split(',').map((surface) => surface.trim()).includes('github') && fields.risk_level === 'high';
}

const nest = (inner, levels) => {
  let text = inner;
  for (let level = 0; level < levels; level += 1) text = `bash -c '${text.replace(/'/g, "'\\''")}'`;
  return text;
};
const HELD = [...new Set([...rows.held, ...rows.heldMore, ...rows.heldUnparseable])];
const KEPT = [...new Set([...rows.mcp.filter((command) => command !== "g''it push origin main"), ...rows.kept, ...rows.data, ...rows.probeKeep])];

test('MP2: every parsed git push and gh merge is `review on github`, protected, risk high', () => {
  for (const command of HELD) assert.deepEqual(answer(command), PUSH_CLASS, command);
});

test('MP2: the adversarial probe rows are held as a push (type review, github, protected, risk high)', () => {
  assert.ok(rows.probeHold.length >= 50, `${rows.probeHold.length} rows`);
  for (const command of rows.probeHold) {
    const classified = classifyTool(bash(command));
    assert.equal(classified.type, 'review', command);
    assert.equal(classified.protected, true, command);
    assert.equal(classified.risk, 'high', command);
    assert.ok(classified.surfaces.includes('github'), command);
    assert.equal(stopGapShape(payload(command)), true, command);
  }
});

test('MP2: the held rows are the plain push answer of master (M01), not a new label', () => {
  assert.deepEqual(master['git push origin master'], { ...PUSH_CLASS });
  for (const command of HELD) assert.deepEqual(answer(command), master['git push origin master'], command);
});

test('MP2: a row that master already held keeps master\'s answer byte for byte', () => {
  let already = 0;
  for (const command of HELD) {
    if (master[command].type !== 'review' || master[command].protected !== true) continue;
    already += 1;
    assert.deepEqual(answer(command), master[command], command);
  }
  assert.ok(already >= 20, `only ${already} rows were held on master`);
});

test('MP2: the unparseable rows really are unparseable, so S2 decides them', () => {
  for (const command of rows.heldUnparseable) assert.equal(policy.parseShellSegments(command), null, command);
  assert.equal(policy.parseShellSegments(`echo ${'a'.repeat(9000)}`), null);
});

test('MP2: the same answer on every host shape the hook serves', () => {
  const shapes = {
    claude: (command) => ({ tool_name: 'Bash', tool_input: { command } }),
    codex: (command) => ({ tool_name: 'exec_command', tool_input: { cmd: command } }),
    cursor: (command) => ({ tool_name: 'Shell', tool_input: { command } }),
    windsurf: (command) => ({ tool_name: 'run_terminal_command', tool_input: { command } }),
    cline: (command) => ({ tool_name: 'execute_command', tool_input: { command } }),
    gemini: (command) => ({ tool_name: 'run_shell_command', tool_input: { command } }),
    monitor: (command) => ({ tool_name: 'Monitor', tool_input: { command } }),
    mcp: (command) => ({ tool_name: 'mcp__host__run', tool_input: { command } }),
  };
  for (const [host, build] of Object.entries(shapes)) {
    for (const command of rows.held) {
      const classified = classifyTool(build(command));
      assert.equal(classified.type, 'review', `${host}: ${command}`);
      assert.equal(classified.protected, true, `${host}: ${command}`);
      assert.equal(classified.risk, 'high', `${host}: ${command}`);
      assert.ok(classified.surfaces.includes('github'), `${host}: ${command}`);
    }
  }
  const powershell = classifyTool({ tool_name: 'PowerShell', tool_input: { command: "& 'git' -C r push origin main" } });
  assert.equal(powershell.type, 'review');
  assert.equal(powershell.protected, true);
  assert.equal(powershell.risk, 'high');
});

test('MP3: every other call keeps master\'s full answer byte for byte (M01-M20 except M13, kept rows, data rows)', () => {
  assert.ok(KEPT.length >= 90, `${KEPT.length} rows`);
  for (const command of KEPT) assert.deepEqual(answer(command), master[command], command);
});

test('MP3: read-only git and push words in data stay read-only and unprotected', () => {
  for (const command of ['git status', 'git log --oneline', 'git diff', "g''it status", "g''it log", 'echo git push', 'grep -n "git push" src', "echo g''it push"]) {
    const classified = classifyTool(bash(command));
    assert.equal(classified.protected, false, command);
    assert.equal(classified.readOnly, true, command);
    assert.equal(classified.risk, 'low', command);
  }
  // A commit is not a push, whatever its spelling: it never takes the push class.
  for (const command of ["g''it commit -m x", 'gi\\t commit -m x', 'git commit -m "push to master later"', "g''it fetch origin", "g''it pull origin main"]) {
    assert.deepEqual(answer(command), master[command], command);
  }
  assert.notEqual(answer("g''it commit -m x").type, 'review');
});

test('MP3: gh api on a merge path is held only when it carries a method or field flag, as master does', () => {
  for (const command of ['gh api repos/o/r/pulls/1/merge', "g''h api repos/o/r/pulls/1/merge"]) assert.deepEqual(answer(command), master[command], command);
  for (const command of ["g''h api -X PUT repos/o/r/pulls/1/merge", "g''h api -XPUT repos/o/r/pulls/1/merge", "g''h api --method put repos/o/r/pulls/1/merge", "g''h api --input body.json repos/o/r/pulls/1/merge"]) {
    assert.deepEqual(answer(command), PUSH_CLASS, command);
  }
});

test('MP3: a data position is not a program position (loops, wrappers, find, xargs, variables, alias)', () => {
  for (const command of rows.data) assert.deepEqual(answer(command), master[command], command);
});

test('S1: global options, wrappers and shell strings are read the way the shell runs them', () => {
  const cases = [
    "g''it -c alias.p=push p origin main",
    "g''it --config-env x=Y push origin main",
    "sudo -u alice g''it -C /r push origin main",
    "env -u X FOO=1 g''it -C /r push origin main",
    "timeout 5s g''it -C /r push origin main",
    "xargs -n 1 -P 2 g''it -C /r push origin",
    "time -p g''it -C /r push origin main",
    "nice -n 5 g''it -C /r push origin main",
    "bash -o pipefail -c \"g''it -C /r push origin main\"",
    "eval \"g''it -C /r push origin main\"",
    "eval g''it -C /r push origin main",
    "for b in main; do g''it -C /r push origin $b; done",
    "if g''it -C /r push origin main; then echo ok; fi",
    "echo a\ng''it -C /r push origin main",
    "echo a && g''it -C /r push origin main || echo failed",
    "  g''it   -C   /r   push  origin main  ",
    "g''it --git-dir=/r/.git --work-tree=/r push origin main",
    "g''it --namespace=n -p push origin main",
    "g''h -R o/r pr merge 1",
    "g''h pr -R o/r merge 1",
  ];
  for (const command of cases) assert.deepEqual(answer(command), PUSH_CLASS, command);
});

test('S2: a text the parser cannot read is judged by its dequoted letters; a hit is held, anything else keeps master\'s answer', () => {
  for (const command of rows.heldUnparseable) assert.deepEqual(answer(command), PUSH_CLASS, command);
  for (const command of ['echo $(date)', 'git status $(pwd)', "g''it status $(pwd)", 'echo "unterminated', 'ls {a,b}', '(cd src && ls)', 'echo $(git log --oneline)']) {
    assert.equal(policy.parseShellSegments(command), null, command);
    assert.deepEqual(answer(command), master[command], command);
  }
  // The gap between git and push is bounded and stops at a command separator: far words and other commands are not a push.
  const far = `g''it ${'a '.repeat(150)}push $(x)`;
  assert.equal(classifyTool(bash(far)).type, 'process');
  // The bound is exact: 240 characters between git and push are held, 241 are not.
  assert.equal(classifyTool(bash(`g''it ${'a'.repeat(238)} push $(x)`)).type, 'review');
  assert.equal(classifyTool(bash(`g''it ${'a'.repeat(239)} push $(x)`)).type, 'process');
  assert.equal(classifyTool(bash("g''it status $(x); echo push")).type, 'process');
  assert.equal(classifyTool(bash("g''it status $(x) && echo push")).type, 'process');
});

test('MP6: an input past the parser bound is judged by S2, and is protected whatever it says', () => {
  const pad = ` ${'a '.repeat(5000)}`;
  const pushPast = `echo ${'a'.repeat(9000)}; g''it push origin main`;
  assert.equal(policy.parseShellSegments(pushPast), null);
  // Past the bound master reads the whole text conservatively and may add surfaces (secrets); the push class is what is asserted.
  for (const command of [pushPast, `g''it push origin main${pad}`]) {
    const classified = classifyTool(bash(command));
    assert.equal(classified.type, 'review', command.slice(0, 40));
    assert.equal(classified.protected, true);
    assert.equal(classified.risk, 'high');
    assert.ok(classified.surfaces.includes('github'));
  }
  const plain = classifyTool(bash(`echo hello${pad}`));
  assert.equal(policy.parseShellSegments(`echo hello${pad}`), null);
  assert.equal(plain.protected, true);
  assert.notEqual(plain.type, 'review');
});

test('MP6: a read that throws is protected (type review on github), never not protected', () => {
  const original = policy.parseShellSegments;
  let calls = 0;
  // Only the push-class reader fails: the other readers of the same parser (self-protection, the text path) are not under test here.
  policy.parseShellSegments = (...args) => {
    if (!/readsPushOrMerge/.test(new Error().stack)) return original(...args);
    calls += 1;
    throw new Error('injected');
  };
  try {
    for (const command of ["g''it push origin main", "g''it -C /r push origin main", "bash -c \"g''it push origin main\"", "g''h pr merge 1"]) {
      assert.deepEqual(answer(command), PUSH_CLASS, command);
    }
  } finally {
    policy.parseShellSegments = original;
  }
  assert.ok(calls >= 4, 'the injected failure was reached');
  assert.deepEqual(answer("g''it -C /r push origin main"), PUSH_CLASS);
});

test('MP6: nesting is bounded: a deep chain of shell strings parses a bounded number of times and is still held', () => {
  const original = policy.parseShellSegments;
  let calls = 0;
  policy.parseShellSegments = (...args) => { calls += 1; return original(...args); };
  try {
    const text = nest('git -C r push origin main', 5);
    assert.ok(text.length < 8192);
    assert.deepEqual(answer(text), PUSH_CLASS);
    assert.ok(calls <= 5, `${calls} parses`);
  } finally {
    policy.parseShellSegments = original;
  }
});

test('MP6: growth: wrapper, option and push repeats at 8k to 1 MB are answered, held where they run a push, and stay near-linear', () => {
  const families = {
    wrappers: (size) => `${'env '.repeat(Math.ceil(size / 4))}git -C r push origin main`,
    options: (size) => `git ${'-c a=b '.repeat(Math.ceil(size / 8))}push origin main`,
    shells: (size) => `${nest('git push origin main', 5)} ${'x '.repeat(Math.ceil(size / 2))}`,
    pushes: (size) => Array.from({ length: Math.ceil(size / 20) }, () => "g''it push origin m").join(' && '),
    gitWords: (size) => 'git '.repeat(Math.ceil(size / 4)),
  };
  const sizes = [8 * 1024, 16 * 1024, 32 * 1024, 1024 * 1024];
  for (const [name, build] of Object.entries(families)) {
    const spent = [];
    for (const size of sizes) {
      const command = build(size);
      const started = process.hrtime.bigint();
      const classified = classifyTool(bash(command));
      spent.push(Number(process.hrtime.bigint() - started) / 1e6);
      // Past 8192 characters master protects any command; below it only a push is.
      if (name !== 'gitWords' || size > 8192) assert.equal(classified.protected, true, `${name} ${size}`);
      if (['wrappers', 'pushes', 'shells'].includes(name)) assert.equal(classified.type, 'review', `${name} ${size}`);
      if (name === 'gitWords') assert.notEqual(classified.type, 'review', `${name} ${size}`);
    }
    // A generous ceiling only (a quadratic or worse read would take minutes at 1 MB); the measured bounds are in the job's report.
    for (const ms of spent) assert.ok(ms < 5000, `${name}: ${spent.map((value) => value.toFixed(1)).join(' ')} ms`);
  }
});

test('MP4(a): the backend stop-gap shape holds every held row and answers every kept row as master does', () => {
  for (const command of HELD) assert.equal(stopGapShape(payload(command)), true, command);
  for (const command of ['git status', 'git log --oneline', "g''it commit -m x", 'echo git push', 'ls -la']) {
    assert.equal(stopGapShape(payload(command)), stopGapShape({ action: `classified Bash action: ${master[command].type} on ${master[command].surfaces.join(', ')}`, fields: { risk_level: master[command].risk } }), command);
  }
});

test('MP4(a): the backend holdsHookProtectedPush and isHookProtectedPushHigh are true for every held row', needsStopGap, () => {
  for (const command of HELD) {
    const { action, fields } = payload(command);
    assert.equal(stopGap.holdsHookProtectedPush({ action, fields }), true, command);
    assert.equal(stopGap.isHookProtectedPushHigh({ action, fields }), true, command);
  }
});

test('MP4(a): the stop-gap answers every other row as it did for master\'s payload', needsStopGap, () => {
  for (const command of KEPT) {
    const tip = payload(command);
    const before = { action: `classified Bash action: ${master[command].type} on ${master[command].surfaces.join(', ')}`, fields: { risk_level: master[command].risk, normalized_action: tip.fields.normalized_action } };
    assert.equal(stopGap.holdsHookProtectedPush(tip), stopGap.holdsHookProtectedPush(before), command);
    assert.equal(stopGap.isHookProtectedPushHigh(tip), stopGap.isHookProtectedPushHigh(before), command);
  }
});

test('MP4(b): the held text and the local approval categories of a held row equal those of the plain push row (M01)', () => {
  const plain = classifyTool(bash('git push origin master'));
  const plainCategories = localApprovalCategories(plain);
  for (const command of HELD) {
    const held = classifyTool(bash(command));
    assert.deepEqual(localApprovalCategories(held), plainCategories, command);
    assert.equal(held.action, plain.action, command);
    assert.equal(held.target, plain.target, command);
  }
  // Never fewer categories than master gave the same call.
  for (const command of rows.held) {
    const before = master[command];
    const now = classifyTool(bash(command));
    for (const category of localApprovalCategories(before)) assert.ok(localApprovalCategories(now).includes(category), `${command}: ${category}`);
  }
});

test('MP4(c): the decision key of a held push is its own: it differs from the matching commit and from every other spelling', () => {
  const pairs = [["g''it push origin main", "g''it commit -m x"], ['gi\\t push origin main', 'gi\\t commit -m x'], ["g''it push --force origin main", "g''it commit -m x"], ['git push origin main', 'git commit -m x']];
  for (const [push, commit] of pairs) {
    assert.notEqual(normalized(push).tool_input.command_sha256, normalized(commit).tool_input.command_sha256, `${push} / ${commit}`);
    assert.notDeepEqual(normalized(push), normalized(commit), `${push} / ${commit}`);
    assert.notEqual(classifyTool(bash(push)).action, classifyTool(bash(commit)).action, `${push} / ${commit}`);
  }
  // Two spellings share a key only when they dequote to the same words (one action); a different action never shares one.
  const spellings = [...new Set(HELD)];
  const keyOf = (command) => JSON.stringify(normalized(command).tool_input);
  const wordsOf = (command) => JSON.stringify((policy.parseShellSegments(command) || [{ words: [command] }]).map((segment) => segment.words));
  for (const a of spellings) {
    assert.ok(normalized(a).tool_input.command_sha256, a);
    for (const b of spellings) if (a < b && keyOf(a) === keyOf(b)) assert.equal(wordsOf(a), wordsOf(b), `${a} / ${b} share a key`);
  }
  assert.notEqual(keyOf("g''it push origin main"), keyOf("g''it push --force origin main"));
  assert.notEqual(keyOf("g''it push origin main"), keyOf("g''it push origin master"));
});

test('MP5 K1/K2: a push and a commit never share a class text or a key; the same push in two spellings is held each time, never shared', () => {
  for (const [push, commit] of [["g''it push origin main", "g''it commit -m x"], ['gi\\t push origin main', 'gi\\t commit -m x']]) {
    assert.notEqual(classifyTool(bash(push)).action, classifyTool(bash(commit)).action);
    assert.notEqual(normalized(push).tool_input.command_sha256, normalized(commit).tool_input.command_sha256);
  }
  const plain = payload('git push origin main');
  const split = payload("g''it push origin main");
  assert.equal(stopGapShape(plain), true);
  assert.equal(stopGapShape(split), true);
  // One action in two spellings is one key (the normalizer reads the words); it is held and asked each time, so no stored approval answers it.
  assert.equal(plain.fields.normalized_action.tool_input.command_sha256, split.fields.normalized_action.tool_input.command_sha256);
  assert.deepEqual(plain.fields.normalized_action.programs, split.fields.normalized_action.programs);
  if (stopGap) {
    assert.equal(stopGap.isHookProtectedPushHigh(plain), true);
    assert.equal(stopGap.isHookProtectedPushHigh(split), true);
  }
});

test('MP5 K3: an approved or recorded `git commit` never satisfies a dequoted push, in the local state', () => {
  const home = mkdtempSync(join(tmpdir(), 'pushclass-home-'));
  try {
    const commit = { sessionId: 'sess_pushclass', harness: 'claude-code', toolName: 'Bash', toolInput: { command: 'git commit -m x' }, readOnly: false };
    const push = { ...commit, toolInput: { command: "g''it push --force origin main" } };
    const first = consultSessionLoopGuard(commit, { home });
    assert.equal(first.allow, true);
    recordSessionLoopOutcome(commit, false, { status: 'failed' }, { home });
    recordSessionLoopOutcome(commit, false, { status: 'failed' }, { home });
    assert.equal(consultSessionLoopGuard(commit, { home }).allow, false, 'the loop guard does remember the failed commit');
    const pushed = consultSessionLoopGuard(push, { home });
    assert.equal(pushed.allow, true);
    assert.notEqual(pushed.fingerprint, first.fingerprint);
    assert.notEqual(pushed.receipt, first.receipt);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  const session = 'sess_pushclass';
  const correlation = (command) => stableToolCorrelation({ session_id: session, tool_name: 'Bash', tool_input: { command } });
  assert.notEqual(correlation("g''it push --force origin main"), correlation('git commit -m x'));
  // The same push in two spellings is one action (the normalizer reads the words), held and asked each time.
  assert.equal(correlation("g''it push --force origin main"), correlation('git push --force origin main'));
  assert.notEqual(correlation("g''it push --force origin main"), correlation("g''it push origin main"));
  assert.notEqual(correlation("g''it push origin main"), correlation("g''it commit -m x"));
});
