#!/usr/bin/env node
'use strict';

// Differential test for the first-hour fixes: the BASE build and the BRANCH build get the same events
// and must give the same DECISION TUPLE for every one. The fixes are message and output changes only,
// so the only differences allowed are the ones counted at the end of the table:
//   (a) a new `systemMessage` key on a Claude Code deny output of a hold denied for later or waiting
//       quietly (A1), or on a UserPromptSubmit output (A3);
//   (b) one extra `mode:<code>` code in the fallback texts (C4, C5).
// Anything else is a MISMATCH.
//
//   node tools/fh-diff.cjs --harness <dir with corpus.cjs probe-corpus.cjs netguard.cjs>
//        --base <base dist/cli.js> --branch <branch dist/cli.js> --out <dir> [--jobs 3] [--only <text>] [--quick]
//
// The tuple of one call:
//   exit code; stdout parsed as JSON with every text field replaced by the set of machine codes in it
//   (rule ids S0..S5/Sx/U5 with their reasons, snake_case reason codes, receipt ids as a placeholder,
//   typed-reply codes kept); stderr replaced by its code set; every file the call wrote under the fake
//   HOME (seatbelt receipts, loop-guard state, host-approval state ...) normalised only for times,
//   latencies and chain hashes; the network guard's attempt count.
// Everything random in a hook (salts, state secrets, ids) is a fixed stream (tools/fh-diff-preload.cjs),
// and the HOME of a profile has the same path for both builds, so keyed values compare byte for byte.
//
// No secret is read or written: keys and secrets here are dummies derived from the seed, nothing is
// printed except codes and counts, and no call leaves the machine (netguard, and a local fetch double
// for the keyed hooks).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const argv = process.argv.slice(2);
const opt = (name, fallback) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : fallback; };
const flag = (name) => argv.includes(name);
const HARNESS = path.resolve(opt('--harness', path.join(__dirname, '..', '..', 'in', 'harness')));
const BASE_CLI = path.resolve(opt('--base', path.join(__dirname, '..', '..', 'base', 'dist', 'cli.js')));
const BRANCH_CLI = path.resolve(opt('--branch', path.join(__dirname, '..', 'dist', 'cli.js')));
const OUT = path.resolve(opt('--out', path.join(process.cwd(), 'fh-diff-out')));
const JOBS = Math.max(1, Number(opt('--jobs', '3')));
const ONLY = opt('--only', '');
const QUICK = flag('--quick');
const DUMP = opt('--dump', '');
const SEED = opt('--seed', 'fh-diff-seed-1');
const BUILDS = [['base', BASE_CLI], ['branch', BRANCH_CLI]];

const NETGUARD = path.join(HARNESS, 'netguard.cjs');
const PRELOAD = path.join(__dirname, 'fh-diff-preload.cjs');
const { EVERYDAY, PROTECTED } = require(path.join(HARNESS, 'corpus.cjs'));
const PROBE = require(path.join(HARNESS, 'probe-corpus.cjs')).EVERYDAY;
const { EXTRA, PAIRS } = require('./fh-diff-corpus.cjs');
const keyed = require('../test/support/first-hour-harness.cjs');

// ------------------------------------------------------------------------------------ determinism

const seeded = (label, bytes = 8) => crypto.createHash('sha256').update(`${SEED}:${label}`).digest('hex').slice(0, bytes * 2);
const SECRET = { S1: `dummy_${seeded('S1', 16)}`, S2: `dummy_${seeded('S2', 16)}` };

// ------------------------------------------------------------------------------------ codes

const IGNORED_NAMES = new Set(['MARROW_API_KEY', 'MARROW_SEATBELT_STRICT', 'CLAUDE_PLUGIN_ROOT']);

function codesOf(text) {
  const t = String(text ?? '');
  const codes = new Set();
  const modes = new Set();
  const trim = (s) => s.replace(/\.$/, '');
  for (const m of t.matchAll(/Code: ([A-Za-z0-9_.:-]+)\/([A-Za-z0-9_.:-]+)/g)) { codes.add(trim(m[1])); codes.add(trim(m[2])); }
  for (const m of t.matchAll(/\(((?:S[0-5x]|Sx|U5)\.[A-Za-z0-9_]+), ([A-Za-z0-9_.:-]+)\)/g)) { codes.add(m[1]); codes.add(m[2]); }
  for (const m of t.matchAll(/; mode: ([a-z_]+)/g)) modes.add(`mode:${m[1]}`);
  for (const m of t.matchAll(/Code: ([a-z_]+)\.(?:\s|$)/g)) modes.add(`mode:${m[1]}`);
  for (const m of t.matchAll(/\b(?:S[0-5x]|Sx|U5)\.[a-z0-9_]+/g)) codes.add(m[0]);
  for (const m of t.matchAll(/\blgr_[0-9a-f]{24}\b/g)) codes.add('<receipt>');
  for (const m of t.matchAll(/gate receipt [A-Za-z0-9_.:-]+/g)) codes.add('<gate-receipt>');
  for (const m of t.matchAll(/approve ([A-Z2-9]{6})\b/g)) codes.add(`code:${m[1]}`);
  for (const m of t.matchAll(/\b[a-z]+(?:_[a-z0-9]+)+\b/g)) if (![...modes].includes(`mode:${m[0]}`)) codes.add(m[0]);
  for (const m of t.matchAll(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g)) if (!IGNORED_NAMES.has(m[0])) codes.add(m[0]);
  // A mode code that is also a snake_case word was added above; keep only the `mode:` form for it.
  for (const mode of modes) codes.delete(mode.slice(5));
  return { codes: [...codes].sort(), modes: [...modes].sort() };
}

const STRUCTURAL = new Set(['permissionDecision', 'permission', 'decision', 'cancel', 'continue', 'hookEventName']);
const TEXT_KEYS = new Set(['permissionDecisionReason', 'reason', 'stopReason', 'systemMessage', 'additionalContext', 'errorMessage', 'user_message', 'agent_message', 'message']);
const NOTICE_A1 = /^Marrow is holding (?:a|an) [a-z -]+ for your approval\. (?:Approving in chat does not count\. Press Shift\+Tab until Claude Code is in default mode, then tell the agent to retry; Claude Code will ask you\.|Nobody can approve it in this run, and a chat reply does not count\. Your next interactive Claude Code session shows it\.)$/;
const NOTICE_A3 = 'Marrow did not record that as an approval: a chat reply cannot approve a held action. To approve it, put Claude Code in default mode (Shift+Tab), then ask the agent to retry; Claude Code will ask you.';
const freeTextKeys = new Set();

// Text fields become code sets; other strings that are not structural are treated as text and listed.
function normalizeJson(value, keyName, state) {
  if (typeof value === 'string') {
    if (STRUCTURAL.has(keyName)) return value;
    if (!TEXT_KEYS.has(keyName)) freeTextKeys.add(keyName || '(root)');
    const { codes, modes } = codesOf(value);
    state.modes.push(...modes);
    return { codes };
  }
  if (Array.isArray(value)) return value.map((item) => normalizeJson(item, keyName, state));
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = normalizeJson(value[key], key, state);
    return out;
  }
  return value;
}

function normalizeStdout(raw) {
  const state = { modes: [] };
  const text = String(raw ?? '').trim();
  if (text === '') return { value: '', modes: [], system: null };
  let parsed;
  try { parsed = JSON.parse(text); } catch { const c = codesOf(text); return { value: { nonJson: c.codes }, modes: c.modes, system: null }; }
  const system = parsed && typeof parsed === 'object' && typeof parsed.systemMessage === 'string' ? parsed.systemMessage : null;
  return { value: normalizeJson(parsed, '', state), modes: state.modes.sort(), system };
}

// ------------------------------------------------------------------------------------ files

const TIME_KEY = /(^|_)(at|ts|time|timestamp|expires|expiry|created|updated|latency|ms)(_|$)|latency|ts_label|^mtime/i;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?$/;
const CHAIN_KEYS = new Set(['prev', 'prev_hash', 'hash', 'chain', 'chain_hash', 'mac', 'seq']);

function scrub(value, keyName) {
  if (typeof value === 'string') {
    if (ISO.test(value)) return '<t>';
    // An event id names its payload, which carries a time: the id is kept, the payload hash is not compared.
    return value.replace(/^((?:pretool|prompt|preaction|posttool|session)-[0-9a-f]{16,}-)[0-9a-f]{12}$/, '$1<payload>');
  }
  if (typeof value === 'number') return TIME_KEY.test(keyName || '') || value > 1.4e9 ? '<t>' : value;
  if (Array.isArray(value)) return value.map((item) => scrub(item, keyName));
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (CHAIN_KEYS.has(key)) { out[key] = '<chain>'; continue; }
      out[key] = TIME_KEY.test(key) && typeof value[key] !== 'object' ? '<t>' : scrub(value[key], key);
    }
    return out;
  }
  return value;
}

const SKIP_DIRS = new Set(['.git', 'node_modules']);
function walk(root) {
  const out = new Map();
  const visit = (dir) => {
    let names;
    try { names = fs.readdirSync(dir).sort(); } catch { return; }
    for (const name of names) {
      const file = path.join(dir, name);
      let stat;
      try { stat = fs.lstatSync(file); } catch { continue; }
      const rel = path.relative(root, file);
      if (stat.isDirectory()) { if (!SKIP_DIRS.has(name)) { out.set(rel, `dir:${(stat.mode & 0o777).toString(8)}`); visit(file); } continue; }
      if (stat.isSymbolicLink()) { out.set(rel, 'link'); continue; }
      let content = '';
      try { content = stat.size <= 1_000_000 ? fs.readFileSync(file, 'utf8') : `big:${stat.size}`; } catch { content = 'unreadable'; }
      out.set(rel, `${(stat.mode & 0o777).toString(8)}:${content}`);
    }
  };
  visit(root);
  return out;
}

function normPath(rel) {
  return rel.replace(/\d{4}-\d{2}-\d{2}/g, '<date>').replace(/[a-f0-9]{12,}/g, '<hex>').replace(/\.tmp$/, '.tmp');
}

function normContent(rel, entry, previous) {
  if (entry.startsWith('dir:')) return entry;
  const idx = entry.indexOf(':');
  const mode = entry.slice(0, idx);
  const body = entry.slice(idx + 1);
  if (rel.endsWith('.jsonl')) {
    const old = previous ? previous.slice(previous.indexOf(':') + 1).split('\n').filter(Boolean) : [];
    const lines = body.split('\n').filter(Boolean);
    const added = lines.slice(old.length);
    return { mode, lines: added.map((line) => { try { return scrub(JSON.parse(line), ''); } catch { return 'unparsed'; } }) };
  }
  if (rel.endsWith('.json')) {
    try { return { mode, json: scrub(JSON.parse(body), '') }; } catch { return { mode, text: 'unparsed' }; }
  }
  return { mode, size: body.length > 0 ? 'nonempty' : 'empty' };
}

// What changed between two walks: new and changed files, normalised.
function delta(before, after) {
  const out = {};
  for (const [rel, entry] of after) {
    const prev = before.get(rel);
    if (prev === entry) continue;
    out[normPath(rel)] = normContent(rel, entry, prev);
  }
  return out;
}

// ------------------------------------------------------------------------------------ running hooks

function runHook(cli, entry, event, env, cwd, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, entry], { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000);
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', () => { clearTimeout(timer); resolve({ status: -1, stdout, stderr }); });
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
    child.stdin.on('error', () => {});
    child.stdin.end(input === undefined ? JSON.stringify(event) : input);
  });
}

// ------------------------------------------------------------------------------------ the fixture

function buildHome(homeDir, label) {
  const rnd = (n = 8) => seeded(`${label}:${rnd.n = (rnd.n || 0) + 1}`, n);
  fs.rmSync(path.dirname(homeDir), { recursive: true, force: true });
  fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(homeDir, 0o700);
  const WS = path.join(homeDir, 'work', 'demo-app');
  const W = (rel, content, mode) => { const p = path.join(WS, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content, mode ? { mode } : undefined); };
  fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(homeDir, '.claude', 'settings.json'), JSON.stringify({ enabledPlugins: { 'marrow@getmarrow': true }, hooks: {} }, null, 2), { mode: 0o600 });
  fs.mkdirSync(path.join(homeDir, '.ssh'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(homeDir, '.ssh', 'id_ed25519'), `dummy-not-a-key ${rnd(32)}\n`, { mode: 0o600 });
  W('package.json', JSON.stringify({ name: 'demo-app', version: '0.1.0', scripts: { dev: 'node server.js', test: 'vitest run', build: 'tsc', lint: 'eslint .', typecheck: 'tsc --noEmit' } }, null, 2));
  W('README.md', '# demo-app\n');
  W('tsconfig.json', '{}\n');
  W('src/app.ts', 'export const app = 1;\n');
  W('src/old.ts', 'export const old = 1;\n');
  W('src/config.ts', 'export const config = {\n  port: Number(process.env.PORT || 3000),\n  apiToken: process.env.API_TOKEN,\n};\n');
  W('.env.example', 'PORT=3000\nAPI_TOKEN=\n');
  W('.env', `PORT=3000\nDATABASE_URL=postgres://app:${rnd(12)}@db.internal.example:5432/app\nAPI_TOKEN=dummy_${rnd(16)}\n`, 0o600);
  W('.gitignore', 'node_modules\ndist\n.env\n.env.local\n.venv\n');
  W('docker-compose.yml', 'services:\n  api:\n    build: .\n    ports: ["3000:3000"]\n');
  W('Dockerfile', 'FROM node:22\nCOPY . .\nRUN npm ci\nCMD ["npm","run","dev"]\n');
  W('Makefile', 'test:\n\tnpm test\n');
  W('requirements.txt', 'pytest\n');
  W('scripts/dev.sh', '#!/bin/sh\necho dev\n');
  W('scripts/seed.py', 'print("seeded")\n');
  W('scripts/migrate.js', 'console.log("migrate")\n');
  W('.github/workflows/ci.yml', 'jobs:\n  test:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n');
  W('packages/ui/package.json', JSON.stringify({ name: '@demo/ui', version: '0.0.1' }));
  const gitEnv = { PATH: process.env.PATH, HOME: homeDir, GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z', GIT_CONFIG_NOSYSTEM: '1' };
  const git = (...a) => spawnSync('git', ['-c', 'user.name=Dev', '-c', 'user.email=dev@example.com', '-c', 'init.defaultBranch=main', ...a], { cwd: WS, env: gitEnv, encoding: 'utf8' });
  const remote = path.join(homeDir, 'remote', 'demo-app.git');
  fs.mkdirSync(remote, { recursive: true });
  spawnSync('git', ['init', '-q', '--bare', '-b', 'main', remote], { env: gitEnv });
  git('init', '-q', '-b', 'main'); git('add', '-A'); git('commit', '-q', '-m', 'init');
  git('remote', 'add', 'origin', remote); git('push', '-q', 'origin', 'main');
  git('checkout', '-q', '-b', 'feat/login-form');
  fs.mkdirSync(path.join(homeDir, 'scratch'), { mode: 0o700 });
  return { WS, scratch: path.join(homeDir, 'scratch') };
}

// ------------------------------------------------------------------------------------ events

const subst = (value, WS, HOME) => JSON.parse(JSON.stringify(value)
  .split('{{WS}}').join(WS).split('{{HOME}}').join(HOME).split('{{S1}}').join(SECRET.S1).split('{{S2}}').join(SECRET.S2));

// One event per entrypoint for a Bash command; other tools only exist for Claude Code.
function eventFor(entry, item, ctx) {
  const input = subst(item.input, ctx.WS, ctx.HOME);
  const sid = ctx.session;
  const toolUseId = `toolu_${item.id}`;
  if (entry === 'claude') {
    const base = { session_id: sid, transcript_path: path.join(ctx.HOME, '.claude', 'projects', 'demo', `${sid}.jsonl`), cwd: ctx.WS, tool_name: item.tool, tool_input: input, tool_use_id: toolUseId };
    if (ctx.permissionMode !== undefined) base.permission_mode = ctx.permissionMode;
    if (ctx.permissionMode === 'auto' && ctx.scratchpad) base.scratchpad_dir = ctx.scratch;
    return { ...base, hook_event_name: 'PreToolUse' };
  }
  if (item.tool !== 'Bash') return null;
  const command = input.command;
  switch (entry) {
    case 'codex': return { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: toolUseId, tool_name: 'Bash', tool_input: { command }, cwd: ctx.WS };
    case 'cursor': return { hook_event_name: 'beforeShellExecution', conversation_id: sid, generation_id: 'g1', command, cwd: ctx.WS };
    case 'gemini': return { session_id: sid, hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: ctx.WS };
    case 'grok': return { hookEventName: 'PreToolUse', sessionId: sid, toolUseId, toolName: 'run_terminal_command', toolInput: { command }, cwd: ctx.WS };
    case 'cline': return { hookName: 'PreToolUse', taskId: sid, workspaceRoots: [ctx.WS], preToolUse: { toolName: 'execute_command', parameters: { command } } };
    case 'windsurf': return { agent_action_name: 'pre_run_command', trajectory_id: sid, execution_id: toolUseId, tool_info: { command_line: command, cwd: ctx.WS } };
    default: throw new Error(`unknown entry ${entry}`);
  }
}

const ENTRYPOINT = (entry) => `${entry}-pre-action-hook`;

// ------------------------------------------------------------------------------------ keyless runs

// A profile = a fake machine: where HOME is, who the passwd home is, what is wrong with it.
//   passwd 'home'  : the passwd home is the fixture folder (a new user: HOME == passwd home)
//   homeEnv 'other': $HOME is another real folder (the untrusted-home fallback: home_mismatch)
//   homeEnv 'gone' : $HOME is a folder that does not exist
function profileList() {
  const main = { corpora: ['main', 'probe', 'extra'] };
  const p = [
    { name: 'isolated-default-fake', mode: 'isolated', permissionMode: 'default', ...main },
    { name: 'session-default-fake', mode: 'session', permissionMode: 'default', ...main },
    { name: 'isolated-auto-fake', mode: 'isolated', permissionMode: 'auto', scratchpad: true, ...main },
    { name: 'isolated-default-real(HOME!=passwd home)', mode: 'isolated', permissionMode: 'default', homeEnv: 'other', ...main },
    { name: 'forced-strict', mode: 'isolated', permissionMode: 'default', strict: true, ...main },
    { name: 'forced-HOME-missing', mode: 'isolated', permissionMode: 'default', homeEnv: 'gone', ...main },
    { name: 'forced-claude-dir-group-writable', mode: 'isolated', permissionMode: 'default', claudeMode: 0o770, ...main },
    { name: 'forced-claude-dir-world-writable', mode: 'isolated', permissionMode: 'default', claudeMode: 0o777, ...main },
  ];
  // permission_mode matrix: the 10 controls and the fallback rows, on a normal and on a fallback machine.
  const modes = [['default', 'default'], ['acceptEdits', 'acceptEdits'], ['auto+scratchpad', 'auto'], ['auto', 'auto'], ['plan', 'plan'], ['dontAsk', 'dontAsk'], ['bypassPermissions', 'bypassPermissions'], ['unknown-string', 'madeUpMode'], ['missing', undefined]];
  for (const [label, pm] of modes) {
    for (const [mname, homeEnv] of [['fake', undefined], ['real', 'other']]) {
      p.push({ name: `pm:${label}:${mname}`, mode: 'isolated', permissionMode: pm, scratchpad: label === 'auto+scratchpad', homeEnv, corpora: ['rows'] });
    }
  }
  // every pre-action entrypoint, the same rows
  for (const entry of ['codex', 'cursor', 'gemini', 'windsurf', 'cline', 'grok']) {
    for (const [mname, homeEnv] of [['fake', undefined], ['real', 'other']]) {
      p.push({ name: `entry:${entry}:${mname}`, mode: 'isolated', permissionMode: 'default', entry, homeEnv, corpora: ['rows'] });
    }
  }
  return p;
}

function itemsFor(profile, rows) {
  const out = [];
  for (const corpus of profile.corpora) {
    if (corpus === 'main') out.push(...EVERYDAY, ...PROTECTED);
    else if (corpus === 'probe') out.push(...PROBE);
    else if (corpus === 'extra') out.push(...EXTRA);
    else if (corpus === 'rows') out.push(...[...EVERYDAY, ...PROTECTED, ...PROBE].filter((it) => rows.has(it.id)));
  }
  return QUICK ? out.filter((_, i) => i % 9 === 0) : out;
}

async function runProfileBuild(profile, build, cli, rows) {
  const homeDir = path.join(OUT, 'homes', profile.name.replace(/[^A-Za-z0-9_.-]/g, '_'), 'home');
  const { WS, scratch } = buildHome(homeDir, profile.name);
  if (profile.claudeMode) fs.chmodSync(path.join(homeDir, '.claude'), profile.claudeMode);
  const root = path.dirname(homeDir);
  const gone = path.join(root, 'gone');
  const other = path.join(root, 'other-home');
  if (profile.homeEnv === 'other') fs.mkdirSync(other, { mode: 0o700 });
  const homeEnv = profile.homeEnv === 'gone' ? gone : profile.homeEnv === 'other' ? other : homeDir;
  const netlog = path.join(root, 'netguard.log');
  const entry = profile.entry || 'claude';
  const env = {
    PATH: process.env.PATH, HOME: homeEnv, USER: process.env.USER || 'dev', LOGNAME: process.env.LOGNAME || 'dev', LANG: 'C.UTF-8',
    CLAUDE_PROJECT_DIR: WS, CLAUDE_CODE_ENTRYPOINT: 'cli', NETGUARD_LOG: netlog, FAKE_PASSWD_HOME: homeDir,
    NODE_OPTIONS: `--require ${NETGUARD} --require ${PRELOAD}`, FHD_SEED: SEED, FHD_ROOMY: '1', MARROW_HOOK_BACKGROUND_NUDGE: 'false',
    ...(profile.strict ? { MARROW_SEATBELT_STRICT: '1' } : {}),
  };
  const items = itemsFor(profile, rows);
  const results = [];
  let session = `sess-${seeded(`${profile.name}:session`, 6)}`;
  for (const item of items) {
    if (profile.mode === 'isolated') session = `sess-${item.id}-${seeded(`${profile.name}:${item.id}`, 3)}`;
    const ctx = { HOME: homeDir, WS, scratch, session, permissionMode: profile.permissionMode, scratchpad: profile.scratchpad };
    const event = eventFor(entry, item, ctx);
    if (!event) continue;
    const before = walk(homeDir);
    const netBefore = fs.existsSync(netlog) ? fs.readFileSync(netlog, 'utf8').split('\n').filter(Boolean).length : 0;
    const pre = await runHook(cli, ENTRYPOINT(entry), event, env, WS);
    let post = null;
    if (profile.mode === 'session' && item.post && entry === 'claude' && /^$|\{\}/.test(pre.stdout.trim() || '{}') && pre.status === 0) {
      const ev = item.post.ok
        ? { ...event, hook_event_name: 'PostToolUse', tool_response: subst(item.post.resp, WS, homeDir) }
        : { ...event, hook_event_name: 'PostToolUseFailure', error: item.post.error, is_interrupt: false };
      post = await runHook(cli, 'claude-hook', ev, env, WS);
    }
    const after = walk(homeDir);
    const netAfter = fs.existsSync(netlog) ? fs.readFileSync(netlog, 'utf8').split('\n').filter(Boolean).length : 0;
    results.push({ id: item.id, entry, event: { entry, tool: item.tool }, pre, post, files: delta(before, after), net: netAfter - netBefore });
  }
  fs.rmSync(root, { recursive: true, force: true });
  return results;
}

// ------------------------------------------------------------------------------------ comparison

function tupleOf(call) {
  const out = normalizeStdout(call.pre.stdout);
  const err = codesOf(call.pre.stderr);
  const post = call.post ? { exit: call.post.status, stdout: normalizeStdout(call.post.stdout).value, stderr: codesOf(call.post.stderr).codes } : null;
  return { exit: call.pre.status, stdout: out.value, modes: [...out.modes, ...err.modes].sort(), stderr: err.codes, system: out.system, post, files: call.files, net: call.net };
}

const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));

// Compares one pair. Returns { kind: 'identical' | 'A1' | 'A3' | 'B' | 'mismatch', detail }.
function comparePair(base, branch, meta) {
  const a = tupleOf(base);
  const b = tupleOf(branch);
  const A = { ...a, system: undefined, modes: undefined };
  const B = { ...b, system: undefined, modes: undefined };
  // (a) a new user-only line on a Claude Code deny output (A1) or a UserPromptSubmit output (A3).
  let kinds = [];
  if (b.system !== null && a.system === null) {
    const denyOut = b.stdout && b.stdout.hookSpecificOutput && b.stdout.hookSpecificOutput.permissionDecision === 'deny';
    if (meta.entry === 'claude' && meta.event === 'PreToolUse' && denyOut && NOTICE_A1.test(b.system)) kinds.push('A1');
    else if (meta.entry === 'claude' && meta.event === 'UserPromptSubmit' && b.system === NOTICE_A3) kinds.push('A3');
    else return { kind: 'mismatch', detail: `unexpected new systemMessage (${meta.entry}/${meta.event})` };
    if (B.stdout && typeof B.stdout === 'object') { const s = { ...B.stdout }; delete s.systemMessage; B.stdout = s; }
  } else if (b.system !== null && a.system !== null) {
    // both have one: the code sets are already inside stdout
  }
  // (b) one extra mode:<code> in a fallback text.
  const extraModes = b.modes.filter((m) => !a.modes.includes(m));
  const lostModes = a.modes.filter((m) => !b.modes.includes(m));
  if (lostModes.length) return { kind: 'mismatch', detail: `mode codes lost: ${lostModes.join(',')}` };
  if (extraModes.length) kinds.push('B');
  const sameTuple = canon(A) === canon(B);
  if (!sameTuple) {
    const keys = Object.keys(A).filter((k) => canon(A[k]) !== canon(B[k]));
    return { kind: 'mismatch', detail: `differs in: ${keys.join(',')}`, base: A, branch: B, keys };
  }
  return { kind: kinds.length ? kinds.join('+') : 'identical' };
}

// ------------------------------------------------------------------------------------ keyed runs

function keyedPlan() {
  const SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';
  const deploy = (over = {}) => ({ ...keyed.fixture('claude-pre-tool-use.json'), ...over });
  const prompt = (text, over = {}) => ({ ...keyed.fixture('claude-user-prompt-submit.json'), prompt: text, ...over });
  const hello = { entry: 'claude-context-hook', event: prompt('hello'), label: 'first prompt' };
  const plans = [];
  const add = (name, runtime, steps, extra = {}) => plans.push({ name, runtime, steps, ...extra });
  const hostRuntime = keyed.hostRuntime();
  for (const [label, pm] of [['default', 'default'], ['acceptEdits', 'acceptEdits'], ['auto+scratchpad', 'auto'], ['plan', 'plan'], ['dontAsk', 'dontAsk'], ['bypassPermissions', 'bypassPermissions'], ['unknown-string', 'madeUpMode']]) {
    add(`keyed:claude:${label}:hold`, hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: pm }), label: 'hold' }, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: pm, tool_use_id: 'toolu_retry' }), label: 'retry' }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes' }, { entry: 'claude-context-hook', event: prompt('approve it'), label: 'approve' }]);
  }
  add('keyed:claude:auto-no-scratchpad', hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: (() => { const e = deploy({ permission_mode: 'auto' }); delete e.scratchpad_dir; return e; })(), label: 'auto no scratchpad' }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes' }]);
  add('keyed:claude:missing-mode', hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: (() => { const e = deploy(); delete e.permission_mode; return e; })(), label: 'no permission_mode' }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes' }]);
  for (const entrypoint of ['sdk-cli', 'sdk-ts', 'cli']) {
    add(`keyed:claude:headless:${entrypoint}`, hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: deploy(), env: { CLAUDE_CODE_ENTRYPOINT: entrypoint }, label: 'hold' }, { entry: 'claude-pre-action-hook', event: deploy({ tool_use_id: 'toolu_retry' }), env: { CLAUDE_CODE_ENTRYPOINT: entrypoint }, label: 'retry' }, { entry: 'claude-context-hook', event: prompt('ok'), label: 'ok' }]);
  }
  add('keyed:claude:headless:owner-ping', keyed.hostRuntime('gate-held', { unattended_owner_ping: true, approval_link_available: true, approval_link_reason: 'unattended_owner_ping', approval_link_endpoint: '/v1/agent/gate-receipts/gate-held/approval-link' }), [hello, { entry: 'claude-pre-action-hook', event: deploy(), env: { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' }, label: 'hold' }]);
  add('keyed:claude:owner-locked', keyed.ownerLockedRuntime(), [hello, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: 'plan' }), label: 'plan' }, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: 'default', tool_use_id: 'toolu_d' }), label: 'default' }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes' }]);
  add('keyed:claude:two-kinds', keyed.hostRuntime('gate-held', { approval_categories: ['production_deploy', 'package_publish'] }), [hello, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: 'plan' }), label: 'plan' }]);
  add('keyed:claude:dialog-then-yes', hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: deploy(), label: 'dialog ask' }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes after dialog' }, { entry: 'claude-permission-request-hook', event: keyed.fixture('claude-permission-request.json'), label: 'permission request' }, { entry: 'claude-hook', event: keyed.fixture('claude-post-tool-use.json'), label: 'post tool use' }, { entry: 'claude-pre-action-hook', event: deploy({ tool_use_id: 'toolu_again' }), label: 'again' }]);
  add('keyed:claude:cross-session', hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: 'plan' }), label: 'plan hold' }, { entry: 'claude-context-hook', event: prompt('hello', { session_id: 'other-session-b' }), label: 'first prompt, other session' }, { entry: 'claude-context-hook', event: prompt('approve', { session_id: 'other-session-b' }), label: 'approve in session B' }, { entry: 'claude-context-hook', event: (() => { const e = prompt('approve'); delete e.session_id; return e; })(), label: 'approve, no session id' }, { entry: 'claude-context-hook', event: prompt('yes please deploy'), label: 'not a reply' }]);
  for (const damage of ['unsafe-dir', 'corrupt']) {
    add(`keyed:claude:state-${damage}`, hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: deploy({ permission_mode: 'plan' }), label: 'hold' }, { damage, label: `damage ${damage}` }, { entry: 'claude-context-hook', event: prompt('yes'), label: 'yes' }, { entry: 'claude-context-hook', event: prompt('what happened?'), label: 'other' }]);
  }
  // other hosts, one hold each (unchanged output expected)
  add('keyed:codex:hold', hostRuntime, [{ entry: 'codex-pre-action-hook', event: keyed.fixture('codex-pre-tool-use.json'), label: 'hold' }, { entry: 'codex-context-hook', event: keyed.fixture('codex-user-prompt-submit.json'), label: 'prompt' }]);
  add('keyed:cursor:hold', hostRuntime, [{ entry: 'cursor-pre-action-hook', event: keyed.fixture('cursor-before-shell.json'), label: 'hold' }]);
  add('keyed:gemini:hold', hostRuntime, [{ entry: 'gemini-pre-action-hook', event: keyed.fixture('gemini-before-tool.json'), label: 'hold' }]);
  add('keyed:grok:hold', hostRuntime, [{ entry: 'grok-pre-action-hook', event: keyed.fixture('grok-pre-tool-use.json'), label: 'hold' }]);
  // the approval binding: approve `git push`, then `git push --force origin main` is a different action
  const git = (command) => deploy({ tool_input: { command, description: 'git' }, tool_use_id: `toolu_${seeded(command, 4)}` });
  add('keyed:binding:push-then-force', hostRuntime, [hello, { entry: 'claude-pre-action-hook', event: git('git push'), label: 'git push' }, { entry: 'claude-pre-action-hook', event: git('git push --force origin main'), label: 'force push' }, { entry: 'claude-pre-action-hook', event: git('git push'), label: 'git push again' }, { entry: 'claude-pre-action-hook', event: git('git  push'), label: 'git  push (double space)' }]);
  // keys and secrets: the request bodies carry the normalised action and its keyed hash
  const secretActions = [
    `curl -H "Authorization: Bearer ${SECRET.S1}" "https://api.example.test/v1/items?mode=read"`,
    `curl -H "Authorization: Bearer ${SECRET.S2}" "https://api.example.test/v1/items?mode=read"`,
    `curl -H "Authorization: Bearer ${SECRET.S1}" "https://api.example.test/v1/items?mode=write"`,
    `curl "https://api.example.test/v1/items?token=${SECRET.S1}&mode=read"`,
    `curl "https://api.example.test/v1/items?token=${SECRET.S2}&mode=read"`,
    `curl "https://api.example.test/v1/items?token=${SECRET.S1}&mode=write"`,
    `API_TOKEN=${SECRET.S1} npm run dev`, `API_TOKEN=${SECRET.S2} npm run dev`, `API_TOKEN=${SECRET.S1} npm run build`,
    `curl -d '{"password":"${SECRET.S1}","op":"read"}' https://api.example.test/v1/login`, `curl -d '{"password":"${SECRET.S2}","op":"read"}' https://api.example.test/v1/login`, `curl -d '{"password":"${SECRET.S1}","op":"write"}' https://api.example.test/v1/login`,
    `mytool --token ${SECRET.S1} --mode read`, `mytool --token ${SECRET.S2} --mode read`, `mytool --token ${SECRET.S1} --mode write`,
    `npx wrangler deploy --env production --api-token ${SECRET.S1}`, `npx wrangler deploy --env production --api-token ${SECRET.S2}`, `npx wrangler deploy --env staging --api-token ${SECRET.S1}`,
  ];
  add('keyed:secrets:actions', hostRuntime, [hello, ...secretActions.map((command, i) => ({ entry: 'claude-pre-action-hook', event: git(command), label: `secret action ${i}` }))]);
  return plans;
}

async function runKeyedPlan(plan, build, cli) {
  const homeRoot = path.join(OUT, 'homes', `${plan.name.replace(/[^A-Za-z0-9_.-]/g, '_')}`);
  fs.rmSync(homeRoot, { recursive: true, force: true });
  fs.mkdirSync(homeRoot, { recursive: true });
  const dir = path.join(homeRoot, 'run');
  const apiKey = `mrw_test_${seeded(`key:${plan.name}`, 16)}`;
  const h = keyed.keyedHarness({ cli, dir, apiKey, nodeOptions: [NETGUARD, PRELOAD, keyed.MOCK], extraEnv: { FHD_SEED: SEED, FHD_ROOMY: '1', FAKE_PASSWD_HOME: path.join(dir, 'home'), NETGUARD_LOG: path.join(homeRoot, 'netguard.log') } });
  h.setConfig({ runtime: plan.runtime, status: { 'gate-held': 'pending', 'gate-locked': 'pending' } });
  const calls = [];
  try {
    for (const step of plan.steps) {
      if (step.damage) {
        const statePath = h.statePath;
        if (step.damage === 'unsafe-dir') fs.chmodSync(path.dirname(statePath), 0o755);
        if (step.damage === 'corrupt') fs.writeFileSync(statePath, 'not json at all', { mode: 0o600 });
        calls.push({ id: step.label, entry: 'damage', event: { entry: 'damage', tool: '-' }, pre: { status: 0, stdout: '', stderr: '' }, post: null, files: {}, net: 0 });
        continue;
      }
      const before = walk(path.join(dir, 'home'));
      const reqBefore = h.requests().length;
      const out = await h.runAsync(step.entry, step.event, step.env || {});
      const after = walk(path.join(dir, 'home'));
      const requests = h.requests().slice(reqBefore).map((r) => ({ method: r.method, path: r.path, body: scrub(r.body, ''), session: r.session ? '<session>' : null, agent: r.agent }));
      calls.push({
        id: step.label, entry: step.entry.startsWith('claude') ? 'claude' : step.entry.split('-')[0], event: { entry: step.entry, tool: '-', event: step.event.hook_event_name },
        pre: out, post: null, files: { ...delta(before, after), '<requests>': requests }, net: 0,
      });
    }
  } finally { h.cleanup(); fs.rmSync(homeRoot, { recursive: true, force: true }); }
  return calls;
}

// ------------------------------------------------------------------------------------ main

async function pool(tasks, limit) {
  const results = new Array(tasks.length);
  let next = 0;
  const worker = async () => { while (next < tasks.length) { const i = next; next += 1; results[i] = await tasks[i](); } };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

function eventName(call) {
  return call.event.event || (call.event.entry === 'claude' ? 'PreToolUse' : 'PreToolUse');
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  for (const [, cli] of BUILDS) if (!fs.existsSync(cli)) throw new Error(`missing build: ${cli}`);
  const started = Date.now();
  const all = profileList().filter((p) => !ONLY || p.name.includes(ONLY));
  // The rows that matter for the matrix: the 10 controls and everything a fallback machine holds at base.
  const rowsProfile = { name: 'rows-pass', mode: 'isolated', permissionMode: 'default', homeEnv: 'other', corpora: ['main', 'probe'] };
  const probeRows = await runProfileBuild(rowsProfile, 'base', BASE_CLI, new Set());
  const rows = new Set(PROTECTED.map((p) => p.id));
  for (const r of probeRows) {
    const t = tupleOf(r);
    const held = r.pre.status !== 0 || (typeof t.stdout === 'object' && t.stdout !== null && Object.keys(t.stdout).length > 0 && JSON.stringify(t.stdout) !== '{}');
    if (held) rows.add(r.id);
  }
  console.log(`rows for the matrix: ${rows.size} (10 controls + ${rows.size - 10} held on a fallback machine)`);

  const summary = [];
  const mismatches = [];
  const tasks = all.map((profile) => async () => {
    const per = {};
    for (const [build, cli] of BUILDS) per[build] = await runProfileBuild(profile, build, cli, rows);
    const counts = { rows: 0, identical: 0, A1: 0, A3: 0, B: 0, mismatch: 0, net: 0 };
    const pairs = new Map();
    for (let i = 0; i < per.base.length; i += 1) {
      const a = per.base[i];
      const b = per.branch[i];
      counts.rows += 1;
      counts.net += (a.net || 0) + (b.net || 0);
      const verdict = a.id === b.id ? comparePair(a, b, { entry: a.entry, event: 'PreToolUse' }) : { kind: 'mismatch', detail: 'row order differs' };
      if (verdict.kind === 'identical') counts.identical += 1;
      else if (verdict.kind === 'mismatch') { counts.mismatch += 1; mismatches.push({ profile: profile.name, id: a.id, ...verdict }); }
      else for (const k of verdict.kind.split('+')) counts[k] += 1;
      pairs.set(a.id, { a, b });
      if (DUMP && a.id === DUMP) console.log(`--- ${profile.name} ${a.id}\nbase ${JSON.stringify(tupleOf(a), null, 1)}\nbranch ${JSON.stringify(tupleOf(b), null, 1)}`);
    }
    // secret pairs: the same relation (same / different action key) in both builds
    const relationFailures = [];
    if (profile.corpora.includes('extra')) {
      const key = (call) => { const files = Object.entries(call.files).filter(([name]) => name.includes('receipts')).map(([, v]) => v); const last = files.length ? (files[0].lines || []).at(-1) : null; return last ? last.action_key ?? null : null; };
      for (const pair of PAIRS) {
        const x = pairs.get(pair.a); const y = pairs.get(pair.b);
        if (!x || !y) continue;
        const rel = (side) => { const ka = key(x[side]); const kb = key(y[side]); return ka === null || kb === null ? 'unknown' : ka === kb ? 'same' : 'different'; };
        const base = rel('a'); const branch = rel('b');
        if (base !== branch) relationFailures.push({ ...pair, base, branch });
        counts.pairs = (counts.pairs || 0) + 1;
        counts.pairKinds = counts.pairKinds || {};
        counts.pairKinds[`${pair.relation}:${base}`] = (counts.pairKinds[`${pair.relation}:${base}`] || 0) + 1;
      }
    }
    if (relationFailures.length) { counts.mismatch += relationFailures.length; mismatches.push({ profile: profile.name, id: 'pairs', kind: 'mismatch', detail: JSON.stringify(relationFailures) }); }
    summary.push({ profile: profile.name, entry: profile.entry || 'claude', ...counts });
    process.stdout.write(`done ${profile.name}: ${counts.rows} rows, ${counts.identical} identical, A1 ${counts.A1}, A3 ${counts.A3}, B ${counts.B}, mismatch ${counts.mismatch}\n`);
  });
  const keyedPlans = keyedPlan().filter((p) => !ONLY || p.name.includes(ONLY));
  const keyedTasks = keyedPlans.map((plan) => async () => {
    const per = {};
    for (const [build, cli] of BUILDS) per[build] = await runKeyedPlan(plan, build, cli);
    const counts = { rows: 0, identical: 0, A1: 0, A3: 0, B: 0, mismatch: 0, net: 0 };
    for (let i = 0; i < per.base.length; i += 1) {
      const a = per.base[i]; const b = per.branch[i];
      counts.rows += 1;
      const verdict = comparePair(a, b, { entry: a.entry, event: eventName(a) });
      if (verdict.kind === 'identical') counts.identical += 1;
      else if (verdict.kind === 'mismatch') { counts.mismatch += 1; mismatches.push({ profile: plan.name, id: a.id, ...verdict }); }
      else for (const k of verdict.kind.split('+')) counts[k] += 1;
    }
    summary.push({ profile: plan.name, entry: 'keyed', ...counts });
    process.stdout.write(`done ${plan.name}: ${counts.rows} rows, ${counts.identical} identical, A1 ${counts.A1}, A3 ${counts.A3}, B ${counts.B}, mismatch ${counts.mismatch}\n`);
  });
  await pool([...tasks, ...keyedTasks], JOBS);

  summary.sort((x, y) => x.profile.localeCompare(y.profile));
  const total = summary.reduce((acc, s) => { for (const k of ['rows', 'identical', 'A1', 'A3', 'B', 'mismatch', 'net']) acc[k] += s[k] || 0; return acc; }, { rows: 0, identical: 0, A1: 0, A3: 0, B: 0, mismatch: 0, net: 0 });
  const line = (s) => `${s.profile.padEnd(46)} ${String(s.entry).padEnd(8)} rows ${String(s.rows).padStart(4)}  identical ${String(s.identical).padStart(4)}  A1 ${String(s.A1).padStart(3)}  A3 ${String(s.A3).padStart(3)}  B ${String(s.B).padStart(4)}  mismatches ${String(s.mismatch).padStart(3)}  network ${String(s.net).padStart(3)}`;
  const text = [
    `fh-diff: base ${BASE_CLI}`, `         branch ${BRANCH_CLI}`, `seed ${SEED}; ${new Date().toISOString().slice(0, 10)}; ${Math.round((Date.now() - started) / 1000)} s`,
    'A1 = new systemMessage on a Claude Code deny of a hold denied for later or waiting quietly; A3 = new systemMessage on a UserPromptSubmit output; B = one extra mode:<code> in a fallback text.', '',
    ...summary.map(line), '',
    `TOTAL rows ${total.rows}  identical ${total.identical}  A1 ${total.A1}  A3 ${total.A3}  B ${total.B}  MISMATCHES ${total.mismatch}  network attempts ${total.net}`,
    `free-text fields found in hook outputs: ${[...freeTextKeys].sort().join(', ') || '(none beyond the known text keys)'}`,
    `known text keys: ${[...TEXT_KEYS].sort().join(', ')}`,
  ].join('\n');
  fs.writeFileSync(path.join(OUT, 'diff-table.txt'), `${text}\n`);
  fs.writeFileSync(path.join(OUT, 'diff-mismatches.json'), JSON.stringify(mismatches, null, 1));
  console.log(text);
  process.exitCode = total.mismatch === 0 ? 0 : 1;
}

main().catch((error) => { console.error(error); process.exitCode = 2; });
