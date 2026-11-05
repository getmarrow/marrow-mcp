const assert = require('node:assert/strict');
const { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createHash, randomBytes } = require('node:crypto');
const test = require('node:test');

// LG_DIST points the file at another build (the round-1 tip or master) so a row can be shown red there.
const dist = (name) => require(process.env.LG_DIST ? join(process.env.LG_DIST, name) : `../dist/${name}`);
const guard = dist('session-loop-guard.js');
const { localLoopGuardDenyOutput, runPreActionHookCommand } = dist('hook-pre-action.js');
const { runHookCommand } = dist('hook.js');

// One Date.now stub for the whole file (the guard prunes with Date.now(), never options.now): real time plus an offset,
// or a pinned trace clock for the clock-step rows, or (tick > 0) the controlled clock: every Date.now() call returns the previous value plus tick.
const realNow = Date.now.bind(Date);
const clock = { offset: 0, fixed: null, tick: 0 };
Date.now = () => (clock.tick ? (clock.fixed += clock.tick) : (clock.fixed ?? realNow() + clock.offset));
// The ONE controlled clock of the rows that need an order of stamps (K1/K3, C2 dropped half, P6): a constant start and a step far above any stamp spread
// inside a call, never wall time, so every stamp the guard writes is strictly later than the one before and a millisecond tie cannot decide a prune.
const CTL_START = 1_700_000_000_000;
const CTL_STEP = 10_000;
const controlClock = () => { clock.fixed = CTL_START; clock.tick = CTL_STEP; };
const releaseClock = () => { clock.fixed = null; clock.tick = 0; };
const {
  advanceSessionInstructionEpoch, clearSessionLoopGuard, consultSessionLoopGuard, recordSessionLoopOutcome,
  sessionLoopGuardPath, UnsafeLoopGuardStateError,
} = guard;

const CAP = 256 * 1024;
const LOW_WATER = 192 * 1024;
const FLOOR = 3;
const hex = (label) => createHash('sha256').update(String(label)).digest('hex');
const bytes = (value) => Buffer.byteLength(typeof value === 'string' ? value : `${JSON.stringify(value)}\n`);
const home = () => mkdtempSync(join(tmpdir(), 'marrow-loop-guard-bytes-'));
const clean = (root) => rmSync(root, { recursive: true, force: true });
const secret = () => randomBytes(32).toString('base64url');
const T0 = Date.now() - 60_000;
const NOW = T0 + 60_000;
const MAX_NOW = 9007199254740991;
// The helper takes the clock as its third argument; the round-1 tip (run only to show a row red) takes the cap there.
const pruneBytes = (state, key, cap, low, now = NOW) => (guard.pruneLoopGuardStateToBytes.length >= 3
  ? guard.pruneLoopGuardStateToBytes(state, key, now, cap, low)
  : guard.pruneLoopGuardStateToBytes(state, key, cap, low));

function mkEntry(fingerprint, updated, extra = {}) {
  return {
    fingerprint, kind: 'read', outcome: 'success', result_hash: hex(`result:${fingerprint}`), unchanged_count: 1, attempts: 1,
    updated_at: updated, receipt: `lgr_${hex(`receipt:${fingerprint}`).slice(0, 24)}`, ...extra,
  };
}

// entries are numbered 0..n-1 (newest = highest number); mapping i points at entry i % n unless oneFp, then all at the newest entry
function mkSession(tag, { entries = 4, mappings = entries, updated = T0 + 5_000, oneFp = false, ties = false, entryExtra = {} } = {}) {
  const session = { work_epoch: 0, instruction_epoch: 0, updated_at: updated, entries: {}, invocations: {} };
  for (let i = 0; i < entries; i += 1) session.entries[hex(`${tag}:e${i}`)] = mkEntry(hex(`${tag}:e${i}`), ties ? T0 : T0 + i, entryExtra);
  for (let i = 0; i < mappings && entries > 0; i += 1) session.invocations[hex(`${tag}:i${i}`)] = hex(`${tag}:e${oneFp ? entries - 1 : i % entries}`);
  return session;
}

const mkState = (sessions, over = {}) => ({ version: 1, secret: secret(), sessions, ...over });
const keyOf = (tag) => hex(`session:${tag}`);
const stateOf = (spec, over) => mkState(Object.fromEntries(Object.entries(spec).map(([tag, s]) => [keyOf(tag), s])), over);
const clone = (value) => JSON.parse(JSON.stringify(value));

// Slow, literal reading of the spec: re-serializes after every dropped unit.
function reference(input, currentKey, cap, lowWater, now = NOW) {
  const state = clone(input);
  const len = () => bytes(state);
  if (len() <= cap) return state;
  const others = Object.keys(state.sessions).filter((key) => key !== currentKey)
    .sort((a, b) => Math.min(state.sessions[a].updated_at, now) - Math.min(state.sessions[b].updated_at, now) || (a < b ? -1 : 1));
  for (const key of others) {
    const session = state.sessions[key];
    const newest = Object.keys(session.entries).sort((a, b) => session.entries[b].updated_at - session.entries[a].updated_at || (a < b ? -1 : 1));
    // the floor is the 3 newest entries stamped at or before now; an entry stamped after now stays on top of it
    const kept = new Set([...newest.filter((e) => session.entries[e].updated_at <= now).slice(0, FLOOR), ...newest.filter((e) => session.entries[e].updated_at > now)]);
    const maps = Object.keys(session.invocations);
    const last = {};
    for (const map of maps) last[session.invocations[map]] = map;
    for (const map of maps) {
      if (len() <= lowWater) break;
      const fp = session.invocations[map];
      if (last[fp] !== map || !(fp in session.entries)) delete session.invocations[map];
    }
    const droppable = newest.filter((e) => !kept.has(e)).sort((a, b) => session.entries[a].updated_at - session.entries[b].updated_at || (a < b ? -1 : 1));
    for (const entry of droppable) {
      if (len() <= lowWater) break;
      delete session.entries[entry];
      for (const map of Object.keys(session.invocations)) if (session.invocations[map] === entry) delete session.invocations[map];
    }
  }
  return state;
}

function lcg(seed) {
  let s = seed >>> 0;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
}

function stateFile(root) { return sessionLoopGuardPath(root); }
function loadFile(root) { return JSON.parse(readFileSync(stateFile(root), 'utf8')); }
function saveFile(root, state) { writeFileSync(stateFile(root), `${JSON.stringify(state)}\n`, { mode: 0o600 }); chmodSync(stateFile(root), 0o600); }
const sizeOf = (root) => statSync(stateFile(root)).size;

// Replaces the filler sessions of an existing state file so it is exactly `target` bytes (an extra field pads the last bytes).
// age > 0: fillers are older than the real sessions; age < 0: newer.
function inflate(root, target, tag = 'fill', age = 7_200_000, abs = undefined) {
  const state = loadFile(root);
  for (const key of Object.keys(state.sessions)) if (state.sessions[key].filler) delete state.sessions[key];
  // newer fillers: move the trace clock on so they are stamped in the past, never after now (the controlled clock needs no move: its steps are 10 s)
  if (age < 0) {
    if (clock.tick) age = 3_000;
    else { clock.offset += 120_000; age = 60_000; }
  }
  const now = Date.now();
  const base = abs ?? now - age;
  const holders = [];
  for (let n = 0; bytes(state) < target - 3_000 && n < 30; n += 1) {
    const key = hex(`${tag}-${n}`);
    const session = { work_epoch: 0, instruction_epoch: 0, updated_at: abs ?? now - age + n, entries: {}, invocations: {}, filler: 1 };
    for (let i = 0; i < 40 && bytes(state) < target - 3_000; i += 1) {
      const fp = hex(`${key}:${i}`);
      session.entries[fp] = mkEntry(fp, abs !== undefined ? base - 3_000 + n * 100 + i : now - age + n * 100 + i);
      session.invocations[hex(`${key}:i${i}`)] = fp;
      state.sessions[key] = session;
    }
    state.sessions[key] = session;
    holders.push(session);
  }
  holders[0].pad = '';
  holders[0].pad = 'x'.repeat(target - bytes(state));
  saveFile(root, state);
  assert.equal(sizeOf(root), target);
}

const op = (overrides = {}) => ({ sessionId: 'sess-loop', agentId: 'agent-loop', harness: 'claude', toolName: 'Read', toolInput: { file_path: '/work/a.txt' }, readOnly: true, ...overrides });

test('pure prune: a state at or under the cap is returned byte for byte without any change', () => {
  const state = stateOf({ cur: mkSession('cur'), a: mkSession('a', { entries: 10 }) });
  const before = JSON.stringify(state);
  const raw = pruneBytes(state, keyOf('cur'));
  assert.equal(raw, `${before}\n`);
  assert.equal(JSON.stringify(state), before);
  const exact = pruneBytes(state, keyOf('cur'), bytes(before + '\n') - 0, 10);
  assert.equal(exact, `${before}\n`);
});

test('L10 (i) between low water and the cap nothing is pruned: the state is returned byte for byte', () => {
  const spec = { cur: mkSession('cur', { entries: 20 }) };
  for (let i = 0; i < 46; i += 1) spec[`o${i}`] = mkSession(`o${i}`, { entries: 8, mappings: 8, updated: T0 + i });
  const state = stateOf(spec);
  assert.ok(bytes(state) > LOW_WATER && bytes(state) <= CAP, `fixture is ${bytes(state)} B`);
  const before = JSON.stringify(state);
  assert.equal(pruneBytes(state, keyOf('cur')), `${before}\n`);
  assert.equal(JSON.stringify(state), before);
});

test('L3 size proof: the floor state plus the largest current session fits the cap, and the full prune leaves it so', () => {
  const wide = mkEntry(hex('wide'), 9007199254740991, { kind: 'verification', outcome: 'failure', unchanged_count: 1000001, attempts: 1000001 });
  const mapBytes = bytes(JSON.stringify(hex('k'))) + 1 + bytes(JSON.stringify(hex('v')));
  const entryBytes = JSON.stringify(hex('k')).length + 1 + JSON.stringify(wide).length;
  const shell = (n, e, m) => ({ work_epoch: 9007199254740991, instruction_epoch: 9007199254740991, updated_at: 9007199254740991, entries: e, invocations: m, n });
  const fullCurrent = shell(0, {}, {});
  delete fullCurrent.n;
  for (let i = 0; i < 256; i += 1) fullCurrent.entries[hex(`cur:e${i}`)] = { ...wide, fingerprint: hex(`cur:e${i}`) };
  for (let i = 0; i < 256; i += 1) fullCurrent.invocations[hex(`cur:i${i}`)] = hex('cur:e255');
  const flat = (tag) => ({ ...shell(0, {}, {}), entries: Object.fromEntries([0, 1, 2].map((i) => [hex(`${tag}:e${i}`), { ...wide, fingerprint: hex(`${tag}:e${i}`) }])), invocations: Object.fromEntries([0, 1, 2].map((i) => [hex(`${tag}:i${i}`), hex(`${tag}:e${i}`)])) });
  const floorState = mkState({ [keyOf('cur')]: fullCurrent });
  for (let i = 0; i < 63; i += 1) { const s = flat(`o${i}`); delete s.n; floorState.sessions[keyOf(`o${i}`)] = s; }
  const floorBytes = bytes(floorState);
  assert.ok(floorBytes <= CAP - 4096, `floor state ${floorBytes} must leave 4 KiB under the cap (entry ${entryBytes}, mapping ${mapBytes})`);
  const full = clone(floorState);
  for (let i = 0; i < 63; i += 1) {
    const s = full.sessions[keyOf(`o${i}`)];
    for (let j = 3; j < 256; j += 1) s.entries[hex(`o${i}:e${j}`)] = { ...wide, fingerprint: hex(`o${i}:e${j}`), updated_at: 9007199254740991 - 1000 + j };
    for (let j = 3; j < 256; j += 1) s.invocations[hex(`o${i}:i${j}`)] = hex(`o${i}:e${j}`);
  }
  assert.ok(bytes(full) > 8_000_000);
  const current = JSON.stringify(full.sessions[keyOf('cur')]);
  const raw = pruneBytes(full, keyOf('cur'), undefined, undefined, MAX_NOW);
  assert.ok(bytes(raw) <= CAP);
  assert.equal(JSON.stringify(full.sessions[keyOf('cur')]), current);
  assert.equal(Object.keys(full.sessions).length, 64);
  for (let i = 0; i < 63; i += 1) assert.equal(Object.keys(full.sessions[keyOf(`o${i}`)].entries).length, FLOOR);
  console.log(`# L3 numbers: entry ${entryBytes} B, mapping ${mapBytes} B, floor state ${floorBytes} B, margin ${CAP - floorBytes} B`);
});

test('L4 pure prune matches the literal spec on seeded states: order, floor, hysteresis, ties, no dangling mapping', () => {
  const rand = lcg(20261103);
  let pruned = 0;
  for (let round = 0; round < 60; round += 1) {
    const spec = { cur: mkSession('cur', { entries: 1 + Math.floor(rand() * 8), mappings: Math.floor(rand() * 12), updated: T0 + 90_000 }) };
    const total = 3 + Math.floor(rand() * 5);
    for (let i = 0; i < total; i += 1) {
      const entries = Math.floor(rand() * 14);
      spec[`o${i}`] = mkSession(`o${round}-${i}`, {
        entries, mappings: Math.floor(rand() * 22), oneFp: rand() < 0.3, ties: rand() < 0.3, entryExtra: rand() < 0.3 ? { note: '日本語✓éü'.repeat(6) } : {}, updated: T0 + (rand() < 0.4 ? 1_000 : Math.floor(rand() * 50_000)),
      });
    }
    const state = stateOf(spec);
    const currentKey = keyOf('cur');
    const total_bytes = bytes(state);
    const cap = total_bytes - 1 - Math.floor(rand() * 2_000);
    const low = Math.floor(total_bytes * (0.4 + rand() * 0.55));
    const expected = reference(state, currentKey, cap, low);
    const current = JSON.stringify(state.sessions[currentKey]);
    const mutated = clone(state);
    if (bytes(expected) > cap) {
      assert.throws(() => pruneBytes(mutated, currentKey, cap, low), UnsafeLoopGuardStateError);
      continue;
    }
    const raw = pruneBytes(mutated, currentKey, cap, low);
    pruned += 1;
    assert.equal(raw, `${JSON.stringify(expected)}\n`);
    assert.equal(JSON.stringify(mutated.sessions[currentKey]), current);
    assert.equal(mutated.secret, state.secret);
    assert.equal(mutated.version, 1);
    assert.deepEqual(Object.keys(mutated.sessions), Object.keys(state.sessions));
    for (const session of Object.values(mutated.sessions)) for (const fingerprint of Object.values(session.invocations)) assert.ok(fingerprint in session.entries);
  }
  assert.ok(pruned >= 40, `only ${pruned} seeded states pruned`);
});

test('L4 fixtures: oldest session first, hysteresis stops at low water, floor kept, 256 mappings to one entry, non-ASCII bytes counted', () => {
  const build = () => ({
    cur: mkSession('cur', { entries: 40, mappings: 40, updated: T0 + 90_000 }),
    old: mkSession('old', { entries: 30, mappings: 60, updated: T0 + 1_000 }),
    mid: mkSession('mid', { entries: 30, mappings: 30, updated: T0 + 2_000 }),
    new: mkSession('new', { entries: 30, mappings: 30, updated: T0 + 3_000 }),
    big: mkSession('big', { entries: 20, mappings: 256, oneFp: true, updated: T0 + 4_000, entryExtra: { note: 'héllo wörld ✓ 日本語'.repeat(10) } }),
  });
  const spec = build();
  const state = stateOf(build());
  const startBytes = bytes(state);
  const cap = startBytes - 1;
  const lowWater = startBytes - 6_000;
  const expected = reference(state, keyOf('cur'), cap, lowWater);
  const raw = pruneBytes(state, keyOf('cur'), cap, lowWater);
  assert.equal(raw, `${JSON.stringify(expected)}\n`);
  assert.ok(bytes(raw) <= lowWater);
  // only the oldest session lost anything
  assert.ok(Object.keys(state.sessions[keyOf('old')].entries).length < 30);
  assert.equal(Object.keys(state.sessions[keyOf('mid')].entries).length, 30);
  assert.equal(Object.keys(state.sessions[keyOf('big')].entries).length, 20);
  // re-adding the last dropped unit would be over low water: the prune stopped as soon as it could
  const lastOld = Object.keys(spec.old.entries).filter((key) => !(key in state.sessions[keyOf('old')].entries)).sort((a, b) => spec.old.entries[a].updated_at - spec.old.entries[b].updated_at).pop();
  const readded = clone(state);
  readded.sessions[keyOf('old')].entries[lastOld] = spec.old.entries[lastOld];
  const newestMapping = Object.keys(spec.old.invocations).filter((key) => spec.old.invocations[key] === lastOld).pop();
  readded.sessions[keyOf('old')].invocations[newestMapping] = lastOld;
  assert.ok(bytes(readded) > lowWater);
  // everything droppable gone: big keeps exactly the floor entries and the newest mapping of each (here all 256 point at one entry)
  const drained = stateOf(build());
  pruneBytes(drained, keyOf('cur'), startBytes - 1, 10);
  const big = drained.sessions[keyOf('big')];
  assert.equal(Object.keys(big.entries).length, FLOOR);
  assert.equal(Object.keys(big.invocations).length, 1);
  assert.deepEqual(Object.keys(big.invocations), Object.keys(spec.big.invocations).slice(-1));
  assert.equal(JSON.stringify(drained.sessions[keyOf('cur')]), JSON.stringify(spec.cur));
  assert.equal(Object.keys(drained.sessions).length, 5);
});

test('L4 equal updated_at: sessions and entries tie-break by key', () => {
  const spec = { cur: mkSession('cur', { updated: T0 + 90_000 }), a: mkSession('a', { entries: 8, ties: true, updated: T0 + 1 }), b: mkSession('b', { entries: 8, ties: true, updated: T0 + 1 }) };
  const state = stateOf(spec);
  const start = bytes(state);
  const first = Object.keys(state.sessions).filter((key) => key !== keyOf('cur')).sort()[0];
  const one = clone(state);
  const oneEntry = bytes(state.sessions[first].entries[Object.keys(state.sessions[first].entries)[0]]) + 80;
  pruneBytes(one, keyOf('cur'), start - 1, start - oneEntry * 2);
  const lowerSession = one.sessions[first];
  const otherKey = Object.keys(state.sessions).find((key) => key !== keyOf('cur') && key !== first);
  assert.ok(Object.keys(lowerSession.entries).length < 8, 'the lower session key is trimmed first');
  assert.equal(Object.keys(one.sessions[otherKey].entries).length, 8);
  // all-equal entries: floor keeps the three lowest keys, the rest go in key order
  const drained = clone(state);
  pruneBytes(drained, keyOf('cur'), start - 1, 10);
  for (const key of [first, otherKey]) {
    const expectedKept = Object.keys(state.sessions[key].entries).sort().slice(0, FLOOR);
    assert.deepEqual(Object.keys(drained.sessions[key].entries).sort(), expectedKept);
  }
});

test('S5 backstop: a current session that alone exceeds the cap fails closed, and an other-session extra field is counted', () => {
  const huge = stateOf({ cur: { ...mkSession('cur'), pad: 'x'.repeat(100_000) }, o: mkSession('o', { entries: 8 }) });
  assert.throws(() => pruneBytes(huge, keyOf('cur'), 60_000, 1_000), UnsafeLoopGuardStateError);
  assert.equal(Object.keys(huge.sessions[keyOf('o')].entries).length, FLOOR);
  const padded = stateOf({ cur: mkSession('cur'), o: mkSession('o', { entries: 8, entryExtra: { pad: 'y'.repeat(30_000) } }) });
  const cap = bytes(padded) - 1;
  const raw = pruneBytes(padded, keyOf('cur'), cap, cap - 1);
  assert.ok(bytes(raw) <= cap);
  assert.equal(raw, `${JSON.stringify(padded)}\n`);
  assert.throws(() => pruneBytes(stateOf({ cur: mkSession('cur'), o: mkSession('o', { entries: 3 }) }), keyOf('cur'), 100, 50), UnsafeLoopGuardStateError);
});

test('L4b: entries past the 24 h TTL go first; a state only over the cap because of them keeps every live entry', () => {
  const root = home();
  try {
    consultSessionLoopGuard(op({ sessionId: 'ttl-first', invocationId: 'i1' }), { home: root });
    const state = loadFile(root);
    const old = Date.now() - 25 * 3_600_000;
    const live = [];
    for (let s = 0; s < 3; s += 1) {
      const session = { work_epoch: 0, instruction_epoch: 0, updated_at: Date.now() - 10_000 + s, entries: {}, invocations: {} };
      for (let i = 0; i < (s === 0 ? 60 : 12); i += 1) {
        const fp = hex(`live:${s}:${i}`);
        session.entries[fp] = mkEntry(fp, Date.now() - 50_000 + i);
        session.invocations[hex(`live:i:${s}:${i}`)] = fp;
        live.push(fp);
      }
      for (let i = 0; i < (s === 0 ? 0 : 200); i += 1) session.entries[hex(`stale:${s}:${i}`)] = mkEntry(hex(`stale:${s}:${i}`), old + i);
      state.sessions[hex(`ttl-session-${s}`)] = session;
    }
    const holder = state.sessions[hex('ttl-session-2')];
    holder.pad = '';
    holder.pad = 'x'.repeat(CAP - 100 - bytes(state));
    saveFile(root, state);
    assert.equal(sizeOf(root), CAP - 100);
    consultSessionLoopGuard(op({ sessionId: 'ttl-second', invocationId: 'i2' }), { home: root });
    const survivors = new Set(Object.values(loadFile(root).sessions).flatMap((session) => Object.keys(session.entries)));
    for (const fp of live) assert.ok(survivors.has(fp), 'a live entry was lost to the byte prune');
    assert.ok(![...survivors].some((fp) => fp === hex('stale:1:0')), 'the TTL rule still removes stale entries');
    assert.ok(sizeOf(root) <= CAP);
  } finally { clean(root); }
});

function drive(root, sessions, calls, extra = {}) {
  for (let i = 0; i < calls; i += 1) {
    const sessionId = `drive-${i % sessions}`;
    const read = op({ sessionId, toolInput: { file_path: `/work/file-${i}` }, invocationId: `toolu_${i}`, ...extra });
    if (consultSessionLoopGuard(read, { home: root }).allow) recordSessionLoopOutcome(read, true, { ok: i }, { home: root });
    assert.ok(sizeOf(root) <= CAP);
  }
}

test('L2/L8 busy host: no throw, size under the cap after every write, every file valid for the next reader', () => {
  const root = home();
  try {
    let crossed = false;
    for (let i = 0; i < 1_400; i += 1) {
      const kind = [{ toolName: 'Read', toolInput: { file_path: `/f/${i}` } }, { toolName: 'Bash', toolInput: { command: `git status ${i}` } }, { toolName: 'Bash', toolInput: { command: `npm test ${i}` } }, { toolName: 'Edit', toolInput: { patch: i }, readOnly: false }][i % 4];
      const operation = op({ sessionId: `busy-${i % 10}`, invocationId: `toolu_${i}`, ...kind });
      const decision = consultSessionLoopGuard(operation, { home: root });
      assert.equal(decision.allow, true);
      recordSessionLoopOutcome(operation, i % 5 !== 0, { i }, { home: root });
      const size = sizeOf(root);
      assert.ok(size <= CAP, `state ${size}`);
      if (size > LOW_WATER) crossed = true;
      if (i % 50 === 0) JSON.parse(readFileSync(stateFile(root), 'utf8'));
    }
    assert.ok(crossed, 'the run never filled the state');
  } finally { clean(root); }
});

test('L2 hook entry: a Read after the state is driven over the cap is allowed (master denies with the unsafe text)', async () => {
  const root = home();
  const previous = { HOME: process.env.HOME, MARROW_API_KEY: process.env.MARROW_API_KEY, MARROW_AUTO_HOOK: process.env.MARROW_AUTO_HOOK };
  const originalWrite = process.stdout.write;
  const originalFetch = globalThis.fetch;
  let output = '';
  try {
    drive(root, 4, 900);
    assert.ok(sizeOf(root) > LOW_WATER);
    process.env.HOME = root;
    process.env.MARROW_API_KEY = `dummy-${randomBytes(8).toString('hex')}`;
    process.env.MARROW_AUTO_HOOK = 'true';
    globalThis.fetch = async () => { throw new Error('network must stay unused'); };
    process.stdout.write = (chunk) => { output += String(chunk); return true; };
    for (let i = 0; i < 40; i += 1) {
      output = '';
      const event = { session_id: `hook-${i % 3}`, tool_use_id: `hook-read-${i}`, tool_name: 'Read', tool_input: { file_path: `/work/hook-${i}` } };
      await runPreActionHookCommand(event);
      assert.doesNotMatch(output, /unsafe/);
      assert.deepEqual(JSON.parse(output), {});
      await runHookCommand({ ...event, hook_event_name: 'PostToolUse', success: true, tool_result: { clean: i } });
    }
    assert.ok(sizeOf(root) <= CAP);
  } finally {
    process.stdout.write = originalWrite;
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    clean(root);
  }
});

function decisions(plan) {
  return plan.map((d) => (d ? { allow: d.allow, receipt: d.receipt, reason: d.reason ?? null, fingerprint: d.fingerprint } : null));
}

const KINDS = {
  read: { toolInput: { file_path: '/loop/a' }, success: true },
  poll: { toolName: 'Bash', toolInput: { command: 'git status' }, success: true },
  failure: { toolName: 'Bash', toolInput: { command: 'cat /loop/missing' }, success: false },
  verification: { toolName: 'Bash', toolInput: { command: 'npm test' }, success: true },
};

// L runs the same call 6 times (consult, record when allowed). mode decides who triggers a prune near the cap.
function runLoop(root, spec, mode, age = 7_200_000) {
  const out = [];
  consultSessionLoopGuard(op({ sessionId: 'seed-session', toolInput: { file_path: '/seed' } }), { home: root });
  for (let n = 0; n < 6; n += 1) {
    const operation = op({ sessionId: 'loop-owner', invocationId: `loop-${n}`, ...spec });
    if (mode === 'consult') inflate(root, CAP - 60, `c${n}`, age);
    if (mode === 'other') {
      inflate(root, CAP - 60, `o${n}`, age);
      consultSessionLoopGuard(op({ sessionId: `other-writer-${n}`, toolInput: { file_path: `/other/${n}` }, invocationId: `ow-${n}` }), { home: root });
    }
    const decision = consultSessionLoopGuard(operation, { home: root });
    out.push(decision);
    if (decision.allow) {
      if (mode === 'record') inflate(root, CAP - 5, `r${n}`, age);
      recordSessionLoopOutcome(operation, spec.success, { result: 'same' }, { home: root });
    }
    assert.ok(sizeOf(root) <= CAP);
  }
  return out;
}

for (const [name, spec] of Object.entries(KINDS)) {
  test(`L5 loop still caught (${name}): same denial count, text and receipt as below the cap, for every prune trigger`, () => {
    const baseline = home();
    let expected;
    try {
      expected = decisions(runLoop(baseline, spec, 'none'));
      assert.ok(expected.some((d) => !d.allow), 'the loop was never denied');
    } finally { clean(baseline); }
    for (const [mode, age] of [['consult', 7_200_000], ['record', 7_200_000], ['other', 7_200_000], ['consult', -60_000], ['record', -60_000], ['other', -60_000]]) {
      const root = home();
      try {
        const actual = decisions(runLoop(root, spec, mode, age));
        // fingerprints and receipts come from the secret, which differs per home: compare the shape, the denial text shape and the repeats
        assert.deepEqual(actual.map((d) => d.allow), expected.map((d) => d.allow), `${name}/${mode} allow sequence`);
        assert.deepEqual(actual.map((d) => (d.reason ?? '').replace(/lgr_[0-9a-f]{24}/, 'R')), expected.map((d) => (d.reason ?? '').replace(/lgr_[0-9a-f]{24}/, 'R')));
        const receipts = actual.map((d) => d.receipt);
        assert.equal(new Set(receipts).size, 1, `${name}/${mode}: one entry kept one receipt`);
      } finally { clean(root); }
    }
  });
}

test('L6 flood: 63 sessions writing around the cap cannot lift a 1-3 call loop; a 4-call cycle residual is recorded', () => {
  const residual = [];
  for (const cycle of [1, 2, 3, 4]) {
    const root = home();
    try {
      const calls = Array.from({ length: cycle }, (_, i) => op({ sessionId: 'flood-victim', toolInput: { file_path: `/victim/${i}` } }));
      calls.forEach((call, i) => { consultSessionLoopGuard({ ...call, invocationId: `v${i}` }, { home: root }); recordSessionLoopOutcome({ ...call, invocationId: `v${i}` }, true, { same: 1 }, { home: root }); });
      drive(root, 63, 1_100);
      const denied = calls.map((call) => !consultSessionLoopGuard(call, { home: root }).allow);
      if (cycle <= FLOOR) assert.deepEqual(denied, calls.map(() => true), `cycle ${cycle} must stay denied`);
      else residual.push(denied.filter((d) => !d).length);
    } finally { clean(root); }
  }
  console.log(`# FLOOD_RESIDUAL_CYCLE ${FLOOR + 1} (cycle 4 repeats allowed after the flood: ${residual.join(',')})`);
});

test('S2 the writing session is never trimmed: a consult-triggered and a record-triggered prune keep all its entries', () => {
  for (const trigger of ['consult', 'record']) {
    const root = home();
    try {
      const calls = Array.from({ length: 8 }, (_, i) => op({ sessionId: 's2-owner', toolInput: { file_path: `/s2/${i}` }, invocationId: `s2-${i}` }));
      calls.forEach((call) => consultSessionLoopGuard(call, { home: root }));
      const owned = () => Object.values(loadFile(root).sessions).filter((session) => !session.filler && Object.keys(session.entries).length >= 8);
      inflate(root, trigger === 'consult' ? CAP - 10 : CAP - 5, 's2fill', -60_000);
      if (trigger === 'consult') consultSessionLoopGuard(op({ sessionId: 's2-owner', toolInput: { file_path: '/s2/new' }, invocationId: 's2-new' }), { home: root });
      else recordSessionLoopOutcome(calls[0], true, { done: 1 }, { home: root });
      assert.equal(owned().length, 1, `${trigger}: the writing session lost entries`);
      assert.equal(Object.keys(owned()[0].entries).length, trigger === 'consult' ? 9 : 8);
      assert.ok(sizeOf(root) <= CAP);
    } finally { clean(root); }
  }
});

test('K1/K3 a pruned-then-recreated entry gets the same fingerprint and receipt', () => {
  const root = home();
  try {
    controlClock();
    const target = op({ sessionId: 'k-owner', toolInput: { file_path: '/k/first' }, invocationId: 'k-first' });
    const first = consultSessionLoopGuard(target, { home: root });
    for (let i = 1; i < 6; i += 1) consultSessionLoopGuard(op({ sessionId: 'k-owner', toolInput: { file_path: `/k/${i}` }, invocationId: `k-${i}` }), { home: root });
    inflate(root, CAP - 10, 'kfill', -60_000);
    // another session writes over the cap: k-owner is the oldest "other" session and its oldest entry is beyond the floor
    consultSessionLoopGuard(op({ sessionId: 'k-writer', toolInput: { file_path: '/k/w' }, invocationId: 'kw' }), { home: root });
    const gone = !Object.values(loadFile(root).sessions).some((session) => first.fingerprint in session.entries);
    assert.ok(gone, 'the oldest entry beyond the floor was pruned');
    const again = consultSessionLoopGuard({ ...target, invocationId: 'k-first-again' }, { home: root });
    assert.equal(again.allow, true);
    assert.equal(again.fingerprint, first.fingerprint);
    assert.equal(again.receipt, first.receipt);
  } finally { releaseClock(); clean(root); }
});

test('K2 operations that differ in any field get different fingerprints; a different session id gets a different session', () => {
  const root = home();
  try {
    const base = op({ toolInput: { file_path: '/p/a' } });
    const variants = [
      { toolName: 'Grep' }, { toolInput: { file_path: '/p/b' } }, { toolInput: { file_path: '/p/a', limit: 1 } }, { agentId: 'agent-two' }, { harness: 'codex' },
      { toolName: 'functions.exec' }, { toolInput: {} }, { toolInput: { file_path: '/p/a ' } }, { toolInput: { 'file_path': '/p/a', offset: 0 } }, { agentId: undefined }, { toolName: 'Glob' }, { toolInput: { file_path: '/p/A' } },
    ];
    const seen = new Set([consultSessionLoopGuard(base, { home: root }).fingerprint]);
    for (const variant of variants) seen.add(consultSessionLoopGuard({ ...base, ...variant }, { home: root }).fingerprint);
    assert.equal(seen.size, variants.length + 1);
    const sessionsBefore = Object.keys(loadFile(root).sessions).length;
    consultSessionLoopGuard({ ...base, sessionId: 'other-session' }, { home: root });
    assert.equal(Object.keys(loadFile(root).sessions).length, sessionsBefore + 1);
    const first = loadFile(root);
    const epochOne = consultSessionLoopGuard(base, { home: root });
    assert.equal(epochOne.allow, true);
    advanceSessionInstructionEpoch(base, { home: root });
    assert.notEqual(consultSessionLoopGuard(base, { home: root }).fingerprint, epochOne.fingerprint);
    assert.ok(first);
  } finally { clean(root); }
});

test('K5 forged tool_input fields change nothing in the stored state or the prune order', () => {
  const root = home();
  try {
    const forged = op({ toolInput: JSON.parse('{"updated_at":1,"session":"x","entries":{"a":1},"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}') });
    assert.equal(consultSessionLoopGuard(forged, { home: root }).allow, true);
    const state = loadFile(root);
    const sessions = Object.values(state.sessions);
    assert.equal(sessions.length, 1);
    assert.equal(Object.keys(sessions[0].entries).length, 1);
    assert.ok(sessions[0].updated_at > 1_000_000);
    assert.equal({}.polluted, undefined);
    assert.doesNotMatch(readFileSync(stateFile(root), 'utf8'), /polluted/);
  } finally { clean(root); }
});

test('L7 unsafe state stays unsafe: each broken state throws and the file is not rewritten', () => {
  const make = () => { const root = home(); consultSessionLoopGuard(op(), { home: root }); return root; };
  const cases = {
    'corrupt json': (root) => writeFileSync(stateFile(root), '{not json', { mode: 0o600 }),
    'truncated': (root) => writeFileSync(stateFile(root), readFileSync(stateFile(root), 'utf8').slice(0, 40), { mode: 0o600 }),
    // one byte over the cap, still valid JSON, with other sessions the write side could prune: only the read cap itself refuses it (a raised cap in either reader would let the call through)
    'one byte over the read cap on disk': (root) => { const s = loadFile(root); const [session] = Object.values(s.sessions); for (let i = 0; i < 3; i += 1) s.sessions[keyOf(`ovr${i}`)] = mkSession(`ovr${i}`, { entries: 40, updated: realNow() - 20_000 }); session.pad = ''; session.pad = 'x'.repeat(CAP + 1 - bytes(s)); saveFile(root, s); assert.equal(sizeOf(root), CAP + 1); },
    'wrong version': (root) => { const s = loadFile(root); s.version = 2; saveFile(root, s); },
    'bad secret': (root) => { const s = loadFile(root); s.secret = 'short'; saveFile(root, s); },
    '65 sessions': (root) => { const s = loadFile(root); for (let i = 0; i < 65; i += 1) s.sessions[hex(`many-${i}`)] = mkSession(`many-${i}`, { entries: 0, updated: Date.now() }); saveFile(root, s); },
    '257 entries': (root) => { const s = loadFile(root); s.sessions[hex('big')] = mkSession('big', { entries: 257, mappings: 0, updated: Date.now() }); saveFile(root, s); },
    'bad entry': (root) => { const s = loadFile(root); const [session] = Object.values(s.sessions); const [key] = Object.keys(session.entries); session.entries[key].kind = 'other'; saveFile(root, s); },
    'mode 0644 file': (root) => chmodSync(stateFile(root), 0o644),
    'mode 0755 directory': (root) => chmodSync(join(root, '.marrow', 'session-loop-guard'), 0o755),
    'group-writable .marrow': (root) => chmodSync(join(root, '.marrow'), 0o770),
    'symlinked state file': (root) => { const real = `${stateFile(root)}.real`; writeFileSync(real, readFileSync(stateFile(root)), { mode: 0o600 }); rmSync(stateFile(root)); symlinkSync(real, stateFile(root)); },
  };
  for (const [name, breakIt] of Object.entries(cases)) {
    const root = make();
    try {
      breakIt(root);
      const before = createHash('sha256').update(readFileSync(stateFile(root))).digest('hex');
      assert.throws(() => consultSessionLoopGuard(op({ toolInput: { file_path: '/new' } }), { home: root }), UnsafeLoopGuardStateError, name);
      assert.throws(() => recordSessionLoopOutcome(op(), true, {}, { home: root }), UnsafeLoopGuardStateError, name);
      assert.equal(createHash('sha256').update(readFileSync(stateFile(root))).digest('hex'), before, `${name}: file rewritten`);
    } finally { clean(root); }
  }
});

test('L7 symlinked state directory fails closed', () => {
  const linked = home();
  const target = home();
  try {
    mkdirSync(join(linked, '.marrow'), { mode: 0o700 });
    symlinkSync(target, join(linked, '.marrow', 'session-loop-guard'));
    assert.throws(() => consultSessionLoopGuard(op(), { home: linked }), UnsafeLoopGuardStateError);
  } finally { clean(linked); clean(target); }
});

test('L9 oversized single call: hashes only, one entry and one mapping, no raw byte kept', () => {
  const root = home();
  try {
    const marker = randomBytes(16).toString('hex');
    const warm = op({ sessionId: 'big-call', toolInput: { file_path: '/warm' }, invocationId: 'warm' });
    consultSessionLoopGuard(warm, { home: root });
    const before = statSync(stateFile(root)).size;
    const huge = op({ sessionId: 'big-call', toolInput: { file_path: '/big', text: `${marker}${'a'.repeat(5 * 1024 * 1024)}` }, invocationId: 'huge' });
    assert.equal(consultSessionLoopGuard(huge, { home: root }).allow, true);
    recordSessionLoopOutcome(huge, true, { text: `${marker}${'b'.repeat(5 * 1024 * 1024)}` }, { home: root });
    const growth = statSync(stateFile(root)).size - before;
    assert.ok(growth > 0 && growth <= 400 + 140, `state grew ${growth} bytes`);
    assert.doesNotMatch(readFileSync(stateFile(root), 'utf8'), new RegExp(marker));
  } finally { clean(root); }
});

test('L11 upgrade: a state sitting just under the cap (where an old client starts throwing) is read and the next call is allowed', () => {
  const root = home();
  try {
    consultSessionLoopGuard(op({ sessionId: 'upgrade', invocationId: 'u0' }), { home: root });
    inflate(root, CAP - 50, 'upgrade');
    assert.ok(sizeOf(root) <= CAP);
    assert.equal(consultSessionLoopGuard(op({ sessionId: 'upgrade', toolInput: { file_path: '/after' }, invocationId: 'u1' }), { home: root }).allow, true);
    assert.ok(sizeOf(root) <= CAP);
    clearSessionLoopGuard(op({ sessionId: 'upgrade' }), { home: root });
    assert.ok(sizeOf(root) <= CAP);
  } finally { clean(root); }
});

test('C2 post-tool record: a kept entry still receives it through its newest mapping; a dropped one is never replaced by another entry', () => {
  const root = home();
  try {
    const pre = op({ sessionId: 'record-owner', toolInput: { file_path: '/rec/pre' }, invocationId: 'toolu_rec' });
    consultSessionLoopGuard(pre, { home: root });
    for (const [i, name] of ['x1', 'x2'].entries()) for (let j = 0; j < 4; j += 1) consultSessionLoopGuard(op({ sessionId: 'record-owner', toolInput: { file_path: `/rec/${name}` }, invocationId: `${name}-${j}-${i}` }), { home: root });
    inflate(root, CAP - 10, 'recfill', -60_000);
    consultSessionLoopGuard(op({ sessionId: 'record-writer', toolInput: { file_path: '/rec/w' }, invocationId: 'rec-w' }), { home: root });
    recordSessionLoopOutcome({ ...pre, toolInput: { file_path: '/rec/post', extra: 'differs' } }, true, { done: 1 }, { home: root });
    assert.equal(consultSessionLoopGuard({ ...pre, invocationId: 'toolu_rec_2' }, { home: root }).allow, false);
  } finally { clean(root); }
  const dropped = home();
  try {
    controlClock();
    const pre = op({ sessionId: 'drop-owner', toolInput: { file_path: '/drop/pre' }, invocationId: 'toolu_drop' });
    consultSessionLoopGuard(pre, { home: dropped });
    for (let i = 0; i < 5; i += 1) consultSessionLoopGuard(op({ sessionId: 'drop-owner', toolInput: { file_path: `/drop/${i}` }, invocationId: `d-${i}` }), { home: dropped });
    inflate(dropped, CAP - 10, 'dropfill', -60_000);
    consultSessionLoopGuard(op({ sessionId: 'drop-writer', toolInput: { file_path: '/drop/w' }, invocationId: 'drop-w' }), { home: dropped });
    const before = readFileSync(stateFile(dropped), 'utf8');
    recordSessionLoopOutcome({ ...pre, toolInput: { file_path: '/drop/post', extra: 'differs' } }, true, { done: 1 }, { home: dropped });
    assert.equal(readFileSync(stateFile(dropped), 'utf8'), before, 'a record for a dropped entry must change no other entry');
  } finally { releaseClock(); clean(dropped); }
});

test('the denial text exported to hosts is unchanged', () => {
  assert.equal(typeof localLoopGuardDenyOutput, 'function');
  assert.match(new UnsafeLoopGuardStateError().message, /^Local Marrow session loop-guard state is unsafe or invalid\./);
});

// ---- patch round: at most 3 mappings per other session (F1) and a backward clock step never evicts a loop (F2) ----
const HOUR = 3_600_000;
const STEPS = [60_000, HOUR, 23 * HOUR];
const UNSAFE_TEXT = /Marrow local loop guard state is unsafe\. Repair the private owner-only state before retrying\./;

// Other sessions force a byte prune: fillers stamped at the pinned clock (newer than the victim) bring the file to the cap, then a writer adds one entry.
function forcePrune(root, tick) {
  clock.fixed += 10;
  inflate(root, CAP - 60, `fp${tick}`, 0, clock.fixed);
  consultSessionLoopGuard(op({ sessionId: `writer-${tick % 5}`, toolInput: { file_path: `/w/${tick}` }, invocationId: `w-${tick}` }), { home: root });
  clock.fixed += 10;
}

const norm = (decision) => ({ allow: decision.allow, reason: (decision.reason ?? '').replace(/lgr_[0-9a-f]{24}/, 'R') });

// S writes the entry X, the clock steps back, then S loops A, B, C (unchanged results) with a prune forced before every call.
function futureCycle(root, stepMs, prune) {
  clock.fixed = realNow();
  const x = op({ sessionId: 'f2-victim', toolInput: { file_path: '/f2/x' }, invocationId: 'f2-x' });
  consultSessionLoopGuard(x, { home: root });
  recordSessionLoopOutcome(x, true, { x: 1 }, { home: root });
  clock.fixed -= stepMs;
  const out = [];
  let tick = 0;
  for (let round = 0; round < 3; round += 1) {
    for (const name of ['a', 'b', 'c']) {
      if (prune) forcePrune(root, tick);
      tick += 1;
      const call = op({ sessionId: 'f2-victim', toolInput: { file_path: `/f2/${name}` }, invocationId: `f2-${name}-${round}` });
      const decision = consultSessionLoopGuard(call, { home: root });
      out.push(norm(decision));
      if (decision.allow) recordSessionLoopOutcome(call, true, { same: name }, { home: root });
      clock.fixed += 10;
    }
  }
  return out;
}

test('P2 F2: a cycle-3 loop of a non-writer session stays denied at master\'s call number after a backward clock step', () => {
  try {
    for (const stepMs of STEPS) {
      const below = home();
      const forced = home();
      try {
        const expected = futureCycle(below, stepMs, false);
        assert.deepEqual(expected.map((d) => d.allow), [true, true, true, false, false, false, false, false, false], 'below the cap the loop is denied from call 4');
        const actual = futureCycle(forced, stepMs, true);
        const firstWrong = actual.findIndex((d, i) => d.allow !== expected[i].allow);
        assert.equal(firstWrong, -1, `step ${stepMs}: call ${firstWrong + 1} of the loop was allowed after a forced prune (evicted)`);
        assert.deepEqual(actual, expected);
      } finally { clean(below); clean(forced); clock.fixed = null; }
    }
  } finally { clock.fixed = null; }
});

test('P3 K7 with skew: a loop denied before a backward step stays denied while prunes run between its retries', () => {
  try {
    for (const stepMs of STEPS) {
      const root = home();
      try {
        clock.fixed = realNow();
        const calls = ['a', 'b', 'c'].map((name) => op({ sessionId: 'k7-victim', toolInput: { file_path: `/k7/${name}` }, invocationId: `k7-${name}` }));
        for (const call of calls) { consultSessionLoopGuard(call, { home: root }); recordSessionLoopOutcome(call, true, { same: 1 }, { home: root }); clock.fixed += 10; }
        const before = calls.map((call) => norm(consultSessionLoopGuard({ ...call, invocationId: `${call.invocationId}-again` }, { home: root })));
        assert.deepEqual(before.map((d) => d.allow), [false, false, false]);
        clock.fixed -= stepMs;
        let tick = 0;
        for (const name of ['d', 'e', 'f']) {
          forcePrune(root, tick++);
          const fresh = op({ sessionId: 'k7-victim', toolInput: { file_path: `/k7/${name}` }, invocationId: `k7-${name}` });
          if (consultSessionLoopGuard(fresh, { home: root }).allow) recordSessionLoopOutcome(fresh, true, { fresh: name }, { home: root });
        }
        const after = calls.map((call, i) => { forcePrune(root, tick++); return norm(consultSessionLoopGuard({ ...call, invocationId: `${call.invocationId}-retry` }, { home: root })); });
        assert.deepEqual(after, before, `step ${stepMs}: a denied loop was allowed after the step`);
      } finally { clean(root); clock.fixed = null; }
    }
  } finally { clock.fixed = null; }
});

function probeHook(root, label) {
  const previous = { HOME: process.env.HOME, MARROW_API_KEY: process.env.MARROW_API_KEY, MARROW_AUTO_HOOK: process.env.MARROW_AUTO_HOOK };
  const originalWrite = process.stdout.write;
  const originalFetch = globalThis.fetch;
  let output = '';
  process.env.HOME = root;
  process.env.MARROW_API_KEY = `dummy-${randomBytes(8).toString('hex')}`;
  process.env.MARROW_AUTO_HOOK = 'true';
  globalThis.fetch = async () => { throw new Error('network must stay unused'); };
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  return runPreActionHookCommand({ session_id: label, tool_use_id: `${label}-read`, tool_name: 'Read', tool_input: { file_path: `/hook/${label}` } }).then(() => output).finally(() => {
    process.stdout.write = originalWrite;
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  });
}

test('P4 big backward step: future entries alone over the cap fail closed as master (hook deny text), then the host recovers by itself', async () => {
  const table = [];
  try {
    for (const stepMs of [2 * HOUR, 12 * HOUR, 23 * HOUR, 25 * HOUR]) {
      const root = home();
      try {
        const t0 = realNow();
        clock.fixed = t0;
        consultSessionLoopGuard(op({ sessionId: 'big-owner', invocationId: 'big-0' }), { home: root });
        inflate(root, CAP - 60, `bigstep${stepMs}`, 0, t0);
        const stuck = readFileSync(stateFile(root));
        clock.fixed = t0 - stepMs;
        const next = (n) => op({ sessionId: 'big-owner', toolInput: { file_path: `/big/${n}` }, invocationId: `big-${n}` });
        assert.throws(() => consultSessionLoopGuard(next(1), { home: root }), UnsafeLoopGuardStateError);
        assert.deepEqual(readFileSync(stateFile(root)), stuck, 'a failed write must leave the file as it was');
        const output = await probeHook(root, 'bigstep');
        assert.match(output, UNSAFE_TEXT);
        console.log(`# HOOK_DENY step=${stepMs} sha256=${createHash('sha256').update(output).digest('hex').slice(0, 16)}`);
        const probe = (elapsed) => {
          writeFileSync(stateFile(root), stuck, { mode: 0o600 });
          clock.fixed = t0 - stepMs + elapsed;
          try { return consultSessionLoopGuard(next(2), { home: root }).allow; } catch (error) { assert.ok(error instanceof UnsafeLoopGuardStateError); return false; }
        };
        assert.equal(probe(stepMs - 60_000), false, 'still stuck a minute before the clock reaches the stamps');
        let lo = 0;
        let hi = stepMs + 25 * HOUR;
        assert.equal(probe(hi), true, 'the host must recover once the clock has passed the stamps and the TTL');
        while (hi - lo > 1_000) { const mid = Math.floor((lo + hi) / 2); if (probe(mid)) hi = mid; else lo = mid; }
        assert.ok(hi <= stepMs + 24 * HOUR + 5_000, `recovery ${hi} is later than master's TTL rule (${stepMs + 24 * HOUR})`);
        table.push(`${stepMs / HOUR}h=${(hi / HOUR).toFixed(3)}h`);
        // never bricked: the next calls are allowed and the state stays under the cap
        writeFileSync(stateFile(root), stuck, { mode: 0o600 });
        clock.fixed = t0 - stepMs + hi;
        for (let i = 3; i < 8; i += 1) { assert.equal(consultSessionLoopGuard(next(i), { home: root }).allow, true); clock.fixed += 10; assert.ok(sizeOf(root) <= CAP); }
      } finally { clean(root); }
    }
  } finally { clock.fixed = null; }
  console.log(`# RECOVERY_TABLE step->recovery (stubbed clock, since the step) ${table.join(', ')}`);
});

test('P5 F1 size proof: every other session ends with at most 3 entries and 3 mappings, and the max-width state fits 4 KiB under the cap', () => {
  const wide = mkEntry(hex('wide'), 9007199254740991, { kind: 'verification', outcome: 'failure', unchanged_count: 1000001, attempts: 1000001 });
  const shell = () => ({ work_epoch: 9007199254740991, instruction_epoch: 9007199254740991, updated_at: 9007199254740991, entries: {}, invocations: {} });
  const full = mkState({});
  const current = shell();
  for (let i = 0; i < 256; i += 1) current.entries[hex(`cur:e${i}`)] = { ...wide, fingerprint: hex(`cur:e${i}`) };
  for (let i = 0; i < 256; i += 1) current.invocations[hex(`cur:i${i}`)] = hex('cur:e255');
  full.sessions[keyOf('cur')] = current;
  // each other session: 256 entries; its 3 kept (newest) entries are named by 256 mappings, the last 3 of them to ONE entry
  for (let o = 0; o < 63; o += 1) {
    const session = shell();
    for (let j = 0; j < 256; j += 1) session.entries[hex(`o${o}:e${j}`)] = { ...wide, fingerprint: hex(`o${o}:e${j}`), updated_at: 9007199254740991 - 1000 + j };
    for (let j = 0; j < 256; j += 1) session.invocations[hex(`o${o}:i${j}`)] = hex(`o${o}:e${j < 2 ? 253 + j : 255}`);
    full.sessions[keyOf(`o${o}`)] = session;
  }
  const currentBytes = JSON.stringify(current);
  const raw = pruneBytes(full, keyOf('cur'), undefined, undefined, MAX_NOW);
  assert.equal(JSON.stringify(full.sessions[keyOf('cur')]), currentBytes);
  let maxEntries = 0;
  let maxMappings = 0;
  for (let o = 0; o < 63; o += 1) {
    const session = full.sessions[keyOf(`o${o}`)];
    maxEntries = Math.max(maxEntries, Object.keys(session.entries).length);
    maxMappings = Math.max(maxMappings, Object.keys(session.invocations).length);
  }
  const entryBytes = JSON.stringify(hex('k')).length + 1 + JSON.stringify(wide).length + 1;
  const mapBytes = JSON.stringify(hex('k')).length + 1 + JSON.stringify(hex('v')).length + 1;
  console.log(`# F1 numbers: F1_BOUND_BYTES ${bytes(raw)} F1_MAX_MAPPINGS_OTHER ${maxMappings} F1_MAX_ENTRIES_OTHER ${maxEntries} entry ${entryBytes} B mapping ${mapBytes} B current ${currentBytes.length} B`);
  assert.equal(maxEntries, FLOOR);
  assert.ok(maxMappings <= FLOOR, `an other session kept ${maxMappings} mappings`);
  assert.ok(bytes(raw) <= CAP - 4096, `bound ${bytes(raw)} is over ${CAP - 4096}`);
});

test('P6 F1 mapping rule: a kept entry keeps its newest mapping only; an older mapping is missing and a delayed record on it changes nothing', () => {
  const state = stateOf({ cur: mkSession('cur', { entries: 2 }), o: mkSession('o', { entries: 3, mappings: 0 }) });
  const other = state.sessions[keyOf('o')];
  const fp = (i) => hex(`o:e${i}`);
  // order: e0 mapped first, then e1, e2, then e0 twice more (the newest mapping of e0 is last)
  for (const [name, entry] of [['m0', 0], ['m1', 1], ['m2', 2], ['m3', 0], ['m4', 0]]) other.invocations[hex(`o:${name}`)] = fp(entry);
  pruneBytes(state, keyOf('cur'), bytes(state) - 1, 10);
  assert.deepEqual(Object.keys(other.invocations), [hex('o:m1'), hex('o:m2'), hex('o:m4')], 'exactly the newest mapping of each kept entry');
  for (const [, mapped] of Object.entries(other.invocations)) assert.ok(mapped in other.entries, 'no dangling mapping');
  // master's path for an invocation without a mapping (record: operationIdentity of the call, then `if (!entry) return`): no throw, nothing written
  const root = home();
  try {
    controlClock();
    const first = op({ sessionId: 'p6-owner', toolInput: { file_path: '/p6/a' }, invocationId: 'p6-a1' });
    consultSessionLoopGuard(first, { home: root });
    for (const [name, file] of [['p6-b', '/p6/b'], ['p6-c', '/p6/c']]) consultSessionLoopGuard(op({ sessionId: 'p6-owner', toolInput: { file_path: file }, invocationId: name }), { home: root });
    consultSessionLoopGuard({ ...first, invocationId: 'p6-a2' }, { home: root });
    consultSessionLoopGuard({ ...first, invocationId: 'p6-a3' }, { home: root });
    inflate(root, CAP - 10, 'p6fill', -60_000);
    consultSessionLoopGuard(op({ sessionId: 'p6-writer', toolInput: { file_path: '/p6/w' }, invocationId: 'p6-w' }), { home: root });
    const owner = Object.values(loadFile(root).sessions).find((session) => !session.filler && Object.keys(session.entries).length === 3 && Object.keys(session.invocations).length <= 3);
    assert.ok(owner, 'the owner session is at its floor with at most 3 mappings');
    const before = readFileSync(stateFile(root), 'utf8');
    assert.doesNotThrow(() => recordSessionLoopOutcome({ ...first, toolInput: { file_path: '/p6/other-input' }, invocationId: 'p6-a1' }, true, { done: 1 }, { home: root }));
    assert.equal(readFileSync(stateFile(root), 'utf8'), before, 'a record on a dropped older mapping must change nothing');
  } finally { releaseClock(); clean(root); }
});

test('P8 session order: a session stamped after now is ordered as now (ties by key), and its future entries stay on top of the floor', () => {
  const future = NOW + 500_000;
  const build = () => ({
    cur: mkSession('cur', { entries: 2, updated: NOW }),
    a: mkSession('a', { entries: 12, updated: future }),
    b: mkSession('b', { entries: 12, updated: NOW }),
  });
  const keys = ['a', 'b'].sort((x, y) => (keyOf(x) < keyOf(y) ? -1 : 1));
  const state = stateOf(build());
  const start = bytes(state);
  const oneEntry = bytes(build().a) - bytes({ ...build().a, entries: {} }) ;
  pruneBytes(state, keyOf('cur'), start - 1, start - 3 * Math.floor(oneEntry / 12));
  const trimmed = (tag) => Object.keys(state.sessions[keyOf(tag)].entries).length < 12;
  assert.equal(trimmed(keys[0]), true, 'the first session by key is trimmed first');
  assert.equal(trimmed(keys[1]), false, 'the second session is untouched while low water is reached');
  // entries stamped after now are never dropped, even from the oldest session
  const stamped = stateOf({ cur: mkSession('cur', { entries: 2, updated: NOW }), o: mkSession('o', { entries: 8, updated: NOW - 1_000, entryExtra: {} }) });
  for (const entry of Object.values(stamped.sessions[keyOf('o')].entries)) entry.updated_at = NOW + 10_000 + entry.updated_at % 1000;
  const before = Object.keys(stamped.sessions[keyOf('o')].entries).length;
  assert.throws(() => pruneBytes(stamped, keyOf('cur'), 100, 50), UnsafeLoopGuardStateError);
  assert.equal(Object.keys(stamped.sessions[keyOf('o')].entries).length, before);
});

test('S2 record-triggered prune with a heavy writer: the other sessions reach their floor and the writer is still never trimmed', () => {
  const root = home();
  try {
    const call = op({ sessionId: 's2-heavy', toolInput: { file_path: '/s2h/0' }, invocationId: 's2h-0' });
    consultSessionLoopGuard(call, { home: root });
    const state = loadFile(root);
    const [ownerKey] = Object.keys(state.sessions);
    const owner = state.sessions[ownerKey];
    for (let i = 0; i < 255; i += 1) { const fp = hex(`s2h:e${i}`); owner.entries[fp] = mkEntry(fp, realNow() - 10_000 + i); owner.invocations[hex(`s2h:i${i}`)] = fp; }
    for (let n = 0; n < 60; n += 1) {
      const fillerKey = hex(`s2h-filler-${n}`);
      const filler = mkSession(`s2h-filler-${n}`, { entries: 4, updated: realNow() - 20_000 + n });
      state.sessions[fillerKey] = filler;
    }
    state.sessions[hex('s2h-filler-0')].pad = '';
    state.sessions[hex('s2h-filler-0')].pad = 'x'.repeat(CAP - 5 - bytes(state));
    saveFile(root, state);
    assert.equal(sizeOf(root), CAP - 5);
    const heavy = Object.keys(owner.entries).length;
    recordSessionLoopOutcome(call, true, { done: 1 }, { home: root });
    const after = loadFile(root).sessions[ownerKey];
    assert.equal(Object.keys(after.entries).length, heavy, 'the record-writing session lost entries');
    assert.equal(Object.keys(after.invocations).length, heavy);
    assert.ok(sizeOf(root) <= CAP);
  } finally { clean(root); }
});
