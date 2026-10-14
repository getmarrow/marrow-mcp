'use strict';

// Test-only preload for the real hook CLI (`node --require <this> dist/cli.js <hook>`), U5 tests.
// It never ships: the hook reads none of these names. Each switch only fakes a host fact or
// injects a fault so a test can see the hook's answer:
//   SBT_PASSWD_HOME  the home getpwuid() reports (the build server's real home is never probed)
//   SBT_NETSPY       file: every socket, DNS, http(s) or fetch attempt appends a line, then throws
//   SBT_RECORD       file: every recordSeatbeltDecision() call appends its JSON record
//   SBT_FS_FAULT     ENOSPC | EACCES: a write to (ENOSPC) or an open of (EACCES) a receipt file fails (U6)
//   SBT_THROW        mapper | mode | git | load | record: that seatbelt part throws
//   SBT_SLOW_MS      the mapper sleeps this long first (the hook budget is 300 ms; with this switch the budget stays 300 ms)
//   SBT_HOOK_BUDGET  production: keep the hook's 300 ms budget (by default a spawned hook gets 30 s so load cannot flip an answer)
//   SBT_HOOK_DEADLINE  roomy: the hook's pre-tool deadline (Codex 2 s, Cursor/Grok/Gemini 4 s) is moved 30 s out (f2 outage tests only)
//   SBT_ROLLOUT_KEYLESS  off: SEATBELT_ROLLOUT.keyless is forced to 'off' (the kill switch, audit I1)
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const dist = path.resolve(__dirname, '..', '..', 'dist');
const env = process.env;

if (env.SBT_PASSWD_HOME) {
  const real = os.userInfo;
  os.userInfo = function userInfo(options) {
    return { ...real.call(os, options), homedir: env.SBT_PASSWD_HOME };
  };
}

if (env.SBT_NETSPY) {
  const out = env.SBT_NETSPY;
  const trip = (what) => {
    fs.appendFileSync(out, `${what}\n`);
    throw new Error(`network blocked in test: ${what}`);
  };
  const net = require('node:net');
  const tls = require('node:tls');
  const http = require('node:http');
  const https = require('node:https');
  const dns = require('node:dns');
  net.Socket.prototype.connect = function connect() { return trip('net.Socket.connect'); };
  net.connect = net.createConnection = () => trip('net.connect');
  tls.connect = () => trip('tls.connect');
  http.request = http.get = () => trip('http.request');
  https.request = https.get = () => trip('https.request');
  dns.lookup = () => trip('dns.lookup');
  dns.promises.lookup = async () => trip('dns.promises.lookup');
  globalThis.fetch = async () => trip('fetch');
}

const wrapAfterLoad = (file, patch) => {
  const target = path.join(dist, file);
  const load = Module._load;
  Module._load = function _load(request, parent, isMain) {
    const exports = load.apply(this, arguments);
    try {
      if (Module._resolveFilename(request, parent, isMain) === target && !exports.__sbtPatched) {
        patch(exports);
        exports.__sbtPatched = true;
      }
    } catch { /* not ours */ }
    return exports;
  };
};

if (env.SBT_RECORD) {
  wrapAfterLoad('seatbelt/record.js', (m) => {
    m.recordSeatbeltDecision = (record) => fs.appendFileSync(env.SBT_RECORD, `${JSON.stringify(record)}\n`);
  });
}

if (env.SBT_FS_FAULT) {
  const code = env.SBT_FS_FAULT;
  const fds = new Map();
  const realOpen = fs.openSync;
  const realWrite = fs.writeSync;
  const receipt = (p) => String(p).includes('/.marrow/seatbelt/receipts/');
  fs.openSync = function openSync(p, ...rest) {
    if (code === 'EACCES' && receipt(p)) throw Object.assign(new Error(code), { code });
    const fd = realOpen.call(this, p, ...rest);
    fds.set(fd, String(p));
    return fd;
  };
  fs.writeSync = function writeSync(fd, ...rest) {
    if (code === 'ENOSPC' && receipt(fds.get(fd))) throw Object.assign(new Error(code), { code });
    return realWrite.call(this, fd, ...rest);
  };
}

const fault = env.SBT_THROW || '';
if (fault === 'load') {
  const target = path.join(dist, 'seatbelt', 'hook.js');
  const load = Module._load;
  Module._load = function _load(request, parent, isMain) {
    let resolved = null;
    try { resolved = Module._resolveFilename(request, parent, isMain); } catch { /* ignore */ }
    if (resolved === target) throw new Error('injected module load failure');
    return load.apply(this, arguments);
  };
}
if (fault === 'mapper') wrapAfterLoad('seatbelt/mapper.js', (m) => { m.evaluateSeatbelt = () => { throw new Error('injected mapper crash'); }; });
if (fault === 'mode') wrapAfterLoad('seatbelt-mode.js', (m) => { m.resolveSeatbeltModeOnHost = () => { throw new Error('injected mode crash'); }; });
if (fault === 'git') wrapAfterLoad('seatbelt-git.js', (m) => { m.discoverGitDirs = () => { throw new Error('injected resolver crash'); }; });
if (fault === 'record') wrapAfterLoad('seatbelt/record.js', (m) => { m.recordSeatbeltDecision = () => { throw new Error('injected record crash'); }; });

// The hook's own 300 ms budget turns any check that runs long into a fail-closed stop (U5.fail_closed, hook_budget). On a
// loaded machine that flips answers these tests are not about, so a spawned hook gets a roomy budget by default.
// SBT_SLOW_MS (the test of the budget itself) and SBT_HOOK_BUDGET=production keep the production 300 ms.
const roomyBudget = !env.SBT_SLOW_MS && env.SBT_HOOK_BUDGET !== 'production';
if (env.SBT_ROLLOUT_KEYLESS || roomyBudget) {
  // One patch for both switches: wrapAfterLoad patches a module once.
  wrapAfterLoad('seatbelt/hook.js', (m) => {
    if (env.SBT_ROLLOUT_KEYLESS) m.SEATBELT_ROLLOUT = Object.freeze({ ...m.SEATBELT_ROLLOUT, keyless: env.SBT_ROLLOUT_KEYLESS });
    if (roomyBudget) m.HOOK_BUDGET_MS = 30_000;
  });
}

// The hook's own deadline (src/host-approval.ts preToolDeadline: Codex about 2 s, Cursor, Grok and Gemini 4 s, counted from process start) also
// limits the seatbelt reading: budget = deadline - now - 200 ms, and a budget under 20 ms means "unknown". On a loaded machine a hook that
// started slowly crosses it, and the outage hold then keeps the classifier's answer. SBT_HOOK_DEADLINE=roomy (set by
// test/f2-outage-fail-closed.test.js only) moves the deadline 30 s out. It never ships; the production values stay pinned by that test.
if (env.SBT_HOOK_DEADLINE === 'roomy') {
  wrapAfterLoad('host-approval.js', (m) => { m.preToolDeadline = () => Date.now() + 30_000; });
}

if (env.SBT_SLOW_MS) {
  const ms = Number(env.SBT_SLOW_MS);
  wrapAfterLoad('seatbelt/mapper.js', (m) => {
    const real = m.evaluateSeatbelt;
    m.evaluateSeatbelt = (...args) => {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
      return real(...args);
    };
  });
}
