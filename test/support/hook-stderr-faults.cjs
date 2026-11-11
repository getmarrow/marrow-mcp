'use strict';

// Test-only (never ships): runs the real hook CLI with a broken stderr, for the C1R1 rows of
// test/cursor-hook-budget.test.js (MARROW_HOOK_TIMING=1 must never change the answer). Two roles:
// - required by a test: runFaulted() spawns `<root>/dist/cli.js <host>-pre-action-hook` with one stderr fault;
// - loaded as a preload in that child (HSF_PRELOAD=1): makes process.stderr.write fail (HSF_FAULT=throw | async-error),
//   from the start or, with HSF_ARM=exit, only once the process is exiting (the `route=total` line).
// Faults: none | epipe (the reader closed the pipe) | epipe-after-answer (closed when the first stdout byte arrives)
// | ebadf (fd 2 closed at spawn) | throw | async-error | full (a FIFO filled to capacity before spawn and never read).
const fs = require('node:fs');
const path = require('node:path');

if (process.env.HSF_PRELOAD === '1') {
  const fault = process.env.HSF_FAULT;
  const arm = () => {
    const stream = process.stderr;
    if (fault === 'throw') {
      stream.write = () => { throw Object.assign(new Error('write EBADF'), { code: 'EBADF' }); };
    } else if (fault === 'async-error') {
      stream.write = function write() {
        process.nextTick(() => this.emit('error', Object.assign(new Error('write EPIPE'), { code: 'EPIPE' })));
        return true;
      };
    }
  };
  if (process.env.HSF_ARM === 'exit') process.once('exit', arm);
  else arm();
} else {
  const crypto = require('node:crypto');
  const { spawn, execFileSync } = require('node:child_process');
  const { makeHome, dummyKey, SHAPES } = require('./cursor-budget-run.cjs');
  const HERE = __dirname;

  /** A FIFO whose buffer is already full, with a reader that never reads, and a blocking write end for the child. */
  function fullFifo(dir) {
    const fifo = path.join(dir, `stderr-${crypto.randomBytes(4).toString('hex')}.fifo`);
    execFileSync('mkfifo', [fifo]);
    const reader = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const filler = fs.openSync(fifo, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
    let filled = 0;
    for (const size of [4096, 256, 16, 1]) {
      const chunk = Buffer.alloc(size, 0x2e);
      for (;;) {
        try { filled += fs.writeSync(filler, chunk); } catch (error) { if (error.code === 'EAGAIN') break; throw error; }
      }
    }
    fs.closeSync(filler);
    const writer = fs.openSync(fifo, fs.constants.O_WRONLY);
    // Each fd is closed once: a second close could hit a number another run has reused since.
    const once = (fd) => { let open = true; return () => { if (open) { open = false; fs.closeSync(fd); } }; };
    return { writer, filled, closeWriter: once(writer), closeReader: once(reader) };
  }

  /**
   * One hook process under one stderr fault. Returns stdout, exit status, stderr (when it is readable), the wall time to
   * the last stdout byte and to exit. root: the build to run (tip, F2 or master); preloads come from that build when it
   * has them.
   */
  function runFaulted({ root, host = 'cursor', command, scenario = 'ok', delays = {}, fault = 'none', timing = false, arm = '', key = dummyKey() }) {
    const own = makeHome();
    const support = (name) => (fs.existsSync(path.join(root, 'test', 'support', name)) ? path.join(root, 'test', 'support', name) : path.join(HERE, name));
    const env = {
      PATH: process.env.PATH, HOME: own.home, SBT_PASSWD_HOME: own.home, MARROW_API_KEY: key, MARROW_BASE_URL: 'https://api.example.test',
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', CB_SCENARIO: scenario,
      ...(timing ? { MARROW_HOOK_TIMING: '1' } : {}),
      ...((fault === 'throw' || fault === 'async-error') ? { HSF_PRELOAD: '1', HSF_FAULT: fault, ...(arm ? { HSF_ARM: arm } : {}) } : {}),
    };
    for (const [name, ms] of Object.entries(delays)) env[`CB_DELAY_${name.toUpperCase()}`] = String(ms);
    const nodeArgs = [
      '--require', support('passwd-home-fake.cjs'), '--require', support('seatbelt-hook-preload.cjs'),
      '--require', path.join(HERE, 'cursor-budget-stub.cjs'), '--require', path.join(HERE, 'hook-stderr-faults.cjs'),
      path.join(root, 'dist', 'cli.js'), `${host}-pre-action-hook`,
    ];
    const fifo = fault === 'full' ? fullFifo(own.home) : null;
    const stdio = ['pipe', 'pipe', fifo ? fifo.writer : 'pipe'];
    return new Promise((resolve) => {
      const t0 = Date.now();
      const child = fault === 'ebadf'
        ? spawn('/bin/sh', ['-c', 'exec 2>&-; exec "$0" "$@"', process.execPath, ...nodeArgs], { cwd: own.proj, stdio, env })
        : spawn(process.execPath, nodeArgs, { cwd: own.proj, stdio, env });
      if (fifo) fifo.closeWriter();
      let out = '';
      let err = '';
      let lastOutMs = null;
      let exitMs = null;
      if (fault === 'epipe') child.stderr.destroy();
      else if (child.stderr) child.stderr.on('data', (chunk) => { err += chunk; });
      child.stdout.on('data', (chunk) => {
        out += chunk;
        lastOutMs = Date.now() - t0;
        if (fault === 'epipe-after-answer' && !child.stderr.destroyed) child.stderr.destroy();
      });
      const killer = setTimeout(() => child.kill('SIGKILL'), 40_000);
      child.on('exit', () => { exitMs = Date.now() - t0; });
      child.on('close', (status, signal) => {
        clearTimeout(killer);
        if (fifo) fifo.closeReader();
        own.cleanup();
        let answer = null;
        try { answer = out.trim() ? JSON.parse(out) : null; } catch { answer = null; }
        resolve({ host, fault, arm, timing, status, signal, out, err, answer, lastOutMs, exitMs: exitMs ?? Date.now() - t0, filled: fifo ? fifo.filled : 0 });
      });
      child.stdin.on('error', () => {});
      child.stdin.end(JSON.stringify(SHAPES[host](command, own.proj, 'hsf-agent-1')));
    });
  }

  const FAULTS = ['epipe', 'ebadf', 'throw', 'async-error', 'full'];
  module.exports = { runFaulted, FAULTS };
}
