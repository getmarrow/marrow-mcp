'use strict';

// Preloaded into every hook process by tools/fh-diff.cjs (NODE_OPTIONS=--require). It makes the
// hooks' randomness a fixed stream, so the base build and the branch build create the same salts,
// state secrets and ids for the same events, and a keyed value (an action key, an exact_hmac, a
// hold id or code) can be compared byte for byte. It changes nothing else.
const crypto = require('node:crypto');

const seed = process.env.FHD_SEED || 'fh-diff-seed';
let counter = 0;

function bytes(size) {
  const parts = [];
  let length = 0;
  while (length < size) {
    const block = crypto.createHmac('sha256', seed).update(String(counter)).digest();
    counter += 1;
    parts.push(block);
    length += block.length;
  }
  return Buffer.concat(parts).subarray(0, size);
}

crypto.randomBytes = function randomBytes(size, callback) {
  const out = bytes(size);
  if (typeof callback === 'function') { process.nextTick(callback, null, out); return undefined; }
  return out;
};
crypto.randomUUID = function randomUUID() {
  const b = bytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};
crypto.randomInt = function randomInt(min, max, callback) {
  if (typeof max === 'undefined' || typeof max === 'function') { callback = max; max = min; min = 0; }
  const span = Number(max) - Number(min);
  const value = Number(min) + (bytes(6).readUIntBE(0, 6) % Math.max(1, span));
  if (typeof callback === 'function') { process.nextTick(callback, null, value); return undefined; }
  return value;
};

// A loaded machine must not flip an answer: the seatbelt's 300 ms budget and the host hooks' own
// deadlines are moved out (the same two switches test/support/seatbelt-hook-preload.cjs has). Both
// builds get the same treatment, so this only removes timing as a source of difference.
if (process.env.FHD_ROOMY === '1') {
  const path = require('node:path');
  const Module = require('node:module');
  const dist = path.dirname(process.argv[1] || '');
  const targets = new Map([
    [path.join(dist, 'seatbelt', 'hook.js'), (m) => { m.HOOK_BUDGET_MS = 30_000; }],
    [path.join(dist, 'host-approval.js'), (m) => { m.preToolDeadline = () => Date.now() + 30_000; }],
  ]);
  const load = Module._load;
  Module._load = function _load(request, parent, isMain) {
    const exports = load.apply(this, arguments);
    try {
      const resolved = Module._resolveFilename(request, parent, isMain);
      const patch = targets.get(resolved);
      if (patch && !exports.__fhdPatched) { patch(exports); exports.__fhdPatched = true; }
    } catch { /* not a module of ours */ }
    return exports;
  };
}
