'use strict';
// Helpers for the K2b loop-guard fingerprint tests (MCP-111). Every home and every dist copy is a mktemp folder; every
// secret is made at run time. Nothing here prints a fingerprint, receipt or secret value.
const { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { createHmac, randomBytes } = require('node:crypto');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const ROOT = resolve(__dirname, '..', '..');
const SWITCH_LINE = 'const LOOP_GUARD_SPLIT = true;';
const copies = [];

function load(dist) { return require(join(dist, 'session-loop-guard.js')); }

/** The shipped dist (switch ON), a mktemp copy with the one switch line set false (OFF) and, when K2B_BASE_DIST names a 3.9.110 dist, that one. */
function variants() {
  const shipped = readFileSync(join(ROOT, 'dist', 'session-loop-guard.js'), 'utf8');
  if (shipped.split(SWITCH_LINE).length !== 2) throw new Error('the shipped dist must hold exactly one switch line, set true');
  const off = mkdtempSync(join(tmpdir(), 'k2b-dist-off-'));
  copies.push(off);
  cpSync(join(ROOT, 'dist'), off, { recursive: true });
  writeFileSync(join(off, 'session-loop-guard.js'), shipped.replace(SWITCH_LINE, 'const LOOP_GUARD_SPLIT = false;'));
  const found = { on: load(join(ROOT, 'dist')), off: load(off) };
  if (process.env.K2B_BASE_DIST) found.base = load(process.env.K2B_BASE_DIST);
  return found;
}
process.on('exit', () => { for (const dir of copies) rmSync(dir, { recursive: true, force: true }); });

function world() { return mkdtempSync(join(tmpdir(), 'k2b-home-')); }
function secretValue() { return randomBytes(32).toString('base64url'); }
/** Write a state file (3.9.110 format) with a known runtime secret so two variants can be compared on one device key. */
function seedHome(home, secret = secretValue(), sessions = {}) {
  const directory = join(home, '.marrow', 'session-loop-guard');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(join(home, '.marrow'), 0o700);
  chmodSync(directory, 0o700);
  const target = join(directory, 'state.json');
  writeFileSync(target, `${JSON.stringify({ version: 1, secret, sessions })}\n`, { mode: 0o600 });
  chmodSync(target, 0o600);
  return { secret, target };
}
function readStateFile(home) { return JSON.parse(readFileSync(join(home, '.marrow', 'session-loop-guard', 'state.json'), 'utf8')); }
function stateBytes(home) { return readFileSync(join(home, '.marrow', 'session-loop-guard', 'state.json'), 'utf8'); }

function op(toolInput, extra = {}) {
  return { sessionId: 'k2b-session', agentId: 'k2b-agent', harness: 'claude', toolName: 'Read', toolInput, readOnly: true, ...extra };
}
const POLL = (extra = {}) => op({ command: 'gh run view --status' }, { toolName: 'Bash', ...extra });
const FAILING = (input, extra = {}) => op(input, { toolName: 'Edit', readOnly: false, ...extra });

// ---- a frozen copy of 3.9.110 canonical() and keyedHash() (src/session-loop-guard.ts at 7142ad3) ----
function canonical110(value, depth = 0) {
  if (depth > 8) return '[depth]';
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'string') return value.slice(0, 16_384);
  if (Array.isArray(value)) return value.slice(0, 128).map((item) => canonical110(item, depth + 1));
  if (value && typeof value === 'object') {
    const source = value;
    return Object.fromEntries(Object.keys(source).sort().slice(0, 128).map((key) => [key.slice(0, 128), canonical110(source[key], depth + 1)]));
  }
  return String(value).slice(0, 256);
}
function keyedHash110(secret, value) {
  return createHmac('sha256', Buffer.from(secret, 'base64url')).update(JSON.stringify(canonical110(value))).digest('hex');
}
function identity110(secret, operation, session = { work_epoch: 0, instruction_epoch: 0 }) {
  const { normalizeHookToolName } = require(join(ROOT, 'dist', 'hook-tool-policy.js'));
  return keyedHash110(secret, ['operation', operation.harness, operation.agentId || 'credential-agent', normalizeHookToolName(operation.toolName) || 'tool', canonical110(operation.toolInput ?? null), session.work_epoch, session.instruction_epoch]);
}
function identityArray(operation, session = { work_epoch: 0, instruction_epoch: 0 }) {
  const { normalizeHookToolName } = require(join(ROOT, 'dist', 'hook-tool-policy.js'));
  return ['operation', operation.harness, operation.agentId || 'credential-agent', normalizeHookToolName(operation.toolName) || 'tool', operation.toolInput ?? null, session.work_epoch, session.instruction_epoch];
}

// ---- seeded generator (mulberry32) and value builders ----
function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const SCALARS = [null, true, false, 0, 1, -1, 2.5, 'a', 'text', ''];
const pick = (r, list) => list[Math.floor(r() * list.length)];
// A value with one slot a caller can fill. `wrap(nesting, leaf)` buries the leaf in `nesting` levels of arrays and objects.
function wrap(nesting, leaf) {
  let node = leaf;
  for (let i = 0; i < nesting; i += 1) node = i % 2 === 0 ? { w: node } : [node];
  return node;
}
const S16 = 'x'.repeat(16_384);
const keysObject = (count, last, prefix = 'k') => Object.fromEntries(Array.from({ length: count }, (_, i) => [`${prefix}${String(i).padStart(4, '0')}`, i === count - 1 ? last : i]));
const itemsArray = (count, last) => Array.from({ length: count }, (_, i) => (i === count - 1 ? last : i));
// A chain of `levels` objects ending in {leaf}; a leaf at relative depth `levels + 1`.
const deepChain = (leaf, levels) => { let node = { leaf }; for (let i = 0; i < levels; i += 1) node = { n: node }; return node; };

// ---- decoder for the fullDigest token stream (K4b): tokens are tagged and length-prefixed, so the stream parses uniquely ----
function decodeTokens(tokens) {
  const text = tokens.join('');
  let at = 0;
  const readUntil = (stop) => { const end = text.indexOf(stop, at); if (end < 0) throw new Error('bad stream'); const part = text.slice(at, end); at = end + 1; return part; };
  const readValue = () => {
    const tag = text[at]; at += 1;
    if (tag === 'z') return null;
    if (tag === 'T') return true;
    if (tag === 'F') return false;
    if (tag === 'n') { const m = /^-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/.exec(text.slice(at)); at += m[0].length; return Number(m[0]); }
    if (tag === 'N') { const word = readUntil(';'); return word === 'NaN' ? Number.NaN : word === 'Infinity' ? Infinity : -Infinity; }
    if (tag === 's') { const length = Number(readUntil(':')); const out = text.slice(at, at + length); at += length; return out; }
    if (tag === '[') { const count = Number(readUntil(':')); const out = []; for (let i = 0; i < count; i += 1) out.push(readValue()); if (text[at] !== ']') throw new Error('bad array'); at += 1; return out; }
    if (tag === '{') {
      const count = Number(readUntil(':'));
      const out = new Map();
      for (let i = 0; i < count; i += 1) { if (text[at] !== 's') throw new Error('bad key'); out.set(readValue(), readValue()); }
      if (text[at] !== '}') throw new Error('bad object'); at += 1; return out;
    }
    throw new Error('bad tag');
  };
  const value = readValue();
  if (at !== text.length) throw new Error('trailing');
  return value;
}
// A plain structure with Map for objects (so `__proto__` and `constructor` keys can be compared without prototype effects).
function toComparable(value) {
  if (Array.isArray(value)) return value.map(toComparable);
  if (value && typeof value === 'object') return new Map(Object.keys(value).sort().map((key) => [key, toComparable(Object.getOwnPropertyDescriptor(value, key).value)]));
  return value;
}

module.exports = { ROOT, variants, world, secretValue, seedHome, readStateFile, stateBytes, op, POLL, FAILING, canonical110, keyedHash110, identity110, identityArray, rng, pick, SCALARS, wrap, S16, keysObject, itemsArray, deepChain, decodeTokens, toComparable, rmSync, existsSync };
