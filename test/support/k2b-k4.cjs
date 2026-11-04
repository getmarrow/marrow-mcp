'use strict';
// K4 generator for K2b: pairs of values that differ only past one canonical() cap (shared by the seed files and the fingerprint tests).
const h = require('./k2b-loop-guard.cjs');

const CAPS = ['string', 'keys', 'items', 'keyname', 'depth', 'nonfinite'];
function pastCapPair(r, cap, place, type, nesting) {
  const at = (first, last) => (place === 0 ? first : place === 2 ? last : first + Math.floor(r() * (last - first + 1)));
  let a; let b;
  if (cap === 'string') {
    const length = 16_385 + Math.floor(r() * 300);
    const i = at(16_384, length - 1);
    const make = (c) => `${'s'.repeat(i)}${c}${'s'.repeat(length - i - 1)}`;
    a = make('A'); b = make('B');
  } else if (cap === 'keys') {
    const count = 129 + Math.floor(r() * 40);
    const i = at(128, count - 1);
    const make = (v) => Object.fromEntries(Array.from({ length: count }, (_, k) => [`k${String(k).padStart(4, '0')}`, k === i ? v : k]));
    a = make('A'); b = make('B');
  } else if (cap === 'items') {
    const count = 129 + Math.floor(r() * 40);
    const i = at(128, count - 1);
    const make = (v) => Array.from({ length: count }, (_, k) => (k === i ? v : k));
    a = make('A'); b = make('B');
  } else if (cap === 'keyname') {
    const length = 129 + Math.floor(r() * 40);
    const i = at(128, length - 1);
    const make = (c) => ({ [`${'n'.repeat(i)}${c}${'n'.repeat(length - i - 1)}`]: 1 });
    a = make('A'); b = make('B');
  } else if (cap === 'depth') {
    const levels = at(7, 20); // the leaf value sits at relative depth levels + 1 (>= 8)
    a = h.deepChain('A', levels); b = h.deepChain('B', levels);
  } else {
    const word = h.pick(r, ['Infinity', '-Infinity', 'NaN']);
    const num = word === 'NaN' ? Number.NaN : word === 'Infinity' ? Infinity : -Infinity;
    a = { v: num }; b = { v: word };
  }
  if (type === 1) { a = [a]; b = [b]; } else if (type === 2) { a = { x: a }; b = { x: b }; }
  return [h.wrap(nesting, a), h.wrap(nesting, b)];
}


module.exports = { CAPS, pastCapPair };
