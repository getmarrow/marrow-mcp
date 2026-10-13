'use strict';

// Dummy secrets for the U6 fuzz, generated at run time from random bytes; none is a real credential and
// none is ever printed. Shapes differ in length and alphabet (hex, base64, base64url, upper-case base32,
// mixed case with digits, a password-like word) so the redaction and the keyed hashes meet every kind of value.
const crypto = require('node:crypto');

const hex = (n) => crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
const b64 = (n) => crypto.randomBytes(n).toString('base64').replace(/=+$/, '');
const b64u = (n) => crypto.randomBytes(n).toString('base64url');
const upper = (n) => [...crypto.randomBytes(n)].map((b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[b % 32]).join('');

const SHAPES = [
  () => hex(32), () => hex(64), () => b64(48), () => b64u(33), () => upper(20), () => `pw-${hex(6)}`, () => `Zq9${hex(12)}X`,
  () => `${b64u(6)}.${b64u(12)}.${b64u(10)}`, () => `${hex(4)}-${hex(24)}`, () => `${upper(4)}_${b64u(27)}`, () => `${b64u(30)}${hex(12)}`,
];

module.exports = { SHAPES, hex };
