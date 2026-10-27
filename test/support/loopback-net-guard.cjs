'use strict';

// Test-only (never ships). A loopback-only network guard, preloaded (--require) into every harness that runs dist/cli.js or
// the MCP server: every non-loopback connect and DNS lookup fails and is logged (one line per attempt to
// MARROW_NET_GUARD_LOG, no key, no URL path), so a dummy-key run can never reach a real service.
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns');

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\]|::ffff:127(?:\.\d{1,3}){3})$/i;
const record = (kind, target) => {
  const line = `${kind} ${String(target).replace(/[^A-Za-z0-9.:\[\]_-]/g, '?').slice(0, 120)}\n`;
  try { if (process.env.MARROW_NET_GUARD_LOG) fs.appendFileSync(process.env.MARROW_NET_GUARD_LOG, line); } catch { /* best effort */ }
};
const refuse = (kind, target, code) => {
  record(kind, target);
  const error = new Error(`loopback-only network guard: ${kind} ${String(target).slice(0, 80)} refused`);
  error.code = code;
  return error;
};
const hostOf = (args) => {
  const first = args[0];
  if (first && typeof first === 'object' && !Array.isArray(first)) return first.path ? null : (first.host ?? first.hostname ?? 'localhost');
  if (typeof first === 'string' && Number.isNaN(Number(first))) return null; // a unix socket path
  return typeof args[1] === 'string' ? args[1] : 'localhost';
};

for (const [owner, name] of [[net, 'connect'], [net, 'createConnection'], [tls, 'connect']]) {
  const original = owner[name];
  owner[name] = function guarded(...args) {
    const host = hostOf(args);
    if (host === null || LOOPBACK.test(String(host))) return original.apply(this, args);
    const socket = new net.Socket();
    process.nextTick(() => socket.destroy(refuse('connect', host, 'ECONNREFUSED')));
    return socket;
  };
}
const socketConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guarded(...args) {
  const host = hostOf(Array.isArray(args[0]) ? args[0] : args);
  if (host === null || LOOPBACK.test(String(host))) return socketConnect.apply(this, args);
  process.nextTick(() => this.destroy(refuse('connect', host, 'ECONNREFUSED')));
  return this;
};
const guardLookup = (original) => function guarded(hostname, ...rest) {
  if (LOOPBACK.test(String(hostname))) return original.call(this, hostname, ...rest);
  const callback = rest.find((entry) => typeof entry === 'function');
  const error = refuse('lookup', hostname, 'ENOTFOUND');
  if (callback) { process.nextTick(callback, error); return undefined; }
  return Promise.reject(error);
};
dns.lookup = guardLookup(dns.lookup);
for (const name of ['resolve', 'resolve4', 'resolve6', 'resolveAny']) if (typeof dns[name] === 'function') dns[name] = guardLookup(dns[name]);
if (dns.promises) {
  dns.promises.lookup = guardLookup(dns.promises.lookup);
  for (const name of ['resolve', 'resolve4', 'resolve6', 'resolveAny']) if (typeof dns.promises[name] === 'function') dns.promises[name] = guardLookup(dns.promises[name]);
}
