'use strict';
// Preload for the base-URL tests: every outgoing fetch and every socket connect is recorded in
// CAPTURE_FILE and refused locally; nothing leaves the process. A record says where the request
// went and whether any header or body carried the dummy key in M2_EXPECT_KEY, never the key.
const fs = require('node:fs');
const net = require('node:net');

const key = process.env.M2_EXPECT_KEY || '';

function carriesKey(init) {
  if (!key) return false;
  const headers = init && init.headers;
  let values = [];
  if (headers && typeof headers.forEach === 'function' && !Array.isArray(headers)) headers.forEach((value) => values.push(String(value)));
  else if (Array.isArray(headers)) values = headers.map((pair) => String(pair[1]));
  else if (headers && typeof headers === 'object') values = Object.values(headers).map(String);
  const body = init && typeof init.body === 'string' ? init.body : '';
  return values.some((value) => value.includes(key)) || body.includes(key);
}

function record(entry) {
  try { fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify(entry)}\n`); } catch { /* recording is best effort */ }
}

globalThis.fetch = async (url, init = {}) => {
  record({ kind: 'fetch', url: String(url && url.url ? url.url : url), carries_key: carriesKey(init) });
  throw new TypeError('fetch failed');
};

const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guarded(...args) {
  const first = args[0];
  const target = first && typeof first === 'object' ? `${first.host || 'localhost'}:${first.port || ''}` : `${args[1] || 'localhost'}:${first}`;
  record({ kind: 'connect', target });
  const error = new Error('connect refused by the test recorder');
  error.code = 'ECONNREFUSED';
  process.nextTick(() => this.destroy(error));
  return this;
};
void connect;
