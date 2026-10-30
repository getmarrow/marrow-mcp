'use strict';
// Preload for the N1 rows (test only, never ships). It starts the process with the OPPOSITE settings (resolver order verbatim, happy eyeballs
// off), then records, at every outgoing fetch, what is in force and what the request is (URL, method, header names). Every fetch is answered
// locally: nothing leaves the process.
const fs = require('node:fs');
const dns = require('node:dns');
const net = require('node:net');

dns.setDefaultResultOrder('verbatim');
net.setDefaultAutoSelectFamily(false);
fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify({ phase: 'start', order: dns.getDefaultResultOrder(), autoSelectFamily: net.getDefaultAutoSelectFamily() })}\n`);

globalThis.fetch = async (url, init = {}) => {
  const headers = init.headers instanceof Headers ? Object.fromEntries(init.headers) : { ...(init.headers || {}) };
  fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify({
    phase: 'request',
    url: String(url),
    method: init.method || 'GET',
    headers: Object.keys(headers).map((name) => name.toLowerCase()).sort(),
    order: dns.getDefaultResultOrder(),
    autoSelectFamily: net.getDefaultAutoSelectFamily(),
  })}\n`);
  return new Response(JSON.stringify({ data: {} }), { status: 200, headers: { 'content-type': 'application/json' } });
};
