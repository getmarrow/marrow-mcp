'use strict';
// Preload for the `keys create` CLI and MCP stdio tests: every outgoing fetch
// (method, URL, body) is appended to CAPTURE_FILE and answered locally; nothing
// leaves the process. The created key is the runtime dummy in STUB_KEY.
const fs = require('node:fs');

globalThis.fetch = async (url, init = {}) => {
  const method = String(init.method || 'GET').toUpperCase();
  fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify({ method, url: String(url), body: typeof init.body === 'string' ? init.body : '' })}\n`);
  const created = method === 'POST' && String(url).endsWith('/v1/auth/keys');
  const data = created ? { key_id: 'key_stub1', key: process.env.STUB_KEY } : {};
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
};
