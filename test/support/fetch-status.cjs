'use strict';
// Preload: every outgoing fetch is appended to CAPTURE_FILE and answered locally with FETCH_STATUS and a JSON error body; nothing leaves the process.
const fs = require('node:fs');

globalThis.fetch = async (url, init = {}) => {
  fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify({ url: String(url), body: typeof init.body === 'string' ? init.body : '' })}\n`);
  const status = Number(process.env.FETCH_STATUS || 403);
  return new Response(JSON.stringify({ error: { code: process.env.FETCH_CODE || 'MARROW_SESSION_AGENT_MISMATCH', message: 'synthetic' } }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
};
