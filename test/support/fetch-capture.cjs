'use strict';
// Preload for the MCP stdio path: every outgoing fetch (URL and body) is
// appended to CAPTURE_FILE and answered locally; nothing leaves the process.
const fs = require('node:fs');

globalThis.fetch = async (url, init = {}) => {
  fs.appendFileSync(process.env.CAPTURE_FILE, `${JSON.stringify({ url: String(url), body: typeof init.body === 'string' ? init.body : '' })}\n`);
  return new Response(JSON.stringify({ data: { decision_count: 0, memories: [], count: 0 } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
};
