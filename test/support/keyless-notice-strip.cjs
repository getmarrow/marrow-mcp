'use strict';

// MCP-5: the first keyless Claude Code hook call of a session also carries `systemMessage` with the exact keyless notice.
// Tests that pin the rest of a keyless answer compare it without that one field.
const { KEYLESS_NOTICE_TEXT } = require('../../dist/keyless-notice.js');

function withoutKeylessNotice(value) {
  if (typeof value === 'string') {
    let parsed;
    try { parsed = JSON.parse(value); } catch { return value; }
    const stripped = withoutKeylessNotice(parsed);
    return stripped === parsed ? value : JSON.stringify(stripped);
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && value.systemMessage === KEYLESS_NOTICE_TEXT) {
    const { systemMessage, ...rest } = value;
    return rest;
  }
  return value;
}

module.exports = { withoutKeylessNotice };
