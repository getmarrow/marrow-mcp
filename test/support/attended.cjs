'use strict';

// Attended evidence for the hook-process harnesses. A Claude Code dialog (an "ask") needs a marker that the
// UserPromptSubmit hook writes when the owner types in a session (dist/attended-marker.js, valid 10 minutes). The
// harnesses run each hook event as its own process, with no prompt hook in front, so they write the marker for a
// default, acceptEdits or auto payload that has a session id (auto is included on purpose: it must never ask even with
// fresh evidence). Plan, bypass and dontAsk payloads never ask, with or without it.
function attendFor(home, payload) {
  let event = payload;
  if (typeof payload === 'string') {
    try { event = JSON.parse(payload); } catch { return false; }
  }
  if (!event || !/^(?:default|acceptEdits|auto)$/.test(event.permission_mode) || typeof event.session_id !== 'string') return false;
  let marker;
  try { marker = require('../../dist/attended-marker.js'); } catch { return false; } // a build without the marker (the BASE build) needs none
  return marker.recordAttendedPrompt(event.session_id, { home });
}

module.exports = { attendFor };
