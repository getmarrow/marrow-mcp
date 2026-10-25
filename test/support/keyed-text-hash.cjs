'use strict';

// Test-only (never ships). An independent re-implementation of the per-install keyed text hash
// (command_sha256 / input_sha256 of every action but a clear deploy, and hook targets), so a test pins the
// formula without calling the code under test. The key is the dummy device salt in the scratch passwd home
// (test/support/isolated-environment.cjs); it is never printed.
const { createHash, createHmac } = require('node:crypto');
const path = require('node:path');

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

function deviceSalt() {
  return require(path.join(__dirname, '..', '..', 'dist', 'seatbelt', 'record.js')).deviceSalt();
}

function textKey(salt) {
  return createHmac('sha256', salt).update('marrow-text-hmac-key-v2').digest();
}

/** HMAC-SHA256(sub-key, "marrow-text-hmac-v2\n" kind "\n" JSON(tool name) "\n" preimage), 64 hex. */
function textMac(salt, kind, toolName, preimage) {
  return createHmac('sha256', textKey(salt)).update(`marrow-text-hmac-v2\n${kind}\n${JSON.stringify(toolName)}\n`).update(preimage).digest('hex');
}

/** The keyed hash of a plain shell call under `toolName`'s domain (Bash: `shell`; Monitor, PowerShell: `shell-tool`). */
function shellMac(salt, toolName, text, domain = 'shell') {
  return textMac(salt, 'shell', toolName, `marrow-normalized-action-v3\n${domain}\n${text}`);
}

/** The keyed hash of a tool input hashed whole (mcp, edit, other): the preimage is the sorted, redacted JSON. */
function inputMac(salt, kind, toolName, json) {
  return textMac(salt, kind, toolName, `marrow-normalized-action-v3\ninput\n${json}`);
}

/** The keyed hold target (hook-contract exactHookTarget). */
function targetMac(salt, parts) {
  return createHmac('sha256', textKey(salt)).update('marrow-hook-target-v2\n').update(JSON.stringify(parts)).digest('hex');
}

module.exports = { sha256, deviceSalt, textMac, shellMac, inputMac, targetMac };
