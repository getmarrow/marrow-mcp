'use strict';

// Redaction for anything the daemon sends to the server or writes to its queue or status. It
// removes secret-shaped values from argv and free text before they leave the process. Keys are
// never logged; this is a second line of defence for tool input the agent supplied.
//
// Input is truncated BEFORE any pattern runs and every quantifier is bounded, so redaction is
// linear in a small constant no matter how large the tool input is (a 48 KB path once took 10 s).

const SECRET_PATTERNS = [
  /\bmrw_(?:live|test)_[A-Za-z0-9]{4,}/g,
  /\bmrw_[A-Za-z0-9_]{8,}/g,
  /\bmarrow_[A-Za-z0-9_]{8,}/g,
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{8,}/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{12,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{8,}/g,
  /\bAKIA[0-9A-Z]{12,}/g,
  /\bAIza[0-9A-Za-z_-]{20,}/g,
  /\bnpm_[A-Za-z0-9]{20,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
  /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)/g,
  /\b(?:bearer|token|basic)\s{1,4}[A-Za-z0-9._~+/=-]{12,}/gi,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
];
const ASSIGNMENT_PATTERN = /\b([A-Za-z0-9_.-]{0,32}(?:key|token|secret|password|passwd|pwd|auth|credential|cookie|session)[A-Za-z0-9_.-]{0,32})\s{0,4}([=:])\s{0,4}("[^"]{0,512}"|'[^']{0,512}'|[^\s&"']{1,512})/gi;
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]{0,20}:\/\/)[^\s/@:]{1,256}:[^\s/@]{1,256}@/gi;

function redactText(value, maxLength = 200) {
  const raw = String(value == null ? '' : value);
  // Keep a little more than we return so a secret cut at the boundary is still recognised.
  let text = raw.length > maxLength * 2 + 64 ? raw.slice(0, maxLength * 2 + 64) : raw;
  text = text.replace(URL_CREDENTIALS, '$1[redacted]@');
  text = text.replace(ASSIGNMENT_PATTERN, (_, name, sep) => `${name}${sep}[redacted]`);
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, '[redacted]');
  text = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ');
  return text.length > maxLength || raw.length > text.length + 64 ? `${text.slice(0, maxLength)}…` : text;
}

// A short label token (reason code, program name, host): redacted and restricted to a safe
// alphabet so tool input can never smuggle a secret through a reason string.
function safeToken(value, maxLength = 64) {
  return redactText(value, maxLength).replace(/[^A-Za-z0-9._:/@+\-[\]]/g, '_');
}

function redactArgv(argv, { maxArgs = 32, maxLength = 160 } = {}) {
  const out = [];
  let hideNext = false;
  for (const raw of (argv || []).slice(0, maxArgs)) {
    const arg = String(raw);
    if (hideNext) { out.push('[redacted]'); hideNext = false; continue; }
    if (/^(?:-H|--header|-u|--user|--password|--token|--otp|--api-key|--key|--secret|-p)$/i.test(arg)) { out.push(arg); hideNext = true; continue; }
    out.push(redactText(arg, maxLength));
  }
  if ((argv || []).length > maxArgs) out.push(`[+${argv.length - maxArgs} args]`);
  return out;
}

module.exports = { redactText, redactArgv, safeToken };
