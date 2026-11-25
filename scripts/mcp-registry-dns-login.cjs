#!/usr/bin/env node
'use strict';

// MCP Registry DNS login for .github/workflows/publish-mcp-registry.yml. The pinned mcp-publisher (v1.7.9)
// takes the signing key only as a --private-key argument, which puts it in the process list. This helper does
// the same DNS login (auth/common.go GetToken and exchangeTokenForRegistry, login.go token file) with the key
// read from the environment only. It is not published (not in package.json files).
// Usage: MCP_PRIVATE_KEY=<64 hex Ed25519 seed> node scripts/mcp-registry-dns-login.cjs --domain <name> [--registry <url>]
// Exit 0: token file written. Exit 1: the registry did not issue a token. Exit 2: refused before any request.
// Output: one line, MCP_REGISTRY_LOGIN=OK|FAIL; never the key, the signature, the token or a response body.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');

const DEFAULT_REGISTRY = 'https://registry.modelcontextprotocol.io';
const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const URL_CHARS = /^https?:\/\/[a-z0-9.:[\]-]+$/;
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const MAX_BODY = 64 * 1024;
const limits = { timeoutMs: 30000 }; // tests lower this through the export only

function fail(code, detail) {
  process.stdout.write(`MCP_REGISTRY_LOGIN=FAIL ${detail}\n`);
  process.exitCode = code;
}

function parseArgs(argv) {
  const seen = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i] === '--domain' ? 'domain' : argv[i] === '--registry' ? 'registry' : null;
    if (!name || name in seen || i + 1 >= argv.length) return { bad: i + 1 };
    seen[name] = argv[i + 1];
  }
  return seen;
}

function registryOk(value) {
  if (typeof value !== 'string' || value.length > 2048 || !URL_CHARS.test(value)) return false;
  let u;
  try { u = new URL(value); } catch { return false; }
  if (u.origin !== value || u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === '[::1]') && u.port !== '';
}

function homeOk(home) {
  try { return typeof home === 'string' && path.isAbsolute(home) && fs.statSync(home).isDirectory(); } catch { return false; }
}

// POST <registry>/v0/auth/dns once: no redirects, TLS verified, bounded time and body.
function exchange(registry, payload) {
  return new Promise((resolve) => {
    const lib = registry.startsWith('https:') ? https : http;
    const body = JSON.stringify(payload);
    let done = false;
    const finish = (result) => { if (!done) { done = true; clearTimeout(timer); req.destroy(); resolve(result); } };
    const req = lib.request(`${registry}/v0/auth/dns`, {
      method: 'POST',
      rejectUnauthorized: true,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      if (res.statusCode !== 200) return finish({ status: String(res.statusCode) });
      const chunks = [];
      let size = 0;
      res.on('data', (c) => { size += c.length; if (size > MAX_BODY) finish({ status: 'response_too_large' }); else chunks.push(c); });
      res.on('error', () => finish({ status: 'network_error' }));
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* malformed below */ }
        const token = parsed && typeof parsed === 'object' ? parsed.registry_token : undefined;
        finish(typeof token === 'string' && token.length > 0 ? { token } : { status: 'malformed_response' });
      });
    });
    const timer = setTimeout(() => finish({ status: 'timeout' }), limits.timeoutMs);
    req.on('error', (err) => finish({ status: /^E[A-Z0-9_]{1,40}$/.test(String(err && err.code)) ? err.code : 'network_error' }));
    req.end(body);
  });
}

// login.go: ~/.config/mcp-publisher/token.json {token, method, registry}; directory 0700, file 0600.
// A fresh 0600 file is renamed over the old one, so an old file or a link there is replaced, never written through.
function writeToken(home, token, registry) {
  const dir = path.join(home, '.config', 'mcp-publisher');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const tmp = path.join(dir, `.token.json.${process.pid}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify({ token, method: 'dns', registry }), { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, path.join(dir, 'token.json'));
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.bad) return fail(2, `bad_argument position=${args.bad}`);
  const domain = args.domain;
  const registry = 'registry' in args ? args.registry : DEFAULT_REGISTRY;
  if (typeof domain !== 'string' || domain.length > 253 || !DOMAIN.test(domain)) return fail(2, 'bad_domain');
  if (!registryOk(registry)) return fail(2, 'bad_registry_url');
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') return fail(2, 'tls_verification_disabled');
  const home = process.env.HOME;
  if (!homeOk(home)) return fail(2, 'home_not_absolute_directory');
  const tokenPath = path.join(home, '.config', 'mcp-publisher', 'token.json');
  try { fs.rmSync(tokenPath, { force: true }); } catch { return fail(2, 'stale_token_file'); }

  const raw = process.env.MCP_PRIVATE_KEY;
  delete process.env.MCP_PRIVATE_KEY;
  const hex = typeof raw === 'string' ? raw.trim() : '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return fail(2, `key_missing_or_malformed length=${typeof raw === 'string' ? raw.length : 0}`);

  // auth/common.go: Ed25519 over the UTC RFC 3339 timestamp (seconds), hex-encoded.
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  let signature;
  try {
    const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
    signature = crypto.sign(null, Buffer.from(timestamp, 'utf8'), key).toString('hex');
  } catch {
    return fail(2, 'key_unusable');
  }
  const result = await exchange(registry, { domain, timestamp, signed_timestamp: signature });
  if (!result.token) return fail(1, `status=${result.status}`);
  try { writeToken(home, result.token, registry); } catch { return fail(1, 'status=token_write_failed'); }
  process.stdout.write(`MCP_REGISTRY_LOGIN=OK method=dns domain=${domain}\n`);
  process.exitCode = 0;
}

module.exports = { main, limits };
if (require.main === module) {
  main(process.argv.slice(2)).catch(() => fail(1, 'status=internal_error'));
}
