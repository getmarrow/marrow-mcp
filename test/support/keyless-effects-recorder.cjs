'use strict';
// Preload for the keyless-start tests: every file write, child process and network attempt is
// written to stderr as one `EFFECT <kind> <api>` line and refused. Paths and values are never
// recorded, only the API name, so nothing secret can reach the log.
const fs = require('node:fs');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const childProcess = require('node:child_process');

const writeSync = fs.writeSync;
function effect(kind, api) {
  try { writeSync(2, `EFFECT ${kind} ${api}\n`); } catch { /* best effort */ }
}
function refuse(kind, api) {
  return function refused() {
    effect(kind, api);
    throw new Error(`keyless-effects-recorder refused ${api}`);
  };
}

const WRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND;
const writes = (flags) => (typeof flags === 'number' ? (flags & WRITE_FLAGS) !== 0 : flags !== undefined && flags !== null && !/^rs?$/.test(String(flags)));
for (const name of ['open', 'openSync']) {
  const original = fs[name];
  fs[name] = function patched(file, flags, ...rest) {
    if (writes(flags)) return refuse('fs', name)();
    return original.call(this, file, flags, ...rest);
  };
}
const FS_WRITES = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync',
  'rename', 'renameSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync',
  'symlink', 'symlinkSync', 'link', 'linkSync', 'chmod', 'chmodSync', 'chown', 'chownSync', 'truncate', 'truncateSync',
  'utimes', 'utimesSync', 'createWriteStream'];
for (const name of FS_WRITES) if (typeof fs[name] === 'function') fs[name] = refuse('fs', name);
for (const name of ['writeFile', 'appendFile', 'mkdir', 'mkdtemp', 'rename', 'unlink', 'rm', 'rmdir', 'copyFile', 'cp', 'symlink', 'link', 'chmod', 'chown', 'truncate', 'utimes']) {
  if (typeof fs.promises[name] === 'function') fs.promises[name] = refuse('fs', `promises.${name}`);
}
const openPromise = fs.promises.open;
fs.promises.open = function patched(file, flags, ...rest) {
  if (writes(flags)) return refuse('fs', 'promises.open')();
  return openPromise.call(this, file, flags, ...rest);
};
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[name] = refuse('child', name);
globalThis.fetch = refuse('net', 'fetch');
net.Socket.prototype.connect = refuse('net', 'connect');
for (const [label, mod] of [['http', http], ['https', https]]) {
  mod.request = refuse('net', `${label}.request`);
  mod.get = refuse('net', `${label}.get`);
}
dns.lookup = refuse('net', 'dns.lookup');
