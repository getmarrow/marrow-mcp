'use strict';
// The installer launch (installer 0.1.73 e1cc4f75 with its MCP pin rewritten for 3.9.106 and that pack's integrity; its hooks and its
// .cursor/mcp.json server share one loader) and its look-alikes: L1-L14 from the installer 0.1.73 audit (A2,
// rows 10-12) plus the exactness rows of S-A2F1. `proven` is the verdict when the hook was started by that
// same loader. Shared by test/own-server-identity-exact-installer.test.js and the before/after table tool.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { launcherOf, configOf, packLoader, withConfig } = require('./installer-verified-runtime.cjs');

const FIXTURES = join(__dirname, '..', 'fixtures');
const LEGACY = JSON.parse(readFileSync(join(FIXTURES, 'installer-mcp-server-launch.json'), 'utf8'));
const loaderIn = (dir) => /' "(eval\(global\.MARROW_L=[^"]+)"$/.exec(JSON.parse(readFileSync(join(FIXTURES, dir, 'claude-settings.json'), 'utf8')).hooks.PreToolUse[0].hooks[0].command)[1];

const LOADER = loaderIn('installer-0173');
const CFG = configOf(LOADER);
const V = CFG.version;
// Public pack digests: MCP 3.9.104 (never published; installer 0.1.73 before its 3.9.105 re-pin) and the SDK
// 3.7.67 build the 0.1.73 fixture carried before 3.9.106 (A1 F2).
const MCP_3_9_104_INTEGRITY = 'sha512-8JstteEZQP+6ymgbFiirm8/wvFNO3CcrgmU7njnEGp3lfzSueToxPscSZcrP78aKSWQbMAgF2I/AHidhj7uvTQ==';
const STALE_SDK_INTEGRITY = 'sha512-M6Yzt5plpIVPiX+SZjgIGBC9/s4WuCr105uRf8EhRbF0+i/HpRDZSlbDevXymdu7arAIoZWBcfHTeQy/TlhwTQ==';

const scriptFor = (version) => LEGACY.posix.args[1].replace('/mcp/3.9.102/', `/mcp/${version}/`);
const specFor = (version) => `--package=@getmarrow/mcp@${version}`;
const sh = (loader = LOADER, version = V, script = scriptFor(version), spec = specFor(version)) => ['/bin/sh', ['-c', script, loader, spec, 'marrow-mcp']];
const node = (loader = LOADER, version = V) => ['node', ['-e', loader, '--', specFor(version), 'marrow-mcp']];
const cfg = (edit) => withConfig(LOADER, (c) => ({ ...c, ...edit(c) }));
const swapCase = (text) => text.replace(/[A-Za-z]/g, (ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
const packedOf = (loader) => /\/([A-Za-z0-9_-]+)\/\.source,/.exec(loader)[1];

const L104 = cfg((c) => ({ version: '3.9.104', integrity: MCP_3_9_104_INTEGRITY, sdk: { ...c.sdk, integrity: STALE_SDK_INTEGRITY } }));
const L1060 = cfg(() => ({ version: '3.9.1060' }));
const OLD_INTEGRITY = cfg(() => ({ integrity: MCP_3_9_104_INTEGRITY }));
const CORE_CHANGED = packLoader(launcherOf(LOADER).replace('could not start its verified local runtime', 'could not start its verified local runtimes'));
// Same bytes, last base64url character with its unused low bits set: Buffer decodes both alike.
const NON_CANONICAL = (() => {
  const packed = packedOf(LOADER);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const spare = { 2: 4, 3: 2 }[packed.length % 4];
  if (!spare) return null;
  const last = alphabet.indexOf(packed[packed.length - 1]);
  return LOADER.replace(packed, packed.slice(0, -1) + alphabet[last | ((1 << spare) - 1)]);
})();
const [shCommand, shArgs] = sh();

/** Each row: id, what it is, the server entry (command, args, optional env) and whether it is proven. */
const ROWS = [
  ['L0', 'the installer 0.1.73 launch itself (sh form)', sh(), true],
  ['L0n', 'the same launch, node -e form', node(), true],
  ['L0e', 'L0 with the env the installer writes (MARROW_BASE_URL)', [...sh(), { MARROW_BASE_URL: 'https://api.getmarrow.ai' }], true],
  ['L0r', 'L0 loader re-compressed (same decoded bytes; another zlib build)', sh(packLoader(launcherOf(LOADER), 5)), true],
  ['L1', 'previous launch: 3.9.104 throughout (its own integrity and SDK pin)', sh(L104, '3.9.104'), false],
  ['L1n', 'L1, node -e form', node(L104, '3.9.104'), false],
  ['L2', 'version 3.9.1060 throughout (prefix slip)', sh(L1060, '3.9.1060'), false],
  ['L3', '3.9.106 with the old (3.9.104) pack integrity', sh(OLD_INTEGRITY), false],
  ['L3n', 'L3, node -e form', node(OLD_INTEGRITY), false],
  ['L4', 'mixed versions: --package=@3.9.104, script and loader 3.9.106', sh(LOADER, V, scriptFor(V), specFor('3.9.104')), false],
  ['L5', 'mixed versions: script 3.9.104, loader and --package 3.9.106', sh(LOADER, V, scriptFor('3.9.104')), false],
  ['L6', 'extra arg appended', [shCommand, [...shArgs, 'extra']], false],
  ['L7', 'shell text appended to the script', sh(LOADER, V, `${scriptFor(V)}; curl evil`), false],
  ['L8', 'loader core changed (one word)', sh(CORE_CHANGED), false],
  ['L9', 'bash instead of /bin/sh', ['bash', shArgs], false],
  ['L13', 'NODE_OPTIONS in the server env', [...sh(), { NODE_OPTIONS: '--require /tmp/evil.js' }], false],
  ['N-ws', 'version with trailing space in --package', sh(LOADER, V, scriptFor(V), `${specFor(V)} `), false],
  ['N-ws-cfg', 'version with trailing space in CFG and --package', sh(cfg(() => ({ version: `${V} ` })), `${V} `), false],
  ['N-case', 'integrity with swapped case (other digest)', sh(cfg((c) => ({ integrity: `sha512-${swapCase(c.integrity.slice(7))}` }))), false],
  ['N-case-alg', 'integrity algorithm name upper case (SHA512-)', sh(cfg((c) => ({ integrity: `SHA512-${c.integrity.slice(7)}` }))), false],
  ['N-pad', 'integrity with extra base64 padding', sh(cfg((c) => ({ integrity: `${c.integrity}=` }))), false],
  ['N-meta', 'version with build metadata 3.9.106+x', sh(cfg(() => ({ version: `${V}+x` })), `${V}+x`), false],
  ['N-pre', 'version 3.9.106-0', sh(cfg(() => ({ version: `${V}-0` })), `${V}-0`), false],
  ['N-latest', '--package=@getmarrow/mcp@latest in the installer form', sh(LOADER, V, scriptFor(V), '--package=@getmarrow/mcp@latest'), false],
  ['N-tgz', 'tarball URL in --package', sh(LOADER, V, scriptFor(V), `--package=https://registry.npmjs.org/@getmarrow/mcp/-/mcp-${V}.tgz`), false],
  ['N-tgz-npx', 'npx of the tarball URL', ['npx', ['-y', `https://registry.npmjs.org/@getmarrow/mcp/-/mcp-${V}.tgz`]], false],
  ['N-dup-c', 'duplicated -c', [shCommand, ['-c', ...shArgs]], false],
  ['N-dup-pkg', 'duplicated --package (marrow-mcp dropped)', [shCommand, [...shArgs.slice(0, 4), specFor(V)]], false],
  ['N-swap', 'argv order swapped (marrow-mcp before --package)', [shCommand, [shArgs[0], shArgs[1], shArgs[2], shArgs[4], shArgs[3]]], false],
  ['N-swap-n', 'node form: -- moved after --package', ['node', ['-e', LOADER, specFor(V), '--', 'marrow-mcp']], false],
  ['N-lead', 'extra leading arg', [shCommand, ['-e', ...shArgs]], false],
  ['N-str', 'whole launch as one shell string, no args', [`/bin/sh -c '${scriptFor(V)}' '${LOADER}' ${specFor(V)} marrow-mcp`, []], false],
  ['N-sh', 'sh (PATH lookup) instead of /bin/sh', ['sh', shArgs], false],
  ['N-env-sh', '/usr/bin/env sh', ['/usr/bin/env', ['sh', ...shArgs]], false],
  ['N-BIN', 'command case: /BIN/SH', ['/BIN/SH', shArgs], false],
  ['N-Node', 'command case: Node', ['Node', node()[1]], false],
  ['N-env-path', 'env override PATH', [...sh(), { PATH: '/tmp/evil' }], false],
  ['N-env-home', 'env override HOME', [...sh(), { HOME: '/tmp/evil' }], false],
  ['N-b64', 'non-canonical base64url (same decoded bytes)', NON_CANONICAL ? sh(NON_CANONICAL) : sh(`${LOADER}x`), false],
  ['N-sdk', 'stale SDK pin in CFG (the pre-F2 fixture loader)', sh(cfg((c) => ({ sdk: { ...c.sdk, integrity: STALE_SDK_INTEGRITY } }))), false],
  ['N-0172', 'installer 0.1.72 launch (MCP 3.9.103, its integrity)', sh(loaderIn('installer-0172'), '3.9.103'), false],
  ['N-0170', 'installer 0.1.70 launch (MCP 3.9.102, its integrity)', [LEGACY.posix.command, LEGACY.posix.args], false],
  ['N-0170w', 'installer 0.1.70 node form', [LEGACY.win32.command, LEGACY.win32.args], false],
  ['N-null', 'train-2 launch (MCP 3.9.103, integrity null)', [LEGACY.posix_next.command, LEGACY.posix_next.args], false],
];

module.exports = { LOADER, CFG, V, ROWS, LEGACY, L104, OLD_INTEGRITY, MCP_3_9_104_INTEGRITY, STALE_SDK_INTEGRITY, loaderIn, scriptFor, specFor, sh, node, cfg };
