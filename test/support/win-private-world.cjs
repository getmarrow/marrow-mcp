'use strict';

// A small in-memory Windows for the win-private-state tests: a path table behind lstat/realpath/mkdir
// and a fake powershell.exe that prints the exact protocol the proof expects. Nothing here touches the
// disk, the host's environment or a real child process.
const SID = 'S-1-5-21-1-2-3-1001';
const NONCE = '0123456789abcdef0123456789abcdef';

function errno(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

const WELL_KNOWN = { SY: 'S-1-5-18', BA: 'S-1-5-32-544', BU: 'S-1-5-32-545', WD: 'S-1-1-0', AU: 'S-1-5-11', CO: 'S-1-3-0', CG: 'S-1-3-1', OW: 'S-1-3-4', AC: 'S-1-15-2-1' };

function sidBuffer(name) {
  const text = WELL_KNOWN[name] || name;
  const parts = text.split('-').slice(1).map(Number);
  const authority = parts[1];
  const subs = parts.slice(2);
  const buffer = Buffer.alloc(8 + 4 * subs.length);
  buffer[0] = parts[0];
  buffer[1] = subs.length;
  buffer.writeUIntBE(authority, 2, 6);
  subs.forEach((value, index) => buffer.writeUInt32LE(value, 8 + 4 * index));
  return buffer;
}

function aceBuffer({ type = 0, flags = 0, mask, sid, size }) {
  const sidBytes = sidBuffer(sid);
  const buffer = Buffer.alloc(8 + sidBytes.length);
  buffer[0] = type;
  buffer[1] = flags;
  buffer.writeUInt16LE(size === undefined ? buffer.length : size, 2);
  buffer.writeUInt32LE(mask >>> 0, 4);
  sidBytes.copy(buffer, 8);
  return buffer;
}

// A self-relative SECURITY_DESCRIPTOR laid out like Windows does: header, owner, group, DACL.
function sdBuffer({ owner = SID, group = SID, aces = [], control = 0x8000 | 0x0004 | 0x0400, nullDacl = false, noGroup = false, trailing = 0, aclSizeDelta = 0, aclCount } = {}) {
  const ownerBytes = sidBuffer(owner);
  const groupBytes = noGroup ? Buffer.alloc(0) : sidBuffer(group);
  const aceBytes = aces.map((ace) => aceBuffer(ace));
  const acl = Buffer.alloc(8 + aceBytes.reduce((sum, ace) => sum + ace.length, 0));
  acl[0] = 2;
  acl.writeUInt16LE(acl.length + aclSizeDelta, 2);
  acl.writeUInt16LE(aclCount === undefined ? aces.length : aclCount, 4);
  let at = 8;
  for (const ace of aceBytes) { ace.copy(acl, at); at += ace.length; }
  const header = Buffer.alloc(20);
  header[0] = 1;
  header.writeUInt16LE(control, 2);
  const ownerOffset = 20;
  const groupOffset = noGroup ? 0 : ownerOffset + ownerBytes.length;
  const daclOffset = nullDacl ? 0 : ownerOffset + ownerBytes.length + groupBytes.length;
  header.writeUInt32LE(ownerOffset, 4);
  header.writeUInt32LE(groupOffset, 8);
  header.writeUInt32LE(daclOffset, 16);
  return Buffer.concat([header, ownerBytes, groupBytes, nullDacl ? Buffer.alloc(0) : acl, Buffer.alloc(trailing)]);
}

const FULL = 0x1F01FF;
const INHERIT = 0x13;
function privateAces(me = SID) {
  return [{ sid: 'SY', mask: FULL, flags: INHERIT }, { sid: 'BA', mask: FULL, flags: INHERIT }, { sid: me, mask: FULL, flags: INHERIT }];
}
// base64 of a descriptor: the private one by default, plus extra ACEs
function sd(options = {}) {
  const { extra = [], me = SID, ...rest } = options;
  return sdBuffer({ aces: [...privateAces(me), ...extra], ...rest }).toString('base64');
}

function makeWorld(options = {}) {
  const home = options.home || 'C:\\Users\\buu';
  const root = options.root || 'C:\\Windows';
  const nodes = new Map();
  let inode = 100n;
  const key = (path) => path.toLowerCase();
  const add = (path, kind, extra = {}) => {
    inode += 1n;
    nodes.set(key(path), { kind, dev: 7n, ino: inode, nlink: 1n, ctimeNs: 1000n, birthtimeNs: 500n, canonical: path, ...extra });
  };
  const addDirs = (path) => {
    const parts = path.slice(3).split('\\');
    let current = path.slice(0, 2);
    for (const part of parts) {
      current = `${current}\\${part}`;
      if (!nodes.has(key(current))) add(current, 'dir');
    }
  };
  addDirs(home);
  addDirs(`${home}\\AppData\\Local\\Temp`);
  addDirs(`${root}\\System32\\WindowsPowerShell\\v1.0`);
  add(`${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, 'file');
  add(`${root}\\System32\\whoami.exe`, 'file');
  if (options.marrow !== false) addDirs(`${home}\\.marrow`);
  if (options.guard !== false && options.marrow !== false) addDirs(`${home}\\.marrow\\session-loop-guard`);
  if (options.state) add(`${home}\\.marrow\\session-loop-guard\\state.json`, 'file');

  const reads = new Set();
  const baseEnv = { SystemRoot: root, windir: root, HOME: '/c/Users/x', USERPROFILE: home, PATH: 'C:\\evil', PSModulePath: 'C:\\evil\\Modules', ...(options.env || {}) };
  const env = new Proxy(baseEnv, { get(target, name) { if (typeof name === 'string') reads.add(name); return target[name]; } });
  const world = {
    home, root, nodes, calls: { spawn: [], mkdir: [], realpath: [] }, reads, clock: 1_000_000, acl: options.acl || {}, sid: SID,
    spawnOverride: options.spawnOverride || null, mkdirError: options.mkdirError || null, lstatError: new Map(), canon: new Map(),
    add, addDirs, key,
    set(path, change) { Object.assign(nodes.get(key(path)), change); },
    // path (lower case) -> base64 descriptor for that canonical path
    setAcl(path, encoded) { world.acl[key(path)] = encoded; },
  };
  const stat = (node) => ({
    isDirectory: () => node.kind === 'dir', isFile: () => node.kind === 'file', isSymbolicLink: () => node.kind === 'link',
    dev: node.dev, ino: node.ino, nlink: node.nlink, ctimeNs: node.ctimeNs, birthtimeNs: node.birthtimeNs, size: 100n,
  });
  world.deps = {
    platform: options.platform || 'win32',
    env,
    lstatBig(path) {
      const failure = world.lstatError.get(key(path));
      if (failure) throw errno(failure);
      const node = nodes.get(key(path));
      if (!node) throw errno('ENOENT');
      return stat(node);
    },
    realpathNative(path) {
      world.calls.realpath.push(path);
      if (world.canon.has(key(path))) return world.canon.get(key(path));
      const node = nodes.get(key(path));
      if (!node) throw errno('ENOENT');
      return node.canonical;
    },
    spawnSync(file, args, spawnOptions) {
      world.calls.spawn.push({ file, args: [...args], options: { ...spawnOptions, env: { ...spawnOptions.env } } });
      if (world.spawnOverride) return world.spawnOverride({ file, args, options: spawnOptions, world });
      return { status: 0, signal: null, stdout: world.output(spawnOptions.env), stderr: '' };
    },
    randomHex: () => options.nonce || NONCE,
    now: () => world.clock,
    mkdir(path) {
      world.calls.mkdir.push(path);
      if (world.mkdirError) throw errno(world.mkdirError);
      add(path, 'dir');
    },
    cache: new Map(),
  };
  world.output = (spawnEnv, overrides = {}) => {
    const count = Number(spawnEnv.MARROW_WINACL_N);
    const lines = [`BEGIN ${overrides.nonce || spawnEnv.MARROW_WINACL_NONCE}`, `SID ${overrides.sid || SID}`];
    for (let index = 1; index <= count; index += 1) {
      const path = spawnEnv[`MARROW_WINACL_P${index}`];
      lines.push(`ACL ${index} ${world.acl[key(path)] || sd()}`);
    }
    lines.push(`END ${overrides.nonce || spawnEnv.MARROW_WINACL_NONCE}`);
    return `${(overrides.transform ? overrides.transform(lines) : lines).join(overrides.eol || '\r\n')}${overrides.eol === '' ? '' : '\r\n'}`;
  };
  return world;
}

module.exports = { makeWorld, sd, sdBuffer, aceBuffer, sidBuffer, errno, SID, NONCE, FULL, INHERIT };
