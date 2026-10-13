'use strict';

// In-memory SeatbeltFs for resolver tests. Intermediate symlinks are followed
// like the kernel does; the final one only where the real call would follow
// it. caseInsensitive=true emulates an APFS/HFS+ default volume on hosts that
// have none (the build server is Linux ext4).

function createFakeFs({ caseInsensitive = false, uid = 1000 } = {}) {
  const nodes = new Map();
  const failures = new Map();
  let nextIno = 1;
  const fold = (p) => (caseInsensitive ? p.normalize('NFC').toLowerCase() : p);
  const split = (p) => p.split('/').filter((part) => part && part !== '.');

  function walk(path, followFinal) {
    if (!path.startsWith('/')) throw Object.assign(new Error('relative'), { code: 'EINVAL' });
    let pending = split(path);
    let current = [];
    let hops = 0;
    while (pending.length) {
      const name = pending.shift();
      if (name === '..') { current.pop(); continue; }
      const candidate = `/${[...current, name].join('/')}`;
      const failure = failures.get(fold(candidate));
      if (failure) throw Object.assign(new Error(failure), { code: failure });
      const node = nodes.get(fold(candidate));
      if (!node) return null;
      const final = pending.length === 0;
      if (node.type === 'symlink' && (!final || followFinal)) {
        hops += 1;
        if (hops > 40) throw Object.assign(new Error('ELOOP'), { code: 'ELOOP' });
        if (node.target.startsWith('/')) current = [];
        pending = [...split(node.target), ...pending];
        continue;
      }
      if (!final && node.type !== 'dir') return null;
      current.push(node.name);
    }
    const real = `/${current.join('/')}`;
    return { real, node: nodes.get(fold(real)) || (real === '/' ? root : null) };
  }

  const root = { type: 'dir', name: '', uid: 0, mode: 0o755, ino: nextIno++, size: 0 };
  nodes.set('/', root);

  function put(path, node) {
    const parts = split(path);
    let prefix = '';
    for (const part of parts.slice(0, -1)) {
      prefix += `/${part}`;
      if (!nodes.has(fold(prefix))) nodes.set(fold(prefix), { type: 'dir', name: part, uid, mode: 0o755, ino: nextIno++, size: 0 });
    }
    nodes.set(fold(path), { name: parts[parts.length - 1], uid, ino: nextIno++, size: 0, ...node });
    return api;
  }

  const api = {
    mkdir: (path, opts = {}) => put(path, { type: 'dir', mode: 0o755, ...opts }),
    file: (path, text = '', opts = {}) => put(path, { type: 'file', content: text, size: Buffer.byteLength(text), mode: 0o644, ...opts }),
    symlink: (path, target) => put(path, { type: 'symlink', target, mode: 0o777 }),
    fifo: (path) => put(path, { type: 'other', mode: 0o644 }),
    remove(path) { nodes.delete(fold(path)); return api; },
    fail(path, code = 'EACCES') { failures.set(fold(path), code); return api; },
    lstat(path) {
      const found = walk(path, false);
      if (!found) return null;
      const node = found.node || nodes.get(fold(path));
      if (!node) return null;
      return { type: node.type, size: node.size || 0, uid: node.uid, ...(node.gid === undefined ? {} : { gid: node.gid }), mode: node.mode, dev: 1, ino: node.ino };
    },
    readlink(path) {
      const found = walk(path, false);
      if (!found || !found.node || found.node.type !== 'symlink') throw Object.assign(new Error('EINVAL'), { code: 'EINVAL' });
      return found.node.target;
    },
    readFile(path, maxBytes) {
      const found = walk(path, false);
      if (!found || !found.node) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      if (found.node.type === 'symlink') throw Object.assign(new Error('ELOOP'), { code: 'ELOOP' });
      if (found.node.type !== 'file' || found.node.size > maxBytes) return null;
      return found.node.content;
    },
    readdir(path) {
      const found = walk(path, true);
      if (!found || !found.node) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      if (found.node.type !== 'dir') throw Object.assign(new Error('ENOTDIR'), { code: 'ENOTDIR' });
      const prefix = fold(found.real === '/' ? '/' : `${found.real}/`);
      const out = [];
      for (const [key, node] of nodes) {
        if (key !== '/' && key.startsWith(prefix) && !key.slice(prefix.length).includes('/')) out.push(node.name);
      }
      return out;
    },
    caseInsensitive: () => caseInsensitive,
  };
  return api;
}

module.exports = { createFakeFs };
