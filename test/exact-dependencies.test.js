// PKG-L8: npm packages do not ship the lockfile, so a range in `dependencies` makes every
// `npx @getmarrow/mcp` install resolve whatever SDK is newest at install time, not the reviewed one.
// Runtime dependencies are exact versions, and the lockfile agrees with package.json.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

// An exact release: three plain numbers, nothing else (no range operator, tag, prerelease, URL or path).
const EXACT = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const RUNTIME_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies'];

function inexact(deps) {
  return Object.entries(deps || {}).filter(([, spec]) => typeof spec !== 'string' || !EXACT.test(spec)).map(([name, spec]) => `${name}@${spec}`);
}

test('the exactness check rejects every range form and accepts only X.Y.Z', () => {
  for (const spec of ['^3.7.65', '~3.7.65', '>3.7.65', '>=3.7.65', '<4', '<=3.7.65', '*', 'x', '3.x', '3.7.x', '3.7', '3', '3.7.65 || 3.7.66', '3.7.65 - 3.7.70', 'latest', 'next', '', 'file:../sdk', 'git+https://example.test/sdk.git', 'https://example.test/sdk.tgz', 'npm:other@3.7.65', '3.7.65-rc.1', '3.7.65+build', ' 3.7.65', '3.7.65 ', 'v3.7.65', '03.7.65', null, undefined, 3.7]) {
    assert.deepEqual(inexact({ '@getmarrow/sdk': spec }).length, 1, `${JSON.stringify(spec)} must be refused`);
  }
  assert.deepEqual(inexact({ '@getmarrow/sdk': '3.7.65', other: '0.0.1', big: '10.20.30' }), []);
});

test('every runtime dependency of @getmarrow/mcp is an exact version', () => {
  for (const field of RUNTIME_FIELDS) {
    const value = manifest[field];
    if (Array.isArray(value)) continue; // bundleDependencies lists names only
    assert.deepEqual(inexact(value), [], `${field} must hold exact versions only`);
  }
  assert.equal(manifest.dependencies['@getmarrow/sdk'], '3.7.65');
});

test('the lockfile root records the same exact dependencies, and each is installed at that version with an integrity', () => {
  const rootEntry = lock.packages[''];
  assert.deepEqual(rootEntry.dependencies, manifest.dependencies);
  for (const [name, version] of Object.entries(manifest.dependencies)) {
    const entry = lock.packages[`node_modules/${name}`];
    assert.ok(entry, `${name} is locked`);
    assert.equal(entry.version, version);
    assert.match(entry.integrity, /^sha512-/);
  }
});
