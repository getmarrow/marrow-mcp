const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

// `npx @getmarrow/mcp ...` must always resolve an executable. Every published
// install command depends on it, and a second `bin` entry without one named
// after the package broke all of them from 3.9.57 until `mcp` was added.
// The script does a static bin check, then packs the package and runs both npx
// forms from a clean cache with a throwaway HOME. Set
// MARROW_NPX_CHECK_STATIC_ONLY=1 to skip the npx run when offline.
test('npx resolves the marrow-mcp executable from a packed tarball', () => {
  const script = path.resolve(__dirname, '..', 'scripts', 'npx-executable-check.cjs')
  const result = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 480000 })
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`)
  assert.match(result.stdout, /NPX_EXECUTABLE_CHECK=PASS/)
})
