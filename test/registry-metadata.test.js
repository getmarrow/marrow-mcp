const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

test('MCP registry metadata matches the npm package contract', () => {
  const root = path.resolve(__dirname, '..')
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
  const server = JSON.parse(fs.readFileSync(path.join(root, 'server.json'), 'utf8'))

  assert.equal(server.$schema, 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json')
  assert.equal(typeof server.description, 'string')
  assert.ok(server.description.length > 0)
  assert.ok(server.description.length <= 100, 'MCP Registry server descriptions are limited to 100 characters')
  assert.equal(pkg.mcpName, 'io.github.getmarrow/marrow')
  assert.equal(server.name, pkg.mcpName)
  assert.equal(server.version, pkg.version)
  assert.equal(server.packages.length, 1)
  assert.equal(server.packages[0].identifier, pkg.name)
  assert.equal(server.packages[0].version, pkg.version)
  assert.equal(server.packages[0].transport.type, 'stdio')
  assert.deepEqual(server.packages[0].environmentVariables, [
    {
      name: 'MARROW_API_KEY',
      description: 'Named Marrow agent API key. Keep it in trusted secret storage.',
      isRequired: true,
      isSecret: true,
    },
  ])
  assert.equal(pkg.files.includes('server.json'), true)
})
