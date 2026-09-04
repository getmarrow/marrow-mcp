#!/usr/bin/env node

const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const server = JSON.parse(fs.readFileSync(path.join(root, 'server.json'), 'utf8'))
const endpoint = new URL(
  `https://registry.modelcontextprotocol.io/v0.1/servers/${encodeURIComponent(server.name)}/versions/${encodeURIComponent(server.version)}`,
)

function identity(entry) {
  const candidate = entry && typeof entry === 'object' && entry.server && typeof entry.server === 'object'
    ? entry.server
    : entry
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || typeof candidate.name !== 'string' || candidate.name.length === 0
    || typeof candidate.version !== 'string' || candidate.version.length === 0) return null
  return { name: candidate.name, version: candidate.version }
}

async function verifyRegistry(fetchImpl = globalThis.fetch) {
  let response
  try {
    response = await fetchImpl(endpoint, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000) })
  } catch {
    throw new Error('MCP Registry query is unavailable')
  }
  if (!response.ok) throw new Error(`MCP Registry query failed with HTTP ${response.status}`)
  let body
  try {
    body = await response.json()
  } catch {
    throw new Error('MCP Registry response is malformed')
  }
  const match = identity(body)
  if (!match) throw new Error('MCP Registry response is malformed')
  if (match.name !== server.name || match.version !== server.version) {
    throw new Error('MCP Registry identity mismatch')
  }
  return match
}

async function main() {
  const match = await verifyRegistry()
  console.log(`MCP_REGISTRY_VERIFY=PASS name=${match.name} version=${match.version}`)
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`MCP_REGISTRY_VERIFY=FAIL reason=${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })
}

module.exports = { endpoint, identity, verifyRegistry }
