#!/usr/bin/env node

const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const server = JSON.parse(fs.readFileSync(path.join(root, 'server.json'), 'utf8'))
const endpoint = new URL('https://registry.modelcontextprotocol.io/v0.1/servers')
endpoint.searchParams.set('search', server.name)

function identity(entry) {
  const candidate = entry && typeof entry === 'object' && entry.server && typeof entry.server === 'object'
    ? entry.server
    : entry
  return {
    name: candidate && typeof candidate.name === 'string' ? candidate.name : '',
    version: candidate && typeof candidate.version === 'string' ? candidate.version : '',
  }
}

async function main() {
  const response = await fetch(endpoint, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000) })
  if (!response.ok) throw new Error(`MCP Registry query failed with HTTP ${response.status}`)
  const body = await response.json()
  const entries = Array.isArray(body?.servers) ? body.servers : []
  const match = entries.map(identity).find((entry) => entry.name === server.name && entry.version === server.version)
  if (!match) {
    throw new Error(`MCP Registry is missing ${server.name}@${server.version}`)
  }
  console.log(`MCP_REGISTRY_VERIFY=PASS name=${match.name} version=${match.version}`)
}

main().catch((error) => {
  console.error(`MCP_REGISTRY_VERIFY=FAIL reason=${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
