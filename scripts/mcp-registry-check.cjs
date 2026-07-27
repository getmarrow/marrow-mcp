#!/usr/bin/env node

const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
const server = JSON.parse(fs.readFileSync(path.join(root, 'server.json'), 'utf8'))
const publishedPackage = server.packages?.find((entry) => entry.registryType === 'npm')

const failures = []
if (packageJson.mcpName !== server.name) failures.push('package mcpName must match server name')
if (packageJson.version !== server.version) failures.push('package and server versions must match')
if (publishedPackage?.identifier !== packageJson.name) failures.push('npm package identifier must match package name')
if (publishedPackage?.version !== packageJson.version) failures.push('npm package version must match package version')
if (!server.repository?.url?.startsWith('https://github.com/getmarrow/')) failures.push('repository must use the canonical public Marrow GitHub URL')

if (failures.length > 0) {
  console.error(`MCP_REGISTRY_CHECK=FAIL reason=${failures.join('; ')}`)
  process.exitCode = 1
} else {
  console.log(`MCP_REGISTRY_CHECK=PASS name=${server.name} version=${server.version}`)
}
