'use strict';
// Writes the official Marrow MCP server entry (the README / `codex mcp add marrow -- npx -y
// @getmarrow/mcp` form) into a test HOME's Codex and Cursor configs, so the own-tool skip can
// prove the server on those hosts (src/own-server-identity.ts). No key, no network.
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

function writeOfficialHostConfigs(home = process.env.HOME) {
  mkdirSync(join(home, '.codex'), { recursive: true });
  writeFileSync(join(home, '.codex', 'config.toml'), '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n');
  mkdirSync(join(home, '.cursor'), { recursive: true });
  writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { marrow: { command: 'npx', args: ['-y', '--package=@getmarrow/mcp@latest', 'marrow-mcp'] } } }));
}

module.exports = { writeOfficialHostConfigs };
