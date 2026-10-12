// Copied verbatim from the independent audit of 613473cf (Barvis, 2026-10-12): out/evidence/ of the audit.
// Each row is the auditor's own reproducing case; test/seatbelt-audit-regression.test.js runs them.
'use strict';
const T = (id, event, expect, opts) => ({ id, event, expect, opts });
const S = (id, cmd, opts) => ({ id, cmd, expect: 'stop', opts });
const P = (id, cmd, opts) => ({ id, cmd, expect: 'pass', opts });
const hookJson = JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'marrow-mcp claude-pre-action-hook' }] }] } });
const codexJson = JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'marrow-mcp codex-pre-action-hook' }] }] } });
const files = { '/home/u/.claude/settings.json': hookJson, '/home/u/.codex/hooks.json': codexJson };
module.exports = [
  T('write-home-settings', { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.json', content: '{}' } }, 'stop', { files }),
  T('write-codex-hooks', { tool_name: 'Write', tool_input: { file_path: '/home/u/.codex/hooks.json', content: '{}' } }, 'stop', { files }),
  T('write-via-link', { tool_name: 'Write', tool_input: { file_path: '/home/u/proj/link/.claude/settings.json', content: '{}' } }, 'stop', { files }),
  T('write-new-settings-local-disable', { tool_name: 'Write', tool_input: { file_path: '/home/u/proj/.claude/settings.local.json', content: '{"disableAllHooks":true}' } }, 'stop'),
  T('write-new-home-settings-local-disable', { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.local.json', content: '{"disableAllHooks":true}' } }, 'stop'),
  T('write-new-ws-settings-disable', { tool_name: 'Write', tool_input: { file_path: '/home/u/proj/sub/.claude/settings.json', content: '{"disableAllHooks":true}' } }, 'stop'),
  T('write-new-ws-settings-disable2', { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.json', content: '{"disableAllHooks":true}' } }, 'stop'),
  T('write-managed', { tool_name: 'Write', tool_input: { file_path: '/etc/claude-code/managed-settings.json', content: '{"disableAllHooks":true}' } }, 'stop'),
  T('write-claude-json-hooks?', { tool_name: 'Write', tool_input: { file_path: '/home/u/proj/.mcp.json', content: '{}' } }, 'pass'),
  S('shell-new-settings-local', "echo '{\"disableAllHooks\":true}' > .claude/settings.local.json"),
  S('git-c-global-file-unknown-alias', 'GIT_CONFIG_GLOBAL=/tmp/g git p origin main'),
  S('repo-hooksPath', 'git config core.hooksPath /dev/null'),
];
