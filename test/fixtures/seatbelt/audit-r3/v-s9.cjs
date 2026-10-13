'use strict';
const S = 'stop', P = 'pass';
const HOOKED = JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'marrow-mcp claude-pre-action-hook' }] }] } });
module.exports = [
  { id: '9a:rm-dashdash', cmd: 'rm -f -- -r /srv', expect: P },
  { id: '9a:rm-permute', cmd: 'rm -f /srv -r', expect: S },
  { id: '9a:rm-permute2', cmd: 'rm /srv -rf', expect: S },
  { id: '9a:rm-dashdash-after', cmd: 'rm -f /srv -- -r', expect: P },
  { id: '9a:rm-R-long', cmd: 'rm --recursive -- /srv', expect: S },
  { id: '9b:pnpm-deploy', cmd: 'pnpm deploy --filter app out', expect: P },
  { id: '9b:pnpm-run-deploy', cmd: 'pnpm run deploy', opts: { files: { '/home/u/proj/package.json': JSON.stringify({ scripts: { deploy: 'vercel --prod' } }) } }, expect: S },
  { id: '9b:pnpm-deploy-noscript', cmd: 'pnpm deploy', opts: { files: { '/home/u/proj/package.json': JSON.stringify({ scripts: { deploy: 'vercel --prod' } }) } }, expect: P },
  { id: '9c:cargo-dry', cmd: 'cargo publish --dry-run --no-verify', expect: P },
  { id: '9c:cargo-n', cmd: 'cargo publish -n', expect: P },
  { id: '9c:cargo-plain', cmd: 'cargo publish --no-verify', expect: S },
  { id: '9d:plus-HEAD-feat', cmd: 'git push origin +HEAD', expect: P },
  { id: '9d:plus-HEAD-main', cmd: 'git push origin +HEAD', opts: { current: 'main' }, expect: S },
  { id: '9d:plus-HEAD-detached', cmd: 'git push origin +HEAD', opts: { current: null }, expect: S },
  { id: '9d:plus-at', cmd: 'git push origin +@', opts: { current: 'main' }, expect: S },
  { id: '9d:plus-HEAD-to-main', cmd: 'git push origin +HEAD:main', expect: S },
  { id: '9e:write-new-home-disable', event: { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.json', content: '{"disableAllHooks": true}' } }, expect: S },
  { id: '9e:write-new-local-disable', event: { tool_name: 'Write', tool_input: { file_path: '/home/u/proj/.claude/settings.local.json', content: '{"disableAllHooks": true}' } }, expect: S },
  { id: '9e:write-new-home-empty', event: { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.json', content: '{}' } }, expect: P },
  { id: '9e:write-existing-empty', event: { tool_name: 'Write', tool_input: { file_path: '/home/u/.claude/settings.json', content: '{}' } }, opts: { files: { '/home/u/.claude/settings.json': HOOKED } }, expect: S },
  { id: '9e:bash-new-disable', cmd: `echo '{"disableAllHooks":true}' > ~/.claude/settings.json`, expect: S },
  { id: '9e:write-codex-new-disable', event: { tool_name: 'Write', tool_input: { file_path: '/home/u/.codex/config.toml', content: '[features]\ncodex_hooks = false\n' } }, expect: undefined },
  { id: '9e:write-managed', event: { tool_name: 'Write', tool_input: { file_path: '/etc/claude-code/managed-settings.json', content: '{"disableAllHooks": true}' } }, expect: S },
];
