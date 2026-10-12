'use strict';
const S = 'stop', P = 'pass';
const b64 = (s) => Buffer.from(s).toString('base64');
module.exports = [
  { id: 'S4:less', cmd: 'less ~/.aws/credentials', expect: S },
  { id: 'S4:jq-docker', cmd: 'jq . ~/.docker/config.json', expect: S },
  { id: 'S4:group-cat', cmd: '{ cat; } < ~/.ssh/id_ed25519', expect: S },
  { id: 'S4:subsh-redirect', cmd: '(cat) < ~/.aws/credentials', expect: S },
  { id: 'S4:while-read-group', cmd: '{ while read l; do echo "$l"; done; } < ~/.aws/credentials', expect: S },
  { id: 'S4:mv-link-read', cmd: 'mv awslink z && cat z/credentials', expect: S },
  { id: 'S4:mcp-stdin', event: { tool_name: 'mcp__c__run_command', tool_input: { command: 'bash', stdin: 'cat ~/.aws/credentials' } }, expect: S },
  { id: 'S4:pass-pub', cmd: 'cat ~/.ssh/id_ed25519.pub', expect: P },
  { id: 'Sx:group-b64', cmd: `echo ${b64('npm publish')} | base64 -d | { bash; }`, expect: S },
  { id: 'Sx:subsh-b64', cmd: `echo ${b64('npm publish')} | base64 -d | (sh)`, expect: S },
  { id: 'Sx:herestr-group-decoded', cmd: `{ bash; } <<< "$(echo ${b64('npm publish')} | base64 -d)"`, expect: S },
  { id: 'Sx:rev', cmd: "echo 'hsilbup mpn' | rev | sh", expect: S },
  { id: 'Sx:pass-decode-only', cmd: `echo ${b64('hello')} | base64 -d`, expect: P },
];
