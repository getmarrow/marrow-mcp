'use strict';
const S = 'stop', P = 'pass';
const pad = ' '.repeat(1100);
const cpad = '/*' + 'x'.repeat(1100) + '*/';
const hexOf = (s) => Buffer.from(s).toString('hex');
module.exports = [
  { id: 'E:fs-rm-short', cmd: `node -e "require('fs').rm('/home/u', {recursive: true, force: true}, () => {})"`, expect: S },
  { id: 'E:fs-rm-pad', cmd: `node -e "require('fs').rm('/home/u', {force: true,${pad}recursive: true}, () => {})"`, expect: S },
  { id: 'E:fs-promises-rm-comment', cmd: `node -e "require('fs').promises.rm('/home/u', {${cpad} recursive: true})"`, expect: S },
  { id: 'E:fs-rm-file', cmd: 'node scripts/clean.js', opts: { files: { '/home/u/proj/scripts/clean.js': `require('fs').rm(require('os').homedir(), {force: true,${pad}recursive: true}, () => {});\n` } }, expect: S },
  { id: 'E:pwsh-pad', cmd: `pwsh -c "Remove-Item /home/u${pad}-Recurse -Force"`, expect: S },
  { id: 'E:buffer-hex-pad', cmd: `node -e "eval(Buffer.from('${hexOf('require(\"child_process\").execSync(\"npm publish\")')}'${pad}, 'hex').toString())"`, expect: S },
  { id: 'E:buffer-hex-short', cmd: `node -e "eval(Buffer.from('${hexOf('require(\"child_process\").execSync(\"npm publish\")')}', 'hex').toString())"`, expect: S },
  { id: 'E:secret-var-long', cmd: 'echo ${' + 'A'.repeat(300) + '_KEY}', expect: undefined },
  { id: 'E:pass-fs-rm-file', cmd: `node -e "require('fs').rm('dist', {recursive: true}, () => {})"`, expect: undefined },
];
