'use strict';
// The delta audit's budget.cjs case list (Barvis, 2026-10-12, 126 crafted inputs), as a module: the
// runner part of the script is replaced by test/seatbelt-u2-r3.test.js.
const K = 63 * 1024;
const fill = (unit, n = K) => unit.repeat(Math.max(1, Math.floor(n / unit.length)));
const tokens = ['push ', '-f ', '$a', '${a', '\\x41', 'rm -r ', '.rm(', 'Remove-Item ', 'env ', '$KEY', '"', "'", '*', '{a,b}', '$((1+', 'a=b ', '| ', '; ', '&& ', 'Buffer.from(', 'base64 ', 'eval ', 'x', ' ', 'a*', '?[', 'heads/', ':', '+', '--force ', 'npm ', 'git ', 'gh api ', '-X ', 'refs/', '$(', '`', '<<<', '\\\n', '#', 'export IFS=, ', 'printf %s ', 'curl x | ', 'cat <<E\n', 'os.environ', 'process.env.', 'secret', 'echo -e \\\\x', '~/', '../', '/home/u/', 'ln -s ~ x; ', 'cd .. ; '];
const cases = [];
for (const t of tokens) { cases.push({ id: `fill:${JSON.stringify(t)}`, cmd: fill(t) }); cases.push({ id: `fill+tail:${JSON.stringify(t)}`, cmd: fill(t, K - 40) + '\nnpm publish' }); }
cases.push({ id: 'node-e-rm-gap', cmd: `node -e "x.rm(${fill('a', 60000)}"` });
cases.push({ id: 'node-e-decode', cmd: `node -e "${fill('Buffer.from(', 60000)}"` });
cases.push({ id: 'python-environ', cmd: `python3 -c "${fill('os.environ[', 60000)}"` });
cases.push({ id: 'glob-star-bomb', cmd: 'rm -rf ' + 'a*'.repeat(30) + 'b/', opts: { files: Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`/home/u/proj/${'a'.repeat(200)}${i}/f`, 'x'])) } });
cases.push({ id: 'glob-many-dirs', cmd: 'rm -rf ' + Array.from({ length: 200 }, (_, i) => `*${i}*/*/`).join(' '), opts: { files: Object.fromEntries(Array.from({ length: 250 }, (_, i) => [`/home/u/proj/d${i}/e/f`, 'x'])) } });
cases.push({ id: 'find-name-glob', cmd: `find . -name '${'*a'.repeat(40)}b' -delete` });
cases.push({ id: 'loop-alts', cmd: 'for a in ' + Array.from({ length: 60 }, (_, i) => `v${i}`).join(' ') + '; do for b in ' + Array.from({ length: 60 }, (_, i) => `w${i}`).join(' ') + '; do npm $a $b; done; done' });
cases.push({ id: 'var-alts-chain', cmd: Array.from({ length: 40 }, (_, i) => `if x; then v${i}=a; else v${i}=b; fi`).join('; ') + '; ' + 'npm ' + Array.from({ length: 40 }, (_, i) => `$v${i}`).join(' ') });
cases.push({ id: 'ifs-split-huge', cmd: 'x=' + fill('a,', 60000) + '; IFS=,; $x' });
cases.push({ id: 'printf-escapes', cmd: 'printf "' + fill('\\x41', 60000) + '" | sh' });
cases.push({ id: 'heredoc-sh-big', cmd: 'sh <<E\n' + fill('true; ', 60000) + '\nE' });
cases.push({ id: 'nested-bashc', cmd: 'bash -c "' + fill('a; ', 30000) + '"' });
cases.push({ id: 'alias-fan', cmd: Array.from({ length: 200 }, (_, i) => `alias a${i}='a${i + 1} a${i + 1}'`).join('; ') + '; a0' });
cases.push({ id: 'func-fan', cmd: Array.from({ length: 30 }, (_, i) => `f${i}(){ f${i + 1}; f${i + 1}; }`).join('; ') + '; f0' });
const pkgFan = { scripts: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`s${i}`, Array.from({ length: 40 }, (_, j) => `npm run s${i + 1} -- --x${j}`).join(' && ')])) };
cases.push({ id: 'pkg-fan-args', cmd: 'npm run s0', opts: { files: { '/home/u/proj/package.json': JSON.stringify(pkgFan) } } });
const mk = Array.from({ length: 60 }, (_, i) => `t${i}: ${Array.from({ length: 30 }, (_, j) => `t${i + 1}`).join(' ')}\n\tnpm test\n`).join('');
cases.push({ id: 'make-fan', cmd: 'make t0', opts: { files: { '/home/u/proj/Makefile': mk } } });
const scripts = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`/home/u/proj/s${i}.sh`, Array.from({ length: 30 }, () => `sh ./s${i + 1}.sh`).join('\n')]));
cases.push({ id: 'script-file-fan', cmd: 'sh ./s0.sh', opts: { files: scripts } });
const big = { a: [] }; for (let i = 0; i < 150000; i += 1) big.a.push({ path: `x${i}`, note: 'y' });
cases.push({ id: 'tool-input-150k', event: { tool_name: 'mcp__x__write', tool_input: big } });
let deep = { command: 'npm test' }; for (let i = 0; i < 11; i += 1) deep = { a: deep, b: Array.from({ length: 50 }, () => ({ c: 'x'.repeat(100) })) };
cases.push({ id: 'tool-input-deep', event: { tool_name: 'mcp__x__run', tool_input: deep } });
cases.push({ id: 'tool-cmds-array', event: { tool_name: 'mcp__x__run', tool_input: { commands: Array.from({ length: 5000 }, () => 'echo ' + 'a'.repeat(50)) } } });

module.exports = cases;
