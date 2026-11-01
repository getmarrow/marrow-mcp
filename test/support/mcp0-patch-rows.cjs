'use strict';

// Test-only (never ships). Round 2 of MCP-0 (audit-mcp0 B1, B2): commands TEXT ONLY, never run. Each row of B1, B2 and CLEAR gets exactly its 3.9.109
// answer (test/fixtures-mcp0-patch-base.json, recorded by running that build); each row of HELD names a control-off word and is held.

// Audit B1: 9 ordinary commands that mention the installer folder or a file of it, then run something else. 3.9.109 lets each through.
const B1 = [
  ['P01 cd installer repo, node --test', 'cd ~/agent-work/marrow-install && node --test test/control-state.test.js'],
  ['P02 grep uninstall in installer README, python script', 'grep -rn uninstall ~/src/marrow-install/README.md; python3 tools/summarize.py'],
  ['P03 echo a message naming the installer, ./script', "echo 'checking marrow-install control flow'; ./run.sh"],
  ['P04 git -C installer log, python script', 'git -C ~/src/marrow-install log --oneline -- src/control-state.js && python3 tools/report.py'],
  ['P05 ls installer file, bash script', 'ls ~/agent-work/marrow-install/src/control-state.js && bash scripts/check.sh'],
  ['P07 cat installer notes piped to a node script', 'cat notes/marrow-install-control.md | node tools/count-lines.js'],
  ['P08 grep -c installer docs, source a venv', 'grep -c marrow-install docs/control.md; source .venv/bin/activate'],
  ['P11 cd installer repo, bash -n syntax check', 'cd ~/src/marrow-install && bash -n scripts/uninstall.sh'],
  ['P12 cd installer repo, python lint', 'cd ~/src/marrow-install && python3 tools/lint.py --check control'],
];

// Audit B2: 2 read-only inline scripts that print a Marrow config or package field. 3.9.109 lets each through.
const B2 = [
  ['M01 python reads .mcp.json marrow server', `python3 -c "import json;print(json.load(open('.mcp.json'))['mcpServers']['marrow'])"`],
  ['M24 node prints the MCP package version', `node -e "console.log(require('@getmarrow/mcp/package.json').version)"`],
];

// Neighbours of B1 and B2 (the class sweep): a command with no control-off word anywhere, in every position the new clauses read.
const CLEAR = [
  ['echo message with control word, bash file', "echo 'marrow-install control flow notes'; bash scripts/check.sh"],
  ['printf to a file, source a venv', "printf '%s\\n' 'marrow-install' > names.txt; source .venv/bin/activate"],
  ['cat doc piped to bash', 'cat docs/marrow-install-control.md | bash'],
  ['echo piped into tee, python script', 'echo marrow-install | tee notes.txt; python3 tools/summarize.py'],
  ['redirect then script by absolute path', 'echo marrow-install > names.txt && ~/bin/report-tool'],
  ['cd installer repo, node script', 'cd ~/src/marrow-install && node bin/report.js'],
  ['git -C installer, script by relative path', 'git -C ~/src/marrow-install status && ./scripts/report.sh'],
  ['cat control doc, python module', 'cat ~/src/marrow-install/docs/control.md; python3 -m tools.report'],
  ['grep control in installer src, bash file', 'grep -rn control ~/src/marrow-install/src; bash scripts/lint.sh'],
  ['ls installer, deno script', 'ls ~/src/marrow-install; deno run tools/report.ts'],
  ['python reads .bashrc inline', `python3 -c "print(open('/home/u/.bashrc').read())"`],
  ['node prints the SDK package version', `node -e "console.log(require('@getmarrow/sdk/package.json').version)"`],
  ['perl prints the MCP package name', `perl -e 'print "@getmarrow/mcp\\n"'`],
];

// A note that names a control-off word as data, then a script of an interpreter (no inline code): 3.9.109 lets it through; so does this change.
const INTERP = [
  ['echo a note naming uninstall, python script', "echo 'marrow-install uninstall notes' > notes.txt; python3 tools/summarize.py"],
  ['printf a note with the whole command, node script', "printf '%s\\n' 'npx @getmarrow/install control disable is owner only' >> notes.md; node tools/count-lines.js notes.md"],
  ['cat then node script, doc named uninstall', 'cat docs/marrow-install-uninstall.md | node tools/count-lines.js'],
];

// 3.9.109 already holds a read of Marrow's own files by an inline script (self-protect); the answer must stay exactly that one.
const BASE_HELD = [
  ['node reads settings.json inline', `node -e "console.log(require('fs').readFileSync('.claude/settings.json','utf8'))"`],
  ['python lists the .marrow folder inline', `python3 -c "import os; print(os.listdir(os.path.expanduser('~/.marrow')))"`],
];

// Round 2 cut (verify-mcp0 B1): commands that name the installer, or a word such as uninstall or disable, only as data and then run another program.
// 3.9.109 lets each through; so does this change.
const RES = [
  ['RES1 cat an installer script, bash a lint', 'cat ~/src/marrow-install/scripts/uninstall.sh | head -20; bash scripts/lint.sh'],
  ['RES2 echo a note naming uninstall to a file, bash another script', "echo 'marrow-install uninstall notes' > n.txt; bash scripts/run.sh"],
  ['RES3 printf a note to a file, source a venv', "printf 'marrow-install disable flag' >> n.txt; source .venv/bin/activate"],
];
const EXEC = [
  ['E1 cat a README, a script with --disable-cache', 'cat ~/src/marrow-install/README.md; ./build.sh --disable-cache'],
  ['E2 grep saved to a file, bash a lint', 'grep -rn uninstall ~/src/marrow-install > hits.txt; bash scripts/lint.sh'],
  ['E3 git log to a file, a script with --disable-cache', 'git -C ~/src/marrow-install log > out.txt; ./run.sh --disable-cache'],
  ['E4 cat a package.json into jq, an uninstall-check script', 'cat ~/src/marrow-install/package.json | jq .version; ./scripts/uninstall-check.sh'],
  ['E5 echo a message, vitest with --disable-console-intercept', 'echo "marrow-install tests"; ./node_modules/.bin/vitest run --disable-console-intercept'],
  ['E6 cat an uninstall doc, source a venv', 'cat ~/src/marrow-install/docs/uninstall.md; source .venv/bin/activate'],
  ['E7 cat an uninstall doc, a formatter script', 'cat ~/src/marrow-install/docs/uninstall.md; ./scripts/fmt.sh'],
  ['E8 bash -n syntax check, cat an uninstall doc', 'bash -n scripts/lint.sh; cat ~/src/marrow-install/docs/uninstall.md'],
  ['E9 cat an uninstall source file, source nvm', 'cat ~/src/marrow-install/src/uninstall.js; source ~/.nvm/nvm.sh; nvm use 22'],
  ['E10 echo a note to a file, a test script', "echo 'do not uninstall marrow-install here' >> notes.md; ./scripts/test.sh"],
  ['E11 cat an uninstall doc into bash -n', 'cat ~/src/marrow-install/docs/uninstall.md | bash -n'],
  ['E12 ls with 2>/dev/null, bash an uninstall test', 'ls ~/src/marrow-install 2>/dev/null; bash scripts/uninstall-test.sh'],
  ['E13 grep with 2>/dev/null, a script with --disable-color', 'grep -c marrow-install docs/control.md 2>/dev/null; ./scripts/check.sh --disable-color'],
];
const TRIP = [
  ['T1 node prints a script field of the MCP package', `node -e "console.log(require('@getmarrow/mcp/package.json').scripts.uninstall)"`],
  ['T2 python prints a disable key of .mcp.json', `python3 -c "import json;print(json.load(open('.mcp.json')).get('disable'))"`],
  ['T3 python tests for uninstall in .mcp.json', `python3 -c "import json;print('uninstall' in json.load(open('.mcp.json')))"`],
  ['T4 node prints the installer version', `node -e "console.log('v'+require('@getmarrow/install/package.json').version)"`],
  ['T5 python counts marrow-install in .mcp.json', `python3 -c "import json;print(json.load(open('.mcp.json')).count('marrow-install'))"`],
  ['T6 node prints the installer package name', `node -e "console.log(require('./node_modules/@getmarrow/install/package.json').name+' ok')"`],
  ['T7 python prints a disabled key of .mcp.json', `python3 -c "import json;print(json.load(open('.mcp.json')).get('disabled'))"`],
  ['T8 python splits the installer name', `python3 -c "print('@getmarrow/install'.split('/')[1]+' version')"`],
  ['T9 node checks the MCP package for an uninstall script', `node -e "const p=require('@getmarrow/mcp/package.json');console.log(p.name+' '+Object.keys(p.scripts).includes('uninstall'))"`],
  ['T10 python prints the size of .mcp.json, a comment names disable', `python3 -c "import json;d=json.load(open('.mcp.json'));print(len(d)) # disable"`],
];

// A control-off command a heredoc writes is read as a command line by the walk and is held (the heredoc body is shell text).
const HELD = [
  ['cat of a heredoc writes the command, bash runs it', "cat > run.sh <<'EOF'\nnpx @getmarrow/install control disable --yes\nEOF\nbash run.sh"],
];

// An inline script that spells a control-off command, or builds it from the environment or a package-folder removal, is still held (the mapper stops it).
const TRIPWIRE_HELD = [
  ['python takes the subcommand from the environment', `D=disable python3 -c "import os; os.system('npx @getmarrow/install control '+os.environ['D'])"`],
  ['node removes the installer package folder', `node -e "require('fs').rmSync('node_modules/@getmarrow/install',{recursive:true}); /* uninstall */"`],
];

module.exports = { B1, B2, RES, EXEC, TRIP, CLEAR, INTERP, BASE_HELD, HELD, TRIPWIRE_HELD };
