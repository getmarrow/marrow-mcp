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

// A text with a control-off word that a chain writes and then runs stays held (the executed-data rule, narrowed to writers and to control-off words).
const HELD = [
  ['printf writes the command, script by path runs it', "printf '%s\\n' 'npx @getmarrow/install control disable --yes' > run.sh; ./run.sh"],
  ['echo piped into sh', "echo 'npx @getmarrow/install control disable --yes' | sh"],
  ['echo writes uninstall, bash file runs it', "echo 'marrow-install uninstall --yes' > run.sh; bash run.sh"],
  ['printf writes the command, source runs it', "printf 'npx @getmarrow/install control disable --yes' > f.sh; source f.sh"],
  ['tee writes the command, script by path runs it', "echo 'marrow-install uninstall --yes' | tee run.sh; ./run.sh"],
  ['cat of a heredoc writes the command, bash runs it', "cat > run.sh <<'EOF'\nnpx @getmarrow/install control disable --yes\nEOF\nbash run.sh"],
  ['redirect writes the command, expansion program runs it', "echo 'marrow-install uninstall --yes' > /tmp/x.sh; $SHELL /tmp/x.sh"],
];

// An inline script that names a control-off word with the installer is still held (the mapper tripwire, narrowed to a call that names control-off).
const TRIPWIRE_HELD = [
  ['node concatenates the installer name, control disable', `node -e "require('child_process').execSync('npx @getmarrow/inst'+'all control disable --yes')"`],
  ['python concatenates the installer name, uninstall', `python3 -c "import os; os.system('npx @getmarrow/' + 'install uninstall --yes')"`],
  ['python takes the subcommand from the environment', `D=disable python3 -c "import os; os.system('npx @getmarrow/install control '+os.environ['D'])"`],
  ['node removes the installer package folder', `node -e "require('fs').rmSync('node_modules/@getmarrow/install',{recursive:true}); /* uninstall */"`],
];

module.exports = { B1, B2, CLEAR, INTERP, BASE_HELD, HELD, TRIPWIRE_HELD };
