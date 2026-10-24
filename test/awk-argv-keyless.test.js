'use strict';

// awk-family programs that start a command: the keyless seatbelt reads the command each one names (system(), `print | CMD`, `printf | CMD`, `CMD | getline`,
// gawk's `|&`). A command made only of literals is judged like a nested shell string, so it stops where the direct command stops; any other command (built from
// ARGV, ENVIRON, a -v or NAME=VALUE variable, a field, a value read by getline, a call such as sprintf, a function parameter) is a dynamic command: a stop.
// The rows are STRINGS fed to the checkers: nothing here runs a command. Friction rows must stay as they were, the keyed mode is unchanged, the normalized
// action (the approval key input) is the command text only, and each new rule has a mutant that a row kills.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const ROOT = path.join(__dirname, '..');
function checkersFor(root) {
  const { classifyTool, outageHolds } = require(path.join(root, 'dist/hook-pre-action.js'));
  const { evaluateSeatbelt } = require(path.join(root, 'dist/seatbelt/mapper.js'));
  const { outageRisk } = require(path.join(root, 'dist/seatbelt/hook.js'));
  const event = (command) => ({ tool_name: 'Bash', tool_input: { command } });
  return {
    keyed: (command) => { const c = classifyTool(event(command)); return c.protected === true && c.readOnly === false; },
    keyless: (command, files) => evaluateSeatbelt(event(command), makeEnv({ classifierClass: 'routine', ...(files ? { files } : {}) })),
    // The outage hold: the mapper's reading of the action, or the client classifier's answer where the mapper could not finish.
    outage: (command) => { const c = classifyTool(event(command)); return outageHolds(c.protected === true, () => outageRisk(event(command), Number.POSITIVE_INFINITY)); },
  };
}
const live = checkersFor(ROOT);
const stops = (checkers, cmd, files) => checkers.keyless(cmd, files).decision === 'stop';
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

const TARGETS = ['wrangler deploy --prod', 'wrangler deploy --env production', 'git push --force origin main', 'git push -f origin master', 'git push --force-with-lease origin main',
  'git push origin +main', 'npm publish', 'gh release create v1.0.0', 'rm -rf ~', 'rm -rf /'];
const BUILDERS = {
  'ARGV[1]': (t) => `awk 'BEGIN{system(ARGV[1])}' ${shq(t)}`,
  'ARGV loop over ARGC': (t) => `awk 'BEGIN{for(i=1;i<ARGC;i++) s=s ARGV[i] " "; system(s)}' ${t}`,
  'ENVIRON': (t) => `C=${shq(t)} awk 'BEGIN{system(ENVIRON["C"])}'`,
  '-v': (t) => `awk -v c=${shq(t)} 'BEGIN{system(c)}'`,
  '--assign': (t) => `awk --assign c=${shq(t)} 'BEGIN{system(c)}'`,
  'operand NAME=VALUE': (t) => `awk 'END{system(c)}' c=${shq(t)} /dev/null`,
  'getline from ARGV': (t) => `awk 'BEGIN{cmd=ARGV[1]; cmd | getline x; print x}' ${shq(t)}`,
  'print | "sh" fed by ARGV': (t) => `awk 'BEGIN{print ARGV[1] | "sh"}' ${shq(t)}`,
  'printf | "sh"': (t) => `awk 'BEGIN{printf "%s\\n", ARGV[1] | "sh"}' ${shq(t)}`,
  'system(sprintf())': (t) => `awk 'BEGIN{system(sprintf("%s", ARGV[1]))}' ${shq(t)}`,
  'system(a b)': (t) => `awk 'BEGIN{a=ARGV[1]; b=" "; system(a b)}' ${shq(t)}`,
  'function wrapper': (t) => `awk 'function run(c){system(c)} BEGIN{run(ARGV[1])}' ${shq(t)}`,
  'main rule': (t) => `awk '{system(ARGV[1])}' ${shq(t)}`,
  'END rule': (t) => `awk 'END{system(ARGV[1])}' ${shq(t)}`,
  'literal': (t) => `awk 'BEGIN{system(${JSON.stringify(t)})}'`,
  'literal variable': (t) => `awk 'BEGIN{c=${JSON.stringify(t)}; system(c)}'`,
  'literal pieces': (t) => `awk 'BEGIN{a=${JSON.stringify(t.slice(0, 4))}; b=${JSON.stringify(t.slice(4))}; system(a b)}'`,
  'literal print | "sh"': (t) => `awk 'BEGIN{print ${JSON.stringify(t)} | "sh"}'`,
  'literal | getline': (t) => `awk 'BEGIN{${JSON.stringify(t)} | getline x; print x}'`,
  'fields': (t) => `echo ${shq(t)} | awk '{system($0)}'`,
};

test('every stopped target, built by every builder, stops keyless, keyed and in an outage', () => {
  const missed = [];
  let rows = 0;
  for (const t of TARGETS) {
    // control: the direct command
    assert.equal(stops(live, t), true, `direct: ${t}`);
    assert.equal(live.keyed(t), true, `direct keyed: ${t}`);
    for (const [name, build] of Object.entries(BUILDERS)) {
      const cmd = build(t);
      rows += 1;
      if (!stops(live, cmd)) missed.push(`keyless ${name}: ${cmd}`);
      // keyed is unchanged: it reads the command text, so it holds the rows whose text is whole (it never held `rm -rf` inside an awk program)
      if (live.keyed(t) && !/^rm /.test(t) && name !== 'literal pieces' && !live.keyed(cmd)) missed.push(`keyed ${name}: ${cmd}`);
      if (live.outage(cmd) !== true) missed.push(`outage ${name}: ${cmd}`);
    }
  }
  assert.ok(rows >= 190, `${rows} rows`);
  assert.deepEqual(missed, []);
});

test('the same builders under every program name and wrapper stop', () => {
  const names = ['awk', 'gawk', 'mawk', 'nawk', 'busybox awk', '/usr/bin/awk', '\\awk', '"awk"', 'command awk', 'env awk', 'exec awk', 'nice awk', 'nohup awk', 'timeout 5 awk',
    'stdbuf -o0 awk', 'xargs awk', 'sudo -n awk'];
  const missed = [];
  for (const name of names) {
    for (const t of ['wrangler deploy --prod', 'git push --force origin main', 'npm publish']) {
      for (const b of ['ARGV[1]', '-v', 'literal', 'ENVIRON']) {
        const cmd = BUILDERS[b](t).replace(/\bawk\b/, name);
        if (!stops(live, cmd)) missed.push(cmd);
      }
    }
  }
  for (const t of ['wrangler deploy --prod', 'git push --force origin main', 'npm publish']) {
    for (const cmd of [`find . -maxdepth 1 -exec awk 'BEGIN{system(ARGV[1])}' ${shq(t)} {} \\;`, `env -S ${shq(`awk BEGIN{system(ARGV[1])} ${t}`)}`, `echo x | xargs awk 'BEGIN{system(ARGV[1])}' ${shq(t)}`]) {
      if (!stops(live, cmd)) missed.push(cmd);
    }
  }
  assert.deepEqual(missed, []);
});

test('chaining, wrappers and substitutions around an awk command that starts a stopped command stop', () => {
  const chains = [(c) => `${c} && true`, (c) => `true && ${c}`, (c) => `${c}; true`, (c) => `false || ${c}`, (c) => `true | ${c}`, (c) => `(${c})`, (c) => `{ ${c}; }`, (c) => `${c} &`,
    (c) => `bash -c ${shq(c)}`, (c) => `sh -c ${shq(c)}`, (c) => `eval ${shq(c)}`, (c) => `sudo -n ${c}`, (c) => `ssh localhost ${shq(c)}`, (c) => `echo $(${c})`, (c) => `echo \`${c}\``];
  const missed = [];
  for (const t of ['wrangler deploy --prod', 'git push --force origin main', 'npm publish']) {
    for (const b of ['ARGV[1]', 'literal', 'ENVIRON', '-v']) for (const chain of chains) { const cmd = chain(BUILDERS[b](t)); if (!stops(live, cmd)) missed.push(cmd); }
  }
  assert.deepEqual(missed, []);
});

test('variables: a command in a shell variable, and a program in one', () => {
  for (const cmd of [
    "C=git; awk 'BEGIN{system(ARGV[1] \" \" ARGV[2] \" \" ARGV[3] \" \" ARGV[4] \" \" ARGV[5])}' \"$C\" push --force origin main",
    "awk 'BEGIN{system(ARGV[1] \" \" ARGV[2] \" \" ARGV[3] \" \" ARGV[4] \" \" ARGV[5])}' \"${V:-git}\" push --force origin main",
    "P='BEGIN{system(ARGV[1])}'; awk \"$P\" 'git push --force origin main'", "awk \"$P\" 'git push --force origin main'", "awk \"$P\" 'wrangler deploy --prod'",
    "X='git push --force origin main'; awk -v c=\"$X\" 'BEGIN{system(c)}'", "export X='git push --force origin main'; awk 'BEGIN{system(ENVIRON[\"X\"])}'",
    "awk -v \"$ASSIGN\" 'BEGIN{system(c)}'", "awk 'BEGIN{system(c)}' \"$ASSIGN\"", "awk $OPTS 'BEGIN{system(\"git push --force origin main\")}'",
    "awk $OPTS 'BEGIN{system(ARGV[1])}' ls", "awk -F'{,}' 'BEGIN{system(\"npm publish\")}'",
  ]) assert.equal(stops(live, cmd), true, cmd);
  for (const cmd of ["awk \"{print \\$$COL}\" data", 'awk "NR==$N" data', 'awk $OPTS \'{print}\' f', 'awk -F$SEP \'{print $1}\' f']) assert.equal(stops(live, cmd), false, cmd);
});

test('a command that is only literals is judged like the direct command; a variable set only from literals is resolved', () => {
  // Pass: the literal command is one the direct command passes.
  for (const cmd of ['awk \'BEGIN{system("date")}\'', 'awk \'BEGIN{system("echo hi")}\'', 'awk \'BEGIN{system("git status")}\'', 'awk \'BEGIN{system("npm test")}\'',
    'awk \'{print | "sort"}\' f', 'awk \'{c="sort"; print | c}\' f', 'awk \'{print $1 | "sort | uniq -c"}\' f', 'awk \'BEGIN{"date" | getline d; print d}\'',
    'awk \'BEGIN{"git log --oneline" | getline l; print l}\'', 'awk \'BEGIN{ system("") }\'', 'awk \'BEGIN { c = "sort"; d = c " -u"; print | d }\' f']) {
    assert.equal(stops(live, cmd), false, cmd);
    assert.equal(live.keyed(cmd), false, cmd);
  }
  // Stop: through a variable, a concatenation, a second assignment, or a piece of a concatenation.
  for (const cmd of ['awk \'BEGIN{c="gh release create v1"; system(c)}\'', 'awk \'BEGIN{a="gh release"; b=" create v1"; system(a b)}\'', 'awk \'BEGIN{c="date"; c="gh release create v1"; system(c)}\'',
    'awk \'BEGIN{ "echo " "gh release create v1" | getline x }\'', 'awk \'BEGIN{ print "x" | "echo " "gh release create v1" }\'', 'awk \'BEGIN{c="gh release"; d=c " create v1"; system(d)}\'']) {
    assert.equal(stops(live, cmd), true, cmd);
  }
  // The stop is the direct command's own: the reason names the same rule.
  assert.equal(live.keyless('gh release create v1').hits[0].reason, live.keyless('awk \'BEGIN{system("gh release create v1")}\'').hits[0].reason);
  assert.equal(live.keyless('rm -rf /').hits[0].category, live.keyless('awk \'BEGIN{system("rm -rf /")}\'').hits[0].category);
  // Not literals: a variable the program also writes some other way, a special variable, an array element, a call, a field, a value read by getline.
  for (const cmd of ["awk 'BEGIN{c=\"sort\"; c=c ARGV[1]; system(c)}' x", "awk 'BEGIN{c=\"ls\"; c++; system(c)}'", "awk 'BEGIN{c=\"ls\"; sub(/s/, ARGV[1], c); system(c)}' x",
    "awk 'BEGIN{c=\"ls\"; split(ARGV[1], c); system(c[1])}' x", "awk 'BEGIN{c=\"ls\"; getline c < ARGV[1]; system(c)}' x", "awk 'BEGIN{system(FILENAME)}' x", "awk 'BEGIN{system(a[1])}'",
    "awk 'BEGIN{system(tolower(\"LS\"))}'", "awk 'BEGIN{system(substr(\"xls\", 2))}'", "awk 'BEGIN{system(f())} function f(){return \"ls\"}'", "awk '{system($1)}' f", "awk '{print | $1}' f",
    "awk 'BEGIN{system(c)}'", "awk 'BEGIN{c=\"ls\"; system(c)}' c=ls /dev/null", "awk -v c=ls 'BEGIN{c=\"ls\"; system(c)}'", "awk 'BEGIN{c=\"ls\"; system(c)}' \"$F\"",
    "awk 'BEGIN{while((getline l < ARGV[1])>0) system(l)}' cmds.txt", "awk 'BEGIN{while((\"cat cmds.txt\" | getline l)>0) system(l)}'", "awk '{system($0)}' cmds.txt", "awk 'BEGIN{@f(\"ls\")}'"]) {
    const d = live.keyless(cmd);
    assert.equal(d.decision, 'stop', cmd);
    assert.ok(d.reasons.includes('dynamic_awk_command'), `${cmd}: ${d.reasons}`);
  }
});

test('words printed into a shell are the commands it runs: they must be literals', () => {
  for (const cmd of ["awk '{print $0 | \"sh\"}' cmds.txt", "awk '{print | \"bash\"}' cmds.txt", "awk 'BEGIN{print ARGV[1] | \"env sh\"}' x", "awk '{print $1 | \"sort | sh\"}' f", "awk 'BEGIN{print ENVIRON[\"C\"] | \"sh\"}'"]) {
    assert.equal(stops(live, cmd), true, cmd);
  }
  for (const cmd of ["awk '{print $1 | \"grep sh\"}' f", "awk '{print $1 | \"sort\"}' f", "awk 'BEGIN{print \"echo hi\" | \"sh\"}'", "awk 'BEGIN{print \"x\" |& \"cat\"}'"]) {
    assert.equal(stops(live, cmd), false, cmd);
  }
});

test('misleading words never stop: a program that only prints, a commit message, a file named deploy.awk, ARGV in a path', () => {
  for (const cmd of ["awk 'BEGIN{print \"git push --force origin main\"}'", "awk 'BEGIN{print \"deploy\"}'", "awk 'BEGIN{print \"npm publish\"}'", "awk 'BEGIN{print ARGV[1], ARGV[2]}' git push",
    "awk '{print}' deploy.awk", "awk '{print $1}' npm publish", "awk '{print $1}' /tmp/ARGV/system/file", "awk '/ARGV/ {print}' f", "awk 'BEGIN{x=\"system(ARGV[1])\"; print x}'",
    "echo 'awk system(ARGV)'", "git commit -m 'awk system(ARGV[1]) idea'", "git commit -m \"awk 'BEGIN{system(ARGV[1])}' x\"", "awk '{print > \"deploy.txt\"}' f", "grep 'system(ARGV' deploy.awk", 'cat deploy.awk',
    "awk 'BEGIN{printf \"%s\\n\", \"git push --force\"}'", "awk 'BEGIN{ # system(\"x\")\n print 1}'"]) {
    assert.equal(stops(live, cmd), false, cmd);
  }
});

test('an unknown or shortened option stops; the options awk knows do not', () => {
  for (const cmd of ["awk --frobnicate 'BEGIN{system(ARGV[1])}' 'git push --force origin main'", "gawk -Z 'BEGIN{system(ARGV[1])}' 'git push --force origin main'", "awk --frobnicate '{print $1}' f",
    "gawk -Z '{print}' f", "mawk -Z '{print}' f", "awk --sou 'BEGIN{print 1}'", "gawk --sourc 'BEGIN{print 1}'", "gawk --ass c=ls 'BEGIN{print c}'", "gawk --posix=1 '{print}' f", "awk -q '{print}' f",
    "gawk -W source=x '{print}' f", "gawk -W exec=x '{print}' f", "awk -Wfrob '{print}' f"]) {
    const d = live.keyless(cmd);
    assert.equal(d.decision, 'stop', cmd);
  }
  assert.ok(live.keyless("awk --frobnicate '{print $1}' f").reasons.includes('awk_unknown_option'));
  for (const cmd of ["awk -F: -v OFS=, '{print $1}' f", 'gawk --version', 'awk --version', 'gawk -V', 'awk -W version', "gawk --posix '{print}' f", "gawk --lint '{print}' f", "gawk --csv '{print $1}' f",
    "gawk -nF, '{print $1}' f", "gawk -F, -v OFS=';' -f script.awk data", "mawk -W sprintf=100 '{print}' f", "gawk --traditional '{print}' f", "gawk -b '{print}' f", "awk -version", "awk -safe '{print}' f",
    "awk -F '\\t' '{print $1}' f", "awk -F\\| '{print $1}' f", "awk -f script.awk -- data", "awk -- '{print}' f", "gawk --field-separator=, '{print $1}' f", "gawk --assign n=1 'NR==n' f"]) {
    assert.equal(stops(live, cmd), false, cmd);
  }
});

test('repeated -v or --assign: every value is judged, in either order; several -e or --source programs are all judged', () => {
  for (const cmd of ["awk -v c=ls -v c='git push --force origin main' 'BEGIN{system(c)}'", "awk -v c='git push --force origin main' -v c=ls 'BEGIN{system(c)}'", "awk --assign c=ls --assign c='npm publish' 'BEGIN{system(c)}'",
    "awk -vc=ls 'BEGIN{system(c)}'", "awk -v c='npm publish' -v d=ls 'BEGIN{system(c)}'",
    "gawk -e 'BEGIN{x=1}' -e 'BEGIN{system(\"git push --force origin main\")}'", "gawk --source 'BEGIN{x=1}' --source 'BEGIN{system(ARGV[1])}' 'git push --force origin main'",
    "gawk -e 'BEGIN{system(ARGV[1])}' 'git push --force origin main'", "gawk --source='BEGIN{system(\"npm publish\")}'", "gawk -e 'BEGIN{' -e 'system(\"gh release create v1\")}'",
    "gawk -e 'BEGIN{x=1}' -e 'BEGIN{system(\"gh release create v1\")}'", "gawk -e 'BEGIN{c=\"gh release\"}' -e 'BEGIN{system(c \" create v1\")}'"]) {
    assert.equal(stops(live, cmd), true, cmd);
  }
});

test('program text that cannot be read is judged as for an interpreter that is given a script it cannot read', () => {
  const analogue = (awkCmd, pyCmd) => assert.equal(stops(live, awkCmd), stops(live, pyCmd), `${awkCmd} / ${pyCmd}`);
  // a script file that is not there: both pass; a path or program that is not literal: both are judged by name
  analogue("awk -f prog.awk 'git push --force origin main'", "python3 prog.py 'git push --force origin main'");
  analogue("awk -f \"$F\" 'git push --force origin main'", "python3 \"$S\" 'git push --force origin main'");
  analogue("awk -f \"$F\" data", "python3 \"$S\" data");
  // a program word that is wholly a variable is code nobody can read, as for `python3 -c \"$P\"`: the whole command text is read for a stopped action
  analogue("awk \"${P:-npm publish}\" f", "python3 -c \"${P:-npm publish}\"");
  analogue("echo \"npm publish done\" && awk \"$P\" f", "echo \"npm publish done\" && python3 -c \"$P\"");
  analogue("echo \"npm publish done\" && awk \"NR==$N\" f", "echo \"npm publish done\" && python3 -c \"print($N)\"");
  for (const cmd of ["awk \"${P:-npm publish}\" f", "echo \"npm publish done\" && awk \"$P\" f"]) assert.equal(stops(live, cmd), true, cmd);
  for (const cmd of ["echo \"npm publish done\" && awk \"NR==$N\" f", "awk \"NR==${N:-1}\" f"]) assert.equal(stops(live, cmd), false, cmd);
  analogue("awk -f <(echo 'BEGIN{system(\"npm publish\")}') data", "python3 <(echo 'import os; os.system(\"npm publish\")') data");
  // the word the older reading took as the program is still judged (awk reads these words as file names)
  for (const cmd of ["awk -f prog.awk 'BEGIN{system(\"gh release create v1\")}'", "awk -- -e 'BEGIN{system(\"gh release create v1\")}'", "awk -f prog.awk 'BEGIN{system(ARGV[1])}' ls"]) assert.equal(stops(live, cmd), true, cmd);
  for (const cmd of ["awk \"$P\" 'git push --force origin main'", 'awk "$P" data', 'awk "$(cat prog.awk)" data', "gawk -E \"$F\" 'npm publish'", "awk \"$(cat prog.awk)\" 'git push --force origin main'", "awk $X 'BEGIN{system(\"npm publish\")}'"]) {
    assert.equal(stops(live, cmd), true, cmd);
  }
  for (const cmd of ['awk -f prog.awk data', "awk -fprog.awk data", 'gawk -E prog.awk data', 'gawk --exec prog.awk data', 'gawk --file=prog.awk data', 'awk -f a.awk -f b.awk data', 'gawk -f "$F" data',
    "gawk -i inplace '{print}' f", "gawk -l ordchr 'BEGIN{print ord(\"a\")}'", "gawk -i inplace -f prog.awk f", 'gawk @include "x" \'BEGIN{}\'', "awk '{print $1}' <(ls)"]) {
    assert.equal(stops(live, cmd), false, cmd);
  }
  // a program given on stdin is read: from a heredoc it is judged, from an unknown source it stops
  assert.equal(stops(live, "awk -f - data <<'EOF'\nBEGIN{system(\"npm publish\")}\nEOF"), true);
  assert.equal(stops(live, "awk -f /dev/stdin data <<'EOF'\nBEGIN{system(ARGV[1])}\nEOF"), true);
  assert.equal(stops(live, 'awk -f - data < p.awk'), true);
  // a program file that IS readable is read like the inline program
  const files = { '/home/u/proj/run.awk': 'BEGIN{ system(ARGV[1]) }\n', '/home/u/proj/lit.awk': 'BEGIN{ system("gh release create v1") }\n', '/home/u/proj/ok.awk': '{ print $1 | "sort" }\n' };
  const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
  const withFiles = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ classifierClass: 'routine', files })).decision;
  assert.equal(withFiles('awk -f run.awk ls'), 'stop');
  assert.equal(withFiles('awk -f lit.awk f'), 'stop');
  assert.equal(withFiles('gawk -E lit.awk f'), 'stop');
  assert.equal(withFiles('awk -f ok.awk f'), 'pass');
  // an awk name the mapper does not know keeps the argument scan of an unknown program
  for (const cmd of ["original-awk 'BEGIN{system(ARGV[1])}' 'git push --force origin main'", "goawk 'BEGIN{system(ARGV[1])}' 'git push --force origin main'"]) assert.equal(stops(live, cmd), true, cmd);
  assert.equal(stops(live, "bioawk -c fastx '{print $name}' f"), false);
});

test('lexing: strings, comments, regular expressions and divisions are read the way awk reads them, under either reading of a bracket expression', () => {
  for (const cmd of ["awk 'BEGIN{x=4/2; system(ARGV[1])}' 'git push --force origin main'", "awk 'BEGIN{x=1 /2/ 3; system(\"gh release create v1\")}'", "awk 'BEGIN{ x=\"#\"; system(ARGV[1]) }' ls",
    "awk '/[/]/ {system(ARGV[1])}' ls", "awk '/[/ {system(\"gh release create v1\")} /]/'", "awk '/]/ {system(c)}' c='npm publish' f", "awk '{ system ( \"gh release create v1\" ) }'",
    "awk 'BEGIN{system(\"gh release \" \"create \" \"v1\")}'", "awk 'BEGIN{system(\"gh release create \\\nv1\")}'", "awk 'BEGIN{ c=\"gh\"; c=c \" release create v1\"; system(c) }'",
    "awk 'BEGIN{ split(\"gh release create v1\", a, \" \"); system(a[1] \" \" a[2]) }'", "awk 'BEGIN{ printf(\"%s\\n\", \"gh release create v1\") | \"sh\" }'", "awk 'BEGIN{ print \"a\", \"gh release create v1\" | \"sh\" }'",
    "gawk 'BEGIN{ print ARGV[1] |& \"sh\" }' 'npm publish'", "awk 'BEGIN{ system() }'", "awk 'BEGIN{ i++; system(\"echo \" i) }'", "awk \"BEGIN{system(\\\"$X\\\")}\"", "awk \"BEGIN{system($X)}\"",
    "awk 'BEGIN{system(\"\\x67h release create v1\")}'", "awk 'BEGIN{system(\"\\147h release create v1\")}'", "awk 'BEGIN{system(\"echo\\040hi\" ARGV[1])}' x"]) {
    assert.equal(stops(live, cmd), true, cmd);
  }
  for (const cmd of ["awk '$1 ~ /a|b/ {print}' f", "awk '/start/,/end/' f", "awk 'BEGIN { printf \"%d\\n\", 10/3 }'", "awk 'BEGIN{FS=\"|\"} {print $2}' f", "awk -F'|' '{print $2}' f", "awk '{print $1 / 2 | \"sort\"}' f",
    "awk '/[/]/ {print}' f", "awk '{ a[$1] = a[$1] \" \" $2 } END { for (k in a) print k, a[k] }' f", "awk '{print $1,$2 | \"sort\"}' f"]) {
    assert.equal(stops(live, cmd), false, cmd);
  }
  // linear time on a large program: many pipes, many parentheses, a long run of operators
  const started = process.hrtime.bigint();
  for (const prog of ['print | "sort";'.repeat(4000), '('.repeat(30000), 'x = (' + '1+'.repeat(20000) + '1)', '| '.repeat(30000), '"a" '.repeat(8000) + '| getline']) {
    live.keyless(`awk '${prog}' f`);
  }
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000, 'the awk reading took over five seconds');
  assert.equal(stops(live, `awk '${'x'.repeat(70000)}; system(c)' f`), true);
});

test('command: only a leading -v or -V looks a name up', () => {
  for (const cmd of ["command awk -v c='npm publish' 'BEGIN{system(c)}'", 'command git push --force origin main -v', 'command git push -v --force origin main', 'command npm publish -v', 'command -- git push --force origin main -v']) {
    assert.equal(stops(live, cmd), true, cmd);
  }
  for (const cmd of ['command -v awk', 'command -V awk', 'command -p -v awk', 'command -v git push']) assert.equal(stops(live, cmd), false, cmd);
});

// ---- friction: none of these changes, in any mode ----
const FRICTION = ["awk '{print $1}' f", "awk -F: '{print $1}' f", "awk 'NR>1' f", "awk -v OFS=, '{print}' f", "awk '{s+=$2} END{print s}' f", "ps aux | awk '{print $2}'", "git log --oneline | awk '{print $1}'",
  "awk 'BEGIN{print ARGV[1]}' x", "awk '{print > \"out.txt\"}' f", "awk '{print | \"sort\"}' f", "awk '{c=\"sort\"; print | c}' f", "awk 'BEGIN{system(\"date\")}'", 'awk -f script.awk data', "gawk -i inplace '{print}' f",
  'git status', 'npm test', 'ls', 'cat README.md', 'grep -r foo .', "awk 'BEGIN{\"date\" | getline d; print d}'", "awk 'BEGIN{while((getline l < ARGV[1])>0) n++; print n}' file.txt", "awk '{print $1 | \"sort -u\"}' f",
  "awk -F, '{print $2}' data.csv", "gawk '{print toupper($0)}' f", "awk 'length > 72' f", "awk '{ sum += $1 } END { print sum / NR }' f", "awk '$3 ~ /foo|bar/ {print $1}' f", "awk '!seen[$0]++' f",
  "awk 'NR==FNR{a[$1];next} $1 in a' f g", "mawk '{print $1}' f", "nawk '{print $1}' f", "busybox awk '{print $1}' f", "awk '{print $NF}' f", "awk '{ close(\"sort\"); print }' f",
  "awk '{ print $1 | \"sort | uniq -c\" }' f", "awk -v n=3 'NR==n' f", "awk 'BEGIN{ \"git log --oneline\" | getline l; print l }'", "awk '{print > \"/dev/stderr\"}' f"];
test('friction rows pass keyless, are not held keyed, and are not held in an outage', () => {
  for (const cmd of FRICTION) {
    assert.equal(stops(live, cmd), false, `keyless ${cmd}`);
    assert.equal(live.keyed(cmd), false, `keyed ${cmd}`);
    assert.equal(live.outage(cmd), false, `outage ${cmd}`);
  }
});

// ---- consumers and collisions ----
test('the normalized action is the command text only: it does not move, and stopped forms never collide with their neighbours', () => {
  const { normalizedHookAction } = require('../dist/normalized-action.js');
  const salt = require('node:crypto').randomBytes(32);
  const key = (command) => JSON.stringify(normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt }));
  const dummy = 'x'.repeat(24);
  const dummy2 = 'y'.repeat(24);
  const differ = [
    ["awk 'BEGIN{system(ARGV[1])}' 'git push --force origin main'", "awk 'BEGIN{print ARGV[1]}' 'git push --force origin main'"],
    ["awk 'BEGIN{system(ARGV[1])}' 'wrangler deploy --prod'", "awk 'BEGIN{system(ARGV[1])}' 'npm publish'"],
    ["awk 'BEGIN{system(ARGV[1] \" \" ARGV[2])}' npm publish", "awk 'BEGIN{system(ARGV[1] \" \" ARGV[2])}' npm test"],
    ["gawk -e 'BEGIN{system(\"npm publish\")}'", "gawk --source 'BEGIN{system(\"npm publish\")}'"],
    ["awk -v c='npm publish' 'BEGIN{system(c)}'", "awk -v c='npm test' 'BEGIN{system(c)}'"],
    [`awk -v t=${dummy} 'BEGIN{system(ARGV[1])}' npm publish`, `awk -v t=${dummy} 'BEGIN{system(ARGV[1])}' npm test`],
    [`TOKEN=${dummy} awk 'BEGIN{system(ARGV[1])}' npm publish`, `TOKEN=${dummy} awk 'BEGIN{system(ARGV[1])}' npm test`],
    [`awk 'BEGIN{system("curl https://x.test/a?token=${dummy}&to=1")}'`, `awk 'BEGIN{system("curl https://x.test/a?token=${dummy}&to=2")}'`],
  ];
  for (const [a, b] of differ) assert.notEqual(key(a), key(b), `${a} / ${b}`);
  // only a dummy secret value differs: the keys may match, and the value is in no key
  assert.equal(key(`TOKEN=${dummy} awk 'BEGIN{system(ARGV[1])}' npm publish`), key(`TOKEN=${dummy2} awk 'BEGIN{system(ARGV[1])}' npm publish`));
  for (const [a] of differ) { assert.ok(!key(a).includes(dummy), a); assert.ok(!key(a).includes(dummy2), a); }
  // nothing about the normalized action depends on the mapper's reading: it is the same as the hotfix tip's for a stopped row and for a passing one
  assert.equal(key("awk 'BEGIN{system(ARGV[1])}' ls"), key("awk 'BEGIN{system(ARGV[1])}' ls"));
  assert.deepEqual(JSON.parse(key("awk 'BEGIN{system(ARGV[1])}' ls")).programs, ['awk']);
});

test('the new reasons are receipt-safe codes and carry no command text', () => {
  const REASON = /^[a-z][a-z0-9_]{0,63}$/;
  for (const cmd of ["awk --frobnicate '{print}' f", "awk 'BEGIN{system(c)}' c='npm publish'", "awk 'BEGIN{system(ARGV[1])}' ls", "gawk -e 'BEGIN{system(\"gh release create v1\")}'"]) {
    const d = live.keyless(cmd);
    assert.equal(d.decision, 'stop', cmd);
    for (const r of d.reasons) { assert.match(r, REASON, cmd); assert.ok(!/publish|release|ARGV/i.test(r.replace(/gh_release_publish|npm_publish/, '')), r); }
  }
});

test('keyed mode is unchanged: the mapper only answers the environment-print and approval-state reads, and an awk command is never held for that by the new reasons', () => {
  for (const cmd of ["awk 'BEGIN{system(ARGV[1])}' ls", "awk '{system($0)}' cmds.txt", "awk --frobnicate '{print}' f", "awk 'BEGIN{while((getline l < ARGV[1])>0) system(l)}' cmds.txt", "awk '{print $0 | \"sh\"}' cmds.txt"]) {
    assert.equal(live.keyed(cmd), false, cmd);
  }
});

// The real keyless hook entry answers from the mapper alone: it asks no backend, so no answer from one can let a stopped form through.
test('the keyless hook entry stops the stopped forms and passes the friction rows, in a child with an empty home', () => {
  const { spawnSync } = require('node:child_process');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-awk-hook-'));
  const script = 'const { keylessSeatbelt } = require(process.argv[1] + "/dist/seatbelt/hook.js"); const out = {}; for (const command of JSON.parse(process.argv[2])) out[command] = keylessSeatbelt("claude-code", { tool_name: "Bash", tool_input: { command }, cwd: process.env.HOME }).stopText === null ? "pass" : "stop"; process.stdout.write(JSON.stringify(out));';
  const stopRows = ["awk 'BEGIN{system(ARGV[1])}' 'npm publish'", "awk -v c=ls 'BEGIN{system(c)}'", "awk 'BEGIN{system(\"git push --force origin main\")}'", "awk --frobnicate '{print}' f"];
  const passRows = ["awk '{print $1}' f", "awk '{c=\"sort\"; print | c}' f", "awk 'BEGIN{system(\"date\")}'", "awk -f script.awk data"];
  try {
    const result = spawnSync(process.execPath, ['-e', script, ROOT, JSON.stringify([...stopRows, ...passRows])], { env: { PATH: process.env.PATH, HOME: home }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const out = JSON.parse(result.stdout);
    for (const cmd of stopRows) assert.equal(out[cmd], 'stop', cmd);
    for (const cmd of passRows) assert.equal(out[cmd], 'pass', cmd);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---- patch round after the audit (aud-mcp-awk-argv, MED-1..4 and LOW-1..3) ----
// A row is a command text or [command text, files]. They are STRINGS fed to the checkers: nothing here runs a command.
const rowCmd = (r) => (typeof r === 'string' ? r : r[0]);
const rowFiles = (r) => (typeof r === 'string' ? undefined : r[1]);
const wrongRows = (rows, want) => rows.filter((r) => stops(live, rowCmd(r), rowFiles(r)) !== want).map(rowCmd);

test('MED-1: a print list is written with OFS (a space) between its words, and a printf format with a % conversion is dynamic', () => {
  assert.deepEqual(wrongRows([
    `awk 'BEGIN{print "gh", "release create v1" | "sh"}'`,
    `awk 'BEGIN{print "npm", "pub" "lish" | "sh"}'`,
    `awk 'BEGIN{print "git", "push", "--fo" "rce", "origin", "main" | "sh"}'`,
    String.raw`awk 'BEGIN{printf "%s %s\n", "gh", "release create v1" | "sh"}'`,
    String.raw`awk 'BEGIN{printf "%c%s\n", 103, "h release create v1" | "sh"}'`,
    `awk 'BEGIN{print("gh", "release create v1") | "sh"}'`,
    `awk 'BEGIN{print "gh ", "release create v1" | "sh"}'`,
    `awk 'BEGIN{print "gh", "release", "create", "v1" | "sh"}'`,
    `awk 'BEGIN{printf "gh release create v1\\n" | "sh"}'`,
    String.raw`awk 'BEGIN{printf "100%%\n" | "sh"}'`,
    // an OFS that the program or the command line sets is a separator nobody can rely on
    `awk -v OFS=- 'BEGIN{print "gh", "release create v1" | "sh"}'`,
    `awk 'BEGIN{OFS="x"; print "a", "b" | "sh"}'`,
  ], true), []);
  assert.deepEqual(wrongRows([
    // no shell sink: nothing is judged
    `awk '{print $1, $2}' f`, String.raw`awk '{printf "%d\n", NR}' f`, String.raw`awk 'BEGIN{printf "%d\n", 3}'`, `awk -v OFS=, '{print $1, $2}' f`,
    // a reader sink: the words are not run
    `awk '{print $1, $2 | "sort -k2"}' f`, String.raw`awk '{printf "%d\n", NR | "sort"}' f`, String.raw`awk '{printf "%s %s\n", $1, $2 | "sort"}' f`,
    // harmless words into a shell, and a concatenation that prints one word
    `awk 'BEGIN{print "echo", "hi" | "sh"}'`, `awk 'BEGIN{print "gh" "release create v1" | "sh"}'`,
  ], false), []);
  // a printf conversion is the dynamic-command stop, as for any other line nobody can read
  assert.ok(live.keyless(String.raw`awk 'BEGIN{printf "%s\n", "x" | "sh"}'`).reasons.includes('dynamic_awk_command'));
});

test('MED-2: the words printed into a command are judged unless the command is a known reader', () => {
  const sinks = ['busybox sh', 'busybox ash', 'mksh', 'yash', 'posh', 'nice -n 1 sh', 'setsid sh', 'script -q /dev/null', 'source /dev/stdin', 'env sh', 'command sh', 'ksh93', 'rbash',
    'sudo -n sh', 'xargs sh -c', 'dash', 'zsh -s', 'bash -s', 'sh -s', '/bin/sh', 'python3', 'perl', 'node', 'eval', 'sort | sh', 'cat | mksh', 'sort; mksh', 'cat && yash', '(posh)', '{ mksh; }',
    'unknown-reader', 'tclsh', 'lua', 'sort --compress-program=sh', 'sort --compress-prog=sh', 'sort --compr=sh', 'sort --co sh', 'sort -S 1 --com=sh', 'less +!sh', 'sort $X', 'sort `echo x`', 'LESSOPEN=x less', 'cat <<EOF', 'for i in 1; do sort; done'];
  assert.deepEqual(wrongRows(sinks.map((sink) => `awk 'BEGIN{print "gh release create v1" | ${JSON.stringify(sink)}}'`), true), []);
  const readers = ['sort', 'cat', 'tee out.txt', 'sort | uniq -c', 'wc -l', 'grep foo', 'head -n 2', 'tail -n +2', 'less', 'cat 1>&2', 'sort -t, -k2', '/usr/bin/sort', 'cut -d, -f1', 'tr a-z A-Z', 'sort -u', 'column -t',
    'grep -v "a b"', 'sort > out.txt', 'sort 2>/dev/null', 'sort --check', 'sort -T /tmp -u'];
  assert.deepEqual(wrongRows(readers.map((sink) => `awk 'BEGIN{print "gh release create v1" | ${JSON.stringify(sink)}}'`), false), []);
  // a reader that gets non-literal words stays a pass (the friction rows), while an unlisted command that gets them stops
  assert.deepEqual(wrongRows(["awk '{print $1 | \"sort -u\"}' f", "awk '{print | \"cat 1>&2\"}' f", "awk '{print $1, $2 | \"sort | uniq -c\"}' f", "awk '{print $1 | \"wc -l\"}' f", "awk '{print $0 | \"tee out.txt\"}' f"], false), []);
  assert.deepEqual(wrongRows(["awk '{print $0 | \"mail -s x u\"}' f", "awk '{print $1 | \"sort --compress-program=sh\"}' f", "awk '{print $1 | \"xargs echo\"}' f"], true), []);
  // the command that receives the words is itself judged as before
  assert.equal(stops(live, `awk 'BEGIN{print "x" | "tee ~/.marrow/hooks/x"}'`), true);
});

test('MED-3: a quoted program word that is wholly a variable, a substitution or a parameter default is code nobody can read, as for python3 -c "$P"', () => {
  const stopRows = [`awk "$P" 'gh release create v1'`, `awk "$(echo 'BEGIN{system(\\"gh release create v1\\")}')"`, `awk "\${P:-BEGIN{system(ARGV[1])}}" 'gh release create v1'`,
    `awk "$P" f`, `awk "$P"`, `awk -e "$P" f`, `gawk --source "$P" f`, `awk "\${P:-{print}}" f`, `awk "\${P:-BEGIN{x=1}}x" f`, `awk "x\${P:-BEGIN{x=1}}" f`, `awk -- "$P" f`, `awk "$P" data`];
  assert.deepEqual(wrongRows(stopRows, true), []);
  for (const cmd of stopRows) assert.deepEqual(live.keyless(cmd).reasons.filter((r) => r === 'dynamic_interpreter_code'), ['dynamic_interpreter_code'], cmd);
  // the same hit as the interpreter's own
  assert.ok(live.keyless('python3 -c "$P" x').reasons.includes('dynamic_interpreter_code'));
  assert.deepEqual(wrongRows([
    `awk -v n="$N" '{print n}' f`, `awk "NR==$N" f`, String.raw`awk "{print \$$COL}" f`, `awk -F "$SEP" '{print $1}' f`, `awk '{print $1}' "$F"`, `awk -f "$F" data`, `awk -v "$A" '{print}' f`,
    `awk $OPTS '{print}' f`, `awk -F$SEP '{print $1}' f`,
  ], false), []);
});

test('MED-4: an awk by a name the table does not know is read as awk, and keeps the unknown program\'s own argument scan', () => {
  assert.deepEqual(wrongRows([
    `C='gh release create v1' original-awk 'BEGIN{system(ENVIRON["C"])}'`, [`goawk '{system($0)}' cmds.txt`, { '/home/u/proj/cmds.txt': 'gh release create v1\n' }], `goawk 'BEGIN{system("gh release create v1")}'`,
    `original-awk 'BEGIN{system("gh release create v1")}'`, `/opt/x/bin/my-awk 'BEGIN{system(ARGV[1])}' ls`, `one-true-awk -v c=ls 'BEGIN{system(c)}'`, `frawk 'BEGIN{print ARGV[1] | "sh"}' ls`,
    `awk-5.2 --frobnicate '{print}' f`, `env goawk 'BEGIN{system("gh release create v1")}'`, `nice goawk 'BEGIN{system("gh release create v1")}'`,
  ], true), []);
  assert.deepEqual(wrongRows([`goawk '{print $1}' f`, `original-awk -F: '{print $1}' f`, `goawk 'BEGIN{system("date")}'`, `my-awk -v n=3 'NR==n' f`, `goawk -f prog.awk data`, `which goawk`, `command -v goawk`,
    `bioawk -c fastx '{print $name}' f`], false), []);
  // the CHANGELOG says what the stop covers: names with awk in them, not every unknown program
  assert.equal(stops(live, `bwk 'BEGIN{system("gh release create v1")}'`), false);
});

test('LOW-1: gawk unicode escapes are decoded; a run of five or more hex digits is read differently by awks and is a stop', () => {
  // (the backslash-u spelling is built, so that no file holds it as text)
  const BSU = String.fromCharCode(92) + 'u';
  assert.deepEqual(wrongRows([
    `gawk 'BEGIN{system("${BSU}0067h release create v1")}'`, `gawk 'BEGIN{system("${BSU}67h release create v1")}'`, `gawk 'BEGIN{system("${BSU}0067" "h release create v1")}'`,
    `gawk 'BEGIN{c="${BSU}0067h release create v1"; system(c)}'`, `gawk 'BEGIN{print "${BSU}0067h release create v1" | "sh"}'`, `gawk 'BEGIN{system("${BSU}000067h release create v1")}'`,
    `gawk 'BEGIN{system("${BSU}0067${BSU}0068 release create v1")}'`,
  ], true), []);
  assert.deepEqual(wrongRows([`gawk 'BEGIN{print "${BSU}0067h"}'`, `gawk 'BEGIN{system("${BSU}0070wd")}'`, `gawk 'BEGIN{system("${BSU}0073ort -u")}'`], false), []);
  // the decoded text is what is judged: the reason is the direct command's own
  assert.equal(live.keyless(`gawk 'BEGIN{system("${BSU}0067h release create v1")}'`).hits[0].reason, live.keyless('gh release create v1').hits[0].reason);
});

test('LOW-2: a special variable is never a literal, and --file= and --exec= name the program file', () => {
  assert.deepEqual(wrongRows([`awk 'BEGIN{FILENAME="date"; system(FILENAME)}'`, `gawk 'BEGIN{RT="date"; system(RT)}'`, `awk 'BEGIN{NR="date"; system(NR)}'`, `gawk 'BEGIN{ERRNO="date"; system(ERRNO)}'`,
    `awk 'BEGIN{FS="date"; system(FS)}'`, `awk 'BEGIN{RS="date"; print | RS}' f`], true), []);
  for (const cmd of [`awk 'BEGIN{FILENAME="date"; system(FILENAME)}'`, `gawk 'BEGIN{RT="date"; system(RT)}'`]) assert.ok(live.keyless(cmd).reasons.includes('dynamic_awk_command'), cmd);
  const RUNS = { '/home/u/proj/prog.awk': 'BEGIN{system(ARGV[1])}\n' };
  assert.deepEqual(wrongRows([[`gawk --exec=prog.awk 'npm publish'`, RUNS], [`gawk --file=prog.awk 'npm publish'`, RUNS], [`gawk --exec prog.awk 'npm publish'`, RUNS],
    [`gawk --file prog.awk 'git push --force origin main'`, RUNS], [`gawk --file=prog.awk 'wrangler deploy --prod'`, RUNS], [`gawk -E prog.awk 'npm publish'`, RUNS], [`gawk -f prog.awk 'npm publish'`, RUNS]], true), []);
  assert.deepEqual(wrongRows([[`gawk --file=prog.awk data`, { '/home/u/proj/prog.awk': '{print $1}\n' }], [`gawk --exec=prog.awk data`, { '/home/u/proj/prog.awk': '{print $1}\n' }], `gawk --file=prog.awk data`], false), []);
});

test('LOW-3: `command` looks a name up only as a leading -v or -V, for every program: friction rows are unchanged', () => {
  assert.deepEqual(wrongRows(['command npm publish -v', 'command git push -v --force origin main', 'command wrangler deploy --prod -V', 'command rm -rf ~ -v', 'command git push --force origin main -v'], true), []);
  assert.deepEqual(wrongRows(['command -v node', 'command -V git', 'command node -v', 'command npm -v', 'command -p git status', 'command grep -v foo f', 'command -p -v awk', 'command -v git push'], false), []);
  for (const cmd of ['command node -v', 'command npm -v', 'command -p git status', 'command grep -v foo f', 'command -v node']) assert.equal(live.keyed(cmd), false, cmd);
});

// ---- mutants: each new rule, switched off in a copy of the build, must let a killer row through ----
const BSU0 = String.fromCharCode(92) + 'u';
const edit = (from, to) => ({ from, to: () => to });
const MUTANTS = [
  { id: 'a command that is not literal is not a stop', edit: edit(/if \(!dynamic\)\s*return;/, 'return;'), killers: ["awk 'BEGIN{system(ENVIRON[\"C\"])}'", "awk '{system($0)}' cmds.txt", "awk -v c=ls 'BEGIN{system(c)}'"] },
  { id: 'a literal command is not judged as a nested shell', edit: edit(/(judged\.add\(text\);\s*if \(judged\.size > 96\) \{\s*dynamic = true;\s*return;\s*\})\s*evalShell\(text, childCtx\(ctx\), run\);/, 'judged.add(text); if (judged.size > 96) { dynamic = true; return; }'),
    killers: ['awk \'BEGIN{system("gh release create v1")}\'', 'awk \'BEGIN{a="gh release"; b=" create v1"; system(a b)}\''] },
  { id: 'an unknown option does not stop', edit: edit(/hit\(run, 'Sx', 'awk_unknown_option'\);/, ''), killers: ["awk --frobnicate '{print $1}' f", "gawk -Z '{print}' f"] },
  { id: 'only the first -e program is read', edit: edit(/texts\.map\(\(\[text\]\) => text\)\.join\('\\n'\)/, "texts.length ? texts[0][0] : ''"), killers: ["gawk -e 'BEGIN{x=1}' -e 'BEGIN{system(\"gh release create v1\")}'"] },
  { id: 'the pieces of a concatenation are not judged on their own', edit: edit(/if \(!slices \|\| w\.length < 2 \|\| w\.length > 6\)/, 'if (true)'), killers: ["awk 'BEGIN{ \"echo \" \"gh release create v1\" | getline x }'"] },
  { id: 'an unreadable command-line word does not make variables non-literal', edit: edit(/if \(facts\.all \|\|/, 'if ('), killers: ["awk 'BEGIN{c=\"ls\"; system(c)}' \"$F\"", "awk -v \"$ASSIGN\" 'BEGIN{c=\"ls\"; system(c)}'"] },
  { id: 'a name written from the command line stays a literal', edit: edit(/tainted: new Set\(taintedNames\), all,/, 'tainted: new Set(), all: false,'), killers: ["awk 'BEGIN{c=\"ls\"; system(c)}' c=ls /dev/null", "awk -v c=ls 'BEGIN{c=\"ls\"; system(c)}'"] },
  { id: 'a command with an unreadable part is judged as if the part were empty', edit: edit(/if \(text\.includes\(DYN\)\) \{/, 'if (false) {'), killers: ["awk \"BEGIN{system(\\\"$X\\\")}\""] },
  { id: 'words printed into a shell need not be literal', edit: edit(/!command\.every\(awkReaderSink\)/, 'false'), killers: ["awk '{print $0 | \"sh\"}' cmds.txt"] },
  { id: 'an unreadable program is not judged by name', edit: edit(/if \(unread\) \{\s*worseParse/, 'if (false) { worseParse'), killers: ["awk -f \"$F\" 'git push --force origin main'", "awk \"$P\" 'git push --force origin main'"] },
  { id: 'a program word that is a variable is not read as code', edit: edit(/if \(unreadCode\) \{\s*tripwire\(/, 'if (false) { tripwire('), killers: ["awk \"${P:-npm publish}\" f", "echo \"npm publish done\" && awk \"$P\" f"] },
  { id: 'a program or program file that is a substitution is not read', edit: edit(/const substituted = \(a\) => \{ if \(a\.word && a\.word\.substitution\)/, 'const substituted = (a) => { if (false)'), killers: ["awk -f <(echo 'BEGIN{system(\"npm publish\")}') data"] },
  { id: 'the program is read under one reading of a bracket expression only', edit: edit(/for \(const bracketAware of \[true, false\]\)/, 'for (const bracketAware of [true])'), killers: ["awk '/[/ {system(\"gh release create v1\")} /]/'"] },
  { id: 'command -v anywhere is a lookup', edit: edit(/if \(a\.text === null \|\| a\.text === '--' \|\| !a\.text\.startsWith\('-'\)\)\s*break;/, ''), killers: ["command awk -v c='npm publish' 'BEGIN{system(c)}'", 'command git push --force origin main -v'] },
  { id: 'the word the older reading took as the program is not judged', edit: edit(/if \(older\)/, 'if (false)'), killers: ["awk -f prog.awk 'BEGIN{system(\"gh release create v1\")}'", "awk -- -e 'BEGIN{system(\"gh release create v1\")}'"] },
  { id: 'an indirect call is not a command', edit: edit(/if \(facts\.indirect\)/, 'if (false)'), killers: ["awk 'BEGIN{@f(\"ls\")}'"] },
  { id: 'a program that cannot be cut into tokens is not a stop', edit: edit(/if \(tokens === null\) \{\s*dynamic = true;/, 'if (tokens === null) { dynamic = false;'), killers: ["awk 'BEGIN{ system(\"ls) }'"] },
  // ---- the patch round (aud-mcp-awk-argv): each of the seven changes switched off on its own, and the audit's m05 and m18 ----
  { id: 'MED-1: a print list is not read with OFS between its words', edit: edit(/judge\(awkJoin\(spaced, 0, spaced\.length\)\);/, ''), killers: [`awk 'BEGIN{print "gh", "release create v1" | "sh"}'`, `awk 'BEGIN{print "git", "push", "--fo" "rce", "origin", "main" | "sh"}'`] },
  { id: 'MED-1: a printf format with a % conversion is not dynamic', edit: edit(/format\.some\(\(f\) => f\.includes\('%'\)\)/, 'false'), killers: [String.raw`awk 'BEGIN{printf "%s %s\n", "gh", "release create v1" | "sh"}'`, String.raw`awk 'BEGIN{printf "%c%s\n", 103, "h release create v1" | "sh"}'`] },
  { id: 'MED-1: an OFS the program sets is taken for a space', edit: edit(/facts\.all \|\| facts\.tainted\.has\('OFS'\) \|\| facts\.assigns\.has\('OFS'\)/, 'false'), killers: [`awk 'BEGIN{OFS="x"; print "a", "b" | "sh"}'`] },
  { id: 'MED-2: only the shells the old list knew are judged', edit: edit(/!command\.every\(awkReaderSink\)/, 'command.some((c) => /^(?:sh|bash|dash|zsh|ksh|ash)\\b/.test(c))'), killers: [`awk 'BEGIN{print "gh release create v1" | "mksh"}'`, `awk 'BEGIN{print "gh release create v1" | "busybox sh"}'`, `awk 'BEGIN{print "gh release create v1" | "nice -n 1 sh"}'`, `awk 'BEGIN{print "gh release create v1" | "source /dev/stdin"}'`] },
  { id: 'MED-2: every command is a known reader', edit: edit(/function awkReaderSink\(text\) \{/, 'function awkReaderSink(text) { return true;'), killers: [`awk 'BEGIN{print "gh release create v1" | "yash"}'`, `awk 'BEGIN{print "gh release create v1" | "posh"}'`] },
  { id: 'MED-2: a reader that runs a program of its own is still a reader', edit: edit(/\/compress-program\/\.test\(w\.text\) \|\| \(m\[1\] === 'sort' && w\.text\.startsWith\('--co'\)\) \|\| /, ''), killers: [`awk 'BEGIN{print "gh release create v1" | "sort --compress-program=sh"}'`] },
  { id: 'MED-2: the compress-program word is a stop for any reader', edit: edit(/\/compress-program\/\.test\(w\.text\) \|\| /, ''), killers: [`awk 'BEGIN{print "gh release create v1" | "cat --compress-program=sh"}'`] },
  { id: 'MED-2: sort --compr=PROG (a prefix of the long option) is still a reader', edit: edit(/\(m\[1\] === 'sort' && w\.text\.startsWith\('--co'\)\) \|\| /, ''), killers: [`awk 'BEGIN{print "gh release create v1" | "sort --compr=sh"}'`, `awk 'BEGIN{print "gh release create v1" | "sort --co sh"}'`, `awk 'BEGIN{print "gh release create v1" | "sort -S 1 --com=sh"}'`] },
  { id: 'MED-2: a reader with an option that runs a command (less +!CMD) is still a reader', edit: edit(/\(m\[1\] === 'less' \|\| m\[1\] === 'more'\) && w\.text\.startsWith\('\+'\)/, 'false'), killers: [`awk 'BEGIN{print "gh release create v1" | "less +!sh"}'`] },
  { id: 'MED-3: a quoted variable program is not a stop', edit: edit(/if \(unreadHit\)\s*hit\(run, 'Sx', 'dynamic_interpreter_code'\);/, ''), killers: [`awk "$P" 'gh release create v1'`, `awk "$(echo 'BEGIN{system(\\"gh release create v1\\")}')"`] },
  { id: 'MED-3: a parameter default that holds braces is read as text', edit: edit(/if \(depth === 0\)\s*return true;/, 'if (depth === 0) return false;'), killers: [`awk "\${P:-BEGIN{system(ARGV[1])}}" 'gh release create v1'`, `awk "\${P:-{print}}" f`] },
  { id: 'MED-3: an -e or --source program that is a variable is not code nobody can read', edit: edit(/(?<=`awk -e "\$P"`[^\n]*\n\s*)if \(awkUnreadable\(a\)\)/, 'if (false)'), killers: [`awk -e "$P" f`, `gawk --source "$P" f`] },
  { id: 'MED-4: an awk by a name the table does not know is not read as awk', edit: edit(/if \(\/awk\/i\.test\(prog\)\)/, 'if (false)'), killers: [`goawk 'BEGIN{system("gh release create v1")}'`, `C='gh release create v1' original-awk 'BEGIN{system(ENVIRON["C"])}'`, `original-awk 'BEGIN{system("gh release create v1")}'`] },
  { id: 'LOW-1: a unicode escape is not decoded', edit: edit(/else if \(e === 'u' && \/\^\[0-9a-fA-F\]\/\.test\(src\.slice\(j, j \+ 1\)\)\)/, 'else if (false)'), killers: [`gawk 'BEGIN{system("${BSU0}0067h release create v1")}'`, `gawk 'BEGIN{system("${BSU0}0067${BSU0}0068 release create v1")}'`] },
  { id: 'LOW-1: a unicode escape with more than four digits is read as four', edit: edit(/digits\.length <= 4 \? String\.fromCharCode\(parseInt\(digits, 16\)\) : DYN/, 'String.fromCharCode(parseInt(digits.slice(0, 4), 16))'), killers: [`gawk 'BEGIN{system("${BSU0}000067h release create v1")}'`] },
  { id: 'm05: special variables such as RT and FILENAME are literals', edit: edit(/AWK_SPECIAL_VARS\.has\(name\) \|\| /, ''), killers: [`awk 'BEGIN{FILENAME="date"; system(FILENAME)}'`, `gawk 'BEGIN{RT="date"; system(RT)}'`, `awk 'BEGIN{NR="date"; system(NR)}'`] },
  { id: 'm18: --file= and --exec= long options are ignored', edit: edit(/if \(name === 'file' \|\| name === 'exec'\)/, 'if (false)'),
    killers: [[`gawk --exec=prog.awk 'npm publish'`, { '/home/u/proj/prog.awk': 'BEGIN{system(ARGV[1])}\n' }], [`gawk --file=prog.awk 'npm publish'`, { '/home/u/proj/prog.awk': 'BEGIN{system(ARGV[1])}\n' }], [`gawk --file prog.awk 'git push --force origin main'`, { '/home/u/proj/prog.awk': 'BEGIN{system(ARGV[1])}\n' }]] },
  { id: 'LOW-3: command -v anywhere is a lookup, for every program', edit: edit(/if \(a\.text === null \|\| a\.text === '--' \|\| !a\.text\.startsWith\('-'\)\)\s*break;/, ''), killers: ['command npm publish -v', 'command git push -v --force origin main', 'command wrangler deploy --prod -V'] },
];

function mutantBuild(edit) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-awk-mutant-'));
  fs.cpSync(path.join(ROOT, 'dist'), path.join(dir, 'dist'), { recursive: true });
  fs.symlinkSync(path.join(ROOT, 'vendor'), path.join(dir, 'vendor'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'));
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(dir, 'package.json'));
  const target = path.join(dir, 'dist', 'seatbelt/mapper.js');
  const before = fs.readFileSync(target, 'utf8');
  const after = before.replace(edit.from, edit.to);
  assert.notEqual(after, before, 'the mutant edit found its text in the build');
  fs.writeFileSync(target, after);
  return dir;
}

for (const mutant of MUTANTS) {
  test(`mutant killed: ${mutant.id}`, () => {
    for (const row of mutant.killers) assert.equal(stops(live, rowCmd(row), rowFiles(row)), true, `${rowCmd(row)} keyless`);
    const dir = mutantBuild(mutant.edit);
    try {
      const mutated = checkersFor(dir);
      const survived = mutant.killers.filter((row) => stops(mutated, rowCmd(row), rowFiles(row)));
      assert.ok(survived.length < mutant.killers.length, `no killer row noticed the mutant: ${mutant.id}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
