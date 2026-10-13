'use strict';

// Regression tests for the seatbelt pre-pass that classifies the substitutions the vendored parser does
// not list (job bc-mcp-sb-heredoc; finding r4 §6 and §13): the body of an UNQUOTED here-document,
// parameter-expansion operands (`${v:-$(…)}`), arithmetic expansion, and the stdin script of a shell or
// interpreter. Every STOP row passes the S0-S5 mapper on 75509fd8. Dummy values only.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const F = { current: 'feat/x' };
const sh = (cmd, opts) => evaluateSeatbeltShell(cmd, makeEnv(opts || F));
const stops = (cmd, opts) => assert.equal(sh(cmd, opts).decision, 'stop', cmd);
const passes = (cmd, opts) => assert.equal(sh(cmd, opts).decision, 'pass', `${cmd} [${sh(cmd, opts).reasons.join(',')}]`);
const T = '\t';

// ---------------------------------------------------------------------------------------------
// Spec 2: commands in an unquoted here-document body are executed commands.

test('heredoc: the r4 repros stop (substitution and backtick forms)', () => {
  for (const cmd of [
    'cat <<EOF\n$(npm publish)\nEOF',
    'cat <<EOF\n$(rm -rf /home/u)\nEOF',
    'cat <<EOF\n`rm -rf /home/u`\nEOF',
    'cat <<EOF\n$(git push -f origin main)\nEOF',
    'cat <<EOF\n$(git push --force origin main)\nEOF',
    'cat <<EOF\n`git push --force origin main`\nEOF',
    'cat <<EOF\n$(cat ~/.aws/credentials)\nEOF',
    'cat <<EOF\ntext before $(npm publish) text after\nEOF',
    'cat <<EOF\nline one\nline two\n$(npm publish)\nEOF',
    'cat <<EOF > out.txt\n$(npm publish)\nEOF',
    'cat > out.txt <<EOF\nhello ${USER}\n$(npm publish)\nEOF',
    'cat <<EOF | tee out.txt\n$(npm publish)\nEOF',
    'grep x <<EOF\n$(npm publish)\nEOF',
    'x=$(cat <<EOF\n$(npm publish)\nEOF\n)',
  ]) stops(cmd);
});

test('heredoc: <<-EOF with tabs, several here-documents on one line, nesting in other constructs', () => {
  for (const cmd of [
    `cat <<-EOF\n${T}${T}$(npm publish)\n${T}EOF`,
    'cat <<A; cat <<B\nhello\nA\n$(npm publish)\nB',
    'cat <<A <<B\nhello\nA\n$(npm publish)\nB',
    'cat <<A <<"B"\n$(npm publish)\nA\nhello\nB',
    'cat <<A\nhello\nA\ncat <<B\n$(npm publish)\nB',
    "bash -c 'cat <<EOF\n$(npm publish)\nEOF'",
    'f() { cat <<EOF\n$(npm publish)\nEOF\n}; f',
    'if true; then cat <<EOF\n$(npm publish)\nEOF\nfi',
    'for i in 1 2; do cat <<EOF\n$(npm publish)\nEOF\ndone',
    'true && cat <<EOF\n$(npm publish)\nEOF',
    'false || cat <<EOF\n$(npm publish)\nEOF',
    '(cat <<EOF\n$(npm publish)\nEOF\n)',
    '{ cat <<EOF\n$(npm publish)\nEOF\n}',
    'echo x | cat <<EOF\n$(npm publish)\nEOF',
    'ls && cat <<EOF >out; echo done\nbody $(npm publish)\nEOF',
    'cat <<EOF\n${y:-$(npm publish)}\nEOF',
    'cat <<EOF\n${y:-`npm publish`}\nEOF',
    'cat <<EOF\n$(( $(npm publish) ))\nEOF',
    'cat <<EOF\ntext "quoted $(npm publish)\nEOF',
    "cat <<EOF\n'$(npm publish)'\nEOF",
  ]) stops(cmd);
});

test('heredoc: decoded execution inside a body (S-x) stops', () => {
  stops('cat <<EOF\n$(echo aGk= | base64 -d | sh)\nEOF');
  stops('bash <<EOF\n$(echo bnBtIHB1Ymxpc2g= | base64 -d)\nEOF');
  stops('cat <<EOF | sh\n$(echo bnBtIHB1Ymxpc2g= | base64 -d)\nEOF');
});

test('heredoc: production-labelled and secret commands in a body stop, whatever surrounds them', () => {
  for (const cmd of [
    'cat <<EOF\n$(wrangler pages deploy dist --branch main)\nEOF',
    'cat <<EOF\n$(wrangler pages deploy dist --branch preview --branch main)\nEOF',
    'cat <<EOF\n$(git push origin "$(git branch --show-current)" --force)\nEOF',
    'cat <<EOF\n$(printenv)\nEOF',
    'cat <<EOF\n$(rm -rf ~/)\nEOF',
    'cat <<EOF\n$(vercel --prod)\nEOF',
    'cat <<EOF\n$(echo hi; npm publish)\nEOF',
    'cat <<EOF\n$(true && npm publish)\nEOF',
    'cat <<EOF\n$(bash -c "npm publish")\nEOF',
  ]) stops(cmd);
});

// ---------------------------------------------------------------------------------------------
// Spec 3: the stdin script of a shell or interpreter is code, quoted or not.

test('stdin script: a quoted or unquoted here-document or here-string fed to a shell or interpreter is code', () => {
  for (const cmd of [
    "bash <<'EOF'\nrm -rf ~/\nEOF",
    'bash <<EOF\nnpm publish\nEOF',
    "bash -s <<'EOF'\nnpm publish\nEOF",
    'bash -s <<EOF\nnpm publish\nEOF',
    'sh <<EOF\nnpm publish\nEOF',
    "zsh <<'EOF'\nnpm publish\nEOF",
    "sudo bash <<'EOF'\nrm -rf ~/\nEOF",
    "env X=1 bash <<'EOF'\nnpm publish\nEOF",
    "cat <<'EOF' | bash\nnpm publish\nEOF",
    "python - <<EOF\nimport shutil\nshutil.rmtree('/etc')\nEOF",
    "python3 <<'EOF'\nimport shutil\nshutil.rmtree('/etc')\nEOF",
    "node - <<'EOF'\nrequire('fs').rmSync('/etc',{recursive:true})\nEOF",
    "node <<'EOF'\nrequire('fs').rmSync('/etc',{recursive:true})\nEOF",
    "perl <<'EOF'\nsystem('npm publish');\nEOF",
    "ruby <<'EOF'\nsystem('npm publish')\nEOF",
    'bash <<< "npm publish"',
    "sh <<< 'npm publish'",
    'sh <<< "$(echo npm publish)"',
    'bash <<< "$(npm publish)"',
    "ssh host <<'EOF'\nrm -rf /srv\nEOF",
    'ssh host <<EOF\nrm -rf /srv\nEOF',
    'ssh host <<< "rm -rf /srv"',
    'bash <<EOF\n$(npm publish)\nEOF',
  ]) stops(cmd);
});

// ---------------------------------------------------------------------------------------------
// Spec 4: operands of a parameter expansion.

test('operands: ${v:-W} ${v-W} ${v:=W} ${v:+W} ${v:?W}, nested, backticks, inside double quotes', () => {
  for (const cmd of [
    'x=${y:-$(npm publish)}',
    'x=${y-$(npm publish)}',
    ': ${X:=$(git push -f origin main)}',
    ': ${X:=$(git push --force origin main)}',
    'echo ${y:+$(npm publish)}',
    'echo ${y:?$(npm publish)}',
    'x=${y:-`npm publish`}',
    ': ${y:-`npm publish`}',
    'echo ${x:-$(printenv)}',
    ': ${a:-${b:-$(npm publish)}}',
    ': ${a:-${b:-${c:-$(npm publish)}}}',
    'echo "${y:-$(npm publish)}"',
    'echo ${y:-"$(npm publish)"}',
    'echo "${y:-"$(npm publish)"}"',
    'echo ${y:-$(echo ${z:-$(npm publish)})}',
    'for i in ${y:-$(npm publish)}; do :; done',
    'f() { echo ${y:-$(npm publish)}; }; f',
    'bash -c \'echo ${y:-$(npm publish)}\'',
    'true && x=${y:-$(git push -f origin main)}',
    'x=${y:-$(echo aGk= | base64 -d | sh)}',
    'x=${y:-$(echo bnBtIHB1Ymxpc2g= | base64 -d)}; eval "$x"',
    'echo ${y/$(npm publish)/z}',
    'echo ${y:$(npm publish)}',
    'echo $(( 1 + ${y:-$(npm publish)} ))',
    'echo ${y:-$(cat ~/.aws/credentials)}',
    'echo ${y:-$(rm -rf /home/u)}',
  ]) stops(cmd);
});

test('arithmetic: a substitution inside $(( … )) and a subshell the parser reads as arithmetic', () => {
  for (const cmd of [
    'echo $(( $(npm publish) + 1 ))',
    'echo $(( `npm publish` + 1 ))',
    'echo $((npm publish); echo x)',
    'i=$(( $(git push -f origin main) ))',
  ]) stops(cmd);
});

// ---------------------------------------------------------------------------------------------
// Spec 5: what the pre-pass cannot bound is dynamic and follows the unparsed rule.

test('unbounded: unterminated, built delimiter, over 8 KB, too deep, desynchronised text follow the unparsed rule', () => {
  const big = 'x'.repeat(9000);
  const deep = '${a:-${b:-${c:-${d:-$(npm publish)}}}}';
  const cases = [
    // [command, stops?]
    ['cat <<EOF\n$(npm publish)\n', true],
    ['cat <<EOF\n$(npm publish)', true],
    ['cat <<$X\n$(npm publish)\n$X', true],
    ['cat <<`echo EOF`\n$(npm publish)\nEOF', true],
    [`cat <<EOF\n${big}\n$(npm publish)\nEOF`, true],
    [`echo ${deep}`, true],
    ["echo ${x:-'}'} ; npm publish # it's", true],
    ['echo ${x:-"}"} ; npm publish', true],
    ['x=$(cat <<E\nEO\\\nF); npm publish\nE\n)', true],
    ['echo $(( 1 + $(( 2 + $(( 3 + $(( 4 + $(npm publish) )) )) )) ))', true],
    // the same shapes without a trigger token pass, with parse=unparsed (the deliberate §2.1.3 trade)
    ['cat <<EOF\n$(date)\n', false],
    ['cat <<$X\n$(date)\n$X', false],
    [`cat <<EOF\n${big}\n$(date)\nEOF`, false],
    ['echo ${a:-${b:-${c:-${d:-$(date)}}}}', false],
  ];
  for (const [cmd, stop] of cases) {
    const d = sh(cmd);
    assert.equal(d.decision, stop ? 'stop' : 'pass', `${cmd.slice(0, 60)} [${d.reasons.join(',')}]`);
    assert.equal(d.parse, 'unparsed', `${cmd.slice(0, 60)} parse=${d.parse}`);
  }
});

test('unbounded: a body line that bash joins to the next one cannot make the delimiter vanish for the parser', () => {
  for (const cmd of [
    // bash joins `EO\` + `F` into the delimiter: the heredoc ends there and `npm publish` runs
    'cat <<EOF\nEO\\\nF\nnpm publish\nEOF',
    `cat <<-EOF\n${T}EO\\\nF\nnpm publish\nEOF`,
    // the delimiter line is joined to the line before it: bash reads on, the `$( )` below is body
    `cat <<-E\n${T}E\\\n${T}E\n$(npm publish)\nE`,
    // bash reads on to the next `E` line, so the quoted here-document below is part of this body and its `$( )` runs
    `cat <<-E\n${T}E\\\n${T}E\nx\nE; cat <<'F'\n$(npm publish)\nF`,
    'cat <<E\nx\\\nE\n$(npm publish)\nE',
    // inside a substitution a line `E)` ends the body and the substitution
    'x=$(cat <<E\nhello\nE)\nnpm publish',
    'cat <<E\nE)\nnpm publish',
    'x=$(cat <<E\nEO\\\nF); npm publish\nE\n)',
    'x=`cat <<E\nEO\\\nF`; npm publish',
  ]) stops(cmd);
  // a joined line that is only data stays data
  passes('cat <<EOF\nrun it with\\\n  --flag\nEOF');
  passes('cat <<E\nEO\\\nF\nnpm test\nE');
});

// ---------------------------------------------------------------------------------------------
// Spec 6: data stays data.

test('data: quoted here-documents fed to a non-shell, plain bodies and plain defaults pass', () => {
  for (const cmd of [
    "git commit -F- <<'EOF'\nfix: mention npm publish in docs\nEOF",
    "git commit -F- <<'EOF'\nfix: docs\n\n$(npm publish)\nEOF",
    "cat <<'EOF' > notes.md\n$(npm publish)\nEOF",
    "cat <<'EOF' > notes.md\n${y:-$(npm publish)}\nEOF",
    'cat <<\\EOF\n$(npm publish)\nEOF',
    'cat <<"EOF"\n$(npm publish)\nEOF',
    'cat <<EOF\nhello $USER and ${HOME}\nEOF',
    'cat <<EOF\nplain text only\nEOF',
    'cat <<EOF\n\\$(npm publish)\nEOF',
    'cat <<EOF\n\\`npm publish\\`\nEOF',
    "cat <<EOF\ntext with 'single quotes' and \"double quotes\"\nEOF",
    'cat <<EOF\n$(date) $(pwd) `hostname`\nEOF',
    'cat <<EOF\nrun it with\\\n  --flag\nEOF',
    'echo ${VAR:-default}',
    'echo ${VAR:-$(pwd)}',
    'x=${y:-$(date)}',
    'echo "${y:-$(git rev-parse --short HEAD)}"',
    'echo ${#v} ${v%x} ${v##*/} ${v/a/b} ${v^^}',
    'echo ${HOME}/bin ${PATH}',
    'echo $((i+1))',
    'i=1; echo $((i+1))',
    'echo $((1+2)) $(( (3+4)*2 ))',
    "echo '${y:-$(npm publish)}'",
    "cat <<<'${y:-$(npm publish)}'",
    'echo hi # ${y:-$(npm publish)}',
    "python3 - <<'EOF'\nprint(1)\nEOF",
    "bash <<'EOF'\nls\nEOF",
    "ssh host <<'EOF'\nls /srv\nEOF",
    'mapfile -t c <<< "npm publish"; echo "${c[@]}"',
    // misleading words are words
    'cat <<EOF\n$(echo "do not npm publish")\nEOF',
    'cat <<EOF\n$(ls publish deploy)\nEOF',
    'echo ${y:-"npm publish"}',
    'git commit -m "docs: npm publish steps" && cat <<EOF\n$(date)\nEOF',
  ]) passes(cmd);
});

test('data: a pure expansion or a here-document without $ or a backtick keeps the parse label it had', () => {
  // `parse` is a receipt field (U6): the labels of the vendored parser stay for text the pre-pass has nothing to say about.
  for (const [cmd, parse] of [
    ['echo ${VAR:-default}', 'dynamic'],
    ['echo ${HOME}', 'dynamic'],
    ['cat <<EOF\nplain\nEOF', 'ok'],
    ["cat <<'EOF'\n$(date)\nEOF", 'ok'],
    ['git commit -F- <<\'EOF\'\nfix: docs\nEOF', 'ok'],
  ]) {
    const d = sh(cmd);
    assert.equal(d.decision, 'pass', cmd);
    assert.equal(d.parse, parse, `${cmd} parse=${d.parse}`);
  }
});

test('data: a here-document or operand the pre-pass bounds is dynamic, never unparsed (no tripwire cost)', () => {
  for (const [cmd, parse] of [
    [`cat <<-EOF\n${T}$(date)\n${T}EOF`, 'dynamic'],
    ['cat <<EOF\nhello $(date)\nEOF', 'dynamic'],
    ['cat <<A <<B\n$(date)\nA\n`pwd`\nB', 'dynamic'],
    ['cat <<A; cat <<B\nx\nA\n$(date)\nB', 'dynamic'],
    ['echo ${a:-${b:-$(date)}}', 'dynamic'],
    ['echo $(( 1 + $(date +%s) ))', 'dynamic'],
    ['cat <<EOF\n${y:-`hostname`}\nEOF\nnpm test', 'dynamic'],
  ]) {
    const d = sh(cmd);
    assert.equal(d.decision, 'pass', `${cmd} [${d.reasons.join(',')}]`);
    assert.equal(d.parse, parse, `${cmd} parse=${d.parse}`);
  }
});

// ---------------------------------------------------------------------------------------------
// Never looser than the same command at top level (production labels, repeated flags, variables,
// unknown flags, chaining): whatever stops on its own stops inside every carrier the parser hides.

test('carriers: a command that stops at top level stops inside every hidden carrier', () => {
  const dangerous = [
    'npm publish', 'git push -f origin main', 'git push --force origin release/1.2', 'git push origin main --delete',
    'git push origin $BR --force', 'git push origin "$(git branch --show-current)" -f', 'git push +HEAD:main origin',
    'rm -rf /home/u', 'rm -rf ~/', 'cat ~/.aws/credentials', 'printenv', 'echo $OPENAI_API_KEY',
    'wrangler pages deploy dist --branch main', 'wrangler pages deploy dist --branch preview --branch main',
    'wrangler deploy --env production', 'wrangler deploy --no-such-flag', 'wrangler pages deploy dist --branch "$B"',
    'vercel --prod', 'npx @getmarrow/install control disable --yes', 'echo aGk= | base64 -d | sh',
    'terraform apply -auto-approve', 'gh release create v1', 'cat .env',
    'echo "update docs"; npm publish', 'true && git push -f origin main', 'ls | xargs rm -rf',
    "bash -c 'npm publish'", 'sh -c "git push --force origin main"',
  ];
  const carriers = {
    body: (x) => `cat <<EOF\n$(${x})\nEOF`,
    bodyTicks: (x) => `cat <<EOF\n\`${x}\`\nEOF`,
    bodyDash: (x) => `cat <<-EOF\n${T}$(${x})\n${T}EOF`,
    second: (x) => `cat <<A <<B\nhello\nA\n$(${x})\nB`,
    default: (x) => `y=\${z:-$(${x})}`,
    defaultTicks: (x) => `echo \${z:-\`${x}\`}`,
    assign: (x) => `: \${z:=$(${x})}`,
    nested: (x) => `: \${a:-\${b:-$(${x})}}`,
    arith: (x) => `echo $(( $(${x}) ))`,
    chained: (x) => `ls && cat <<EOF\n$(${x})\nEOF`,
    piped: (x) => `echo hi | cat <<EOF\n$(${x})\nEOF`,
    group: (x) => `( cat <<EOF\n$(${x})\nEOF\n)`,
    fn: (x) => `f() { y=\${z:-$(${x})}; }; f`,
    loop: (x) => `for i in 1 2; do cat <<EOF\n$(${x})\nEOF\ndone`,
    inBashC: (x) => (x.includes("'") ? null : `bash -c 'echo \${z:-$(${x})}'`),
    stdinShell: (x) => `bash <<'EOF'\n${x}\nEOF`,
    hereString: (x) => (x.includes('"') ? null : `sh <<< "${x}"`),
  };
  let n = 0;
  for (const x of dangerous) {
    if (sh(x).decision !== 'stop') continue;
    for (const [name, wrap] of Object.entries(carriers)) {
      const cmd = wrap(x);
      if (cmd === null) continue;
      n += 1;
      assert.equal(sh(cmd).decision, 'stop', `${name}: ${JSON.stringify(cmd)}`);
    }
  }
  assert.ok(n >= 250, `only ${n} carrier rows ran`);
});

test('carriers: everyday commands keep passing inside the same carriers (no new everyday stops)', () => {
  const benign = ['date', 'pwd', 'git status', 'ls -la', 'whoami', 'echo hi', 'cat README.md', 'git rev-parse --short HEAD', 'hostname', 'basename "$PWD"', 'git branch --show-current', 'npm test', 'npm run build'];
  const carriers = {
    body: (x) => `cat <<EOF\nhello $(${x})\nEOF`,
    bodyTicks: (x) => `cat <<EOF\n\`${x}\`\nEOF`,
    bodyFile: (x) => `cat > notes.md <<EOF\nrun: $(${x})\nEOF`,
    default: (x) => `y=\${z:-$(${x})}`,
    defaultQuoted: (x) => `echo "\${z:-$(${x})}"`,
    nested: (x) => `: \${a:-\${b:-$(${x})}}`,
    arith: (x) => `echo $(( $(${x} | wc -l) + 1 ))`,
  };
  for (const x of benign) {
    assert.equal(sh(x).decision, 'pass', x);
    for (const [name, wrap] of Object.entries(carriers)) passes(wrap(x));
  }
});

test('residual (documented): a value that only a later command runs is data until that command runs', () => {
  // `mapfile` stores the text; the use that runs it is what stops.
  passes('mapfile -t c <<< "npm publish"; echo "${c[@]}"');
  stops('mapfile -t c <<< "npm publish"; "${c[@]}"');
  stops('mapfile -t c <<< "npm publish"; eval "${c[@]}"');
});

// ---------------------------------------------------------------------------------------------
// Consumers: a verdict never carries the text of the command or a secret.

test('verdicts do not carry command text: a dummy key in a hidden command stays out of the result', () => {
  const dummy = `dummykey_${crypto.randomBytes(12).toString('hex')}`;
  for (const cmd of [
    `cat <<EOF\n$(npm publish --token ${dummy})\nEOF`,
    `x=\${y:-$(npm publish --token ${dummy})}`,
    `cat <<EOF\n$(git push -f https://user:${dummy}@example.invalid/r.git main)\nEOF`,
  ]) {
    const d = sh(cmd);
    assert.equal(d.decision, 'stop', cmd.replace(dummy, '<dummy>'));
    assert.equal(JSON.stringify(d).includes(dummy), false);
  }
});

test('determinism and the same verdict for the same text; a different hidden command gives a different reason', () => {
  const a = sh('cat <<EOF\n$(npm publish)\nEOF');
  const b = sh('cat <<EOF\n$(npm publish)\nEOF');
  assert.deepEqual(a, b);
  const c = sh('cat <<EOF\n$(git push -f origin main)\nEOF');
  assert.notDeepEqual(a.reasons, c.reasons);
  assert.equal(sh('cat <<EOF\n$(date)\nEOF').decision, 'pass');
});

test('the pre-pass is fast on hostile input (a 300 ms budget for a command)', () => {
  const texts = [
    `cat <<EOF\n${'$(date) '.repeat(1000)}\nEOF`,
    `echo ${'${a:-'.repeat(200)}x${'}'.repeat(200)}`,
    `${'cat <<EOF\n$(date)\nEOF\n'.repeat(300)}`,
    `echo ${'$(( '.repeat(50)}1${' ))'.repeat(50)}`,
    `cat <<EOF\n${'\\\n'.repeat(2000)}EOF`,
  ];
  for (const text of texts) {
    const t0 = process.hrtime.bigint();
    sh(text);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 300, `${ms.toFixed(1)} ms for ${text.slice(0, 40)}`);
  }
});
