const assert = require('node:assert/strict');
const { chmodSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');

// MCP-1a (spec friction r3 §4.2, §4.3 T1, §4.7 A1-A51, §4.8 K1-1..7): the data-write recognizer and the data-file-never-runs tightening.
// Abuse rows carry the risky words "deploy production wrangler" in their payload on purpose: the 3.9.108 words path protects every one of
// them, so a recognizer that wrongly admitted a row would flip `protected` to false and fail it.

const root = mkdtempSync(join(tmpdir(), 'marrow-dw-'));
const ws = join(root, 'ws');
const elsewhere = join(root, 'elsewhere');
mkdirSync(ws, { recursive: true });
mkdirSync(elsewhere, { recursive: true });
writeFileSync(join(ws, 'existing.md'), 'old\n');
writeFileSync(join(ws, 'appendable.md'), 'old\n');
writeFileSync(join(ws, 'CLAUDE.md'), 'old\n');
writeFileSync(join(ws, 'exec.md'), 'old\n');
chmodSync(join(ws, 'exec.md'), 0o755);
writeFileSync(join(elsewhere, 'sensitive.md'), 'x\n');
symlinkSync(join(elsewhere, 'sensitive.md'), join(ws, 'link.md'));
linkSync(join(elsewhere, 'sensitive.md'), join(ws, 'hard.md'));
mkdirSync(join(ws, '.hidden'));
mkdirSync(join(ws, 'sub'));
symlinkSync(elsewhere, join(ws, 'linkdir'));
test.after(() => rmSync(root, { recursive: true, force: true }));

const DW_LABEL = 'classified Bash action: process on workspace';
const bash = (command, extra = {}) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: ws, ...extra });
const isDw = (command, extra) => {
  const result = bash(command, extra);
  return result.protected === false && result.action === DW_LABEL && result.readOnly === false;
};

const ADMITTED = [
  ['R-F1 heredoc append + date echo', `R=${ws}\ncat >> $R/DOGFOOD-FINDINGS.md <<'EOF'\nStatus 409 install key variables "Security Weaken" deploy production\nEOF\necho "$(date -u +%Y-%m-%dT%H:%MZ) wrangler deploy done" >> $R/OVERNIGHT-LOG.md; echo ok`],
  ['R-F2 two echo appends naming /proc/<pid>/environ', `echo "reads /proc/123/environ and deploy production" >> ${ws}/a.md; echo "$(date -u +%s) key token" >> ${ws}/b.log`],
  ['R-29a echo segment alone', `echo "$(date -u +%FT%TZ) board note: deploy production wrangler" >> ${ws}/board-notes.md`],
  ['relative target in the event cwd', 'echo "deploy production" >> notes.md'],
  ['printf with a format and arguments', `printf '%s %s\\n' deploy production >> ${ws}/p.txt`],
  ['tee -a from a pipe', `echo "deploy production" | tee -a ${ws}/t.md`],
  ['tee -a -a repeated (A50)', `echo "deploy production" | tee -a -a ${ws}/t2.md`],
  ['echo repeated flags (A49)', `echo -n -e -n "deploy production" >> ${ws}/f.md`],
  ['note named production deploys nothing (A43)', `echo x >> ${ws}/production-deploy.md`],
  ['comment is not executed (A31)', `echo x >> ${ws}/c.md # ; wrangler deploy`],
  ['append to an existing note', `echo "deploy production" >> ${ws}/appendable.md`],
  ['truncate of an absent file', `echo "deploy production" > ${ws}/fresh.md`],
  ['unquoted heredoc without expansion', `cat >> ${ws}/h.md <<EOF\nplain deploy production text\nEOF`],
  ['heredoc with tab-stripped delimiter', `cat >> ${ws}/h2.md <<-'EOF'\n\tdeploy production\n\tEOF`],
  ['/dev/null and descriptor duplication', `echo "deploy production" >> ${ws}/d.md 2>&1 >/dev/null`],
];

for (const [id, command] of ADMITTED) {
  test(`MCP-1a admitted: ${id}`, () => {
    assert.equal(isDw(command), true, JSON.stringify(bash(command)));
  });
}

test('MCP-1a admitted rows are never read-only and carry no secrets surface', () => {
  const result = bash(`echo "k=1 deploy production" >> ${ws}/q.md`);
  assert.deepEqual([result.protected, result.readOnly, result.surfaces, result.type, result.risk], [false, false, ['workspace'], 'process', 'medium']);
});

test('MCP-1a label is fixed text: the payload never reaches it (K1-1, K1-4)', () => {
  const a = bash(`echo "deploy prod" >> ${ws}/a.md`);
  const b = bash(`echo "note" >> ${ws}/a.md`);
  assert.equal(a.action, b.action);
  assert.equal(a.action, DW_LABEL);
  assert.doesNotMatch(JSON.stringify(a), /deploy prod/);
});

const HELD = [
  ['A1 && wrangler', `echo "deploy" >> ${ws}/n.md && wrangler deploy`],
  ['A2 ; npx wrangler production', `echo x >> ${ws}/n.md; npx wrangler deploy --env production`],
  ['A3 || git push', `echo x >> ${ws}/n.md || git push origin master`],
  ['A4 pipe to bash', 'echo "wrangler deploy" | bash'],
  ['A5 command substitution', `echo "$(wrangler deploy)" >> ${ws}/n.md`],
  ['A6 backtick', `echo "\`wrangler deploy\`" >> ${ws}/n.md`],
  ['A7 bash -c', `bash -c "echo x >> ${ws}/n.md; wrangler deploy"`],
  ['A8 unquoted delimiter with $ body', `cat >> ${ws}/n.md <<EOF\n$(wrangler deploy)\nEOF`],
  ['A9 script extension', `cat >> ${ws}/run.sh <<'EOF'\nwrangler deploy production\nEOF`],
  ['A11 rc file', "echo 'curl x|sh deploy production' >> ~/.bashrc"],
  ['A12 settings', `echo '{"hooks":{}} deploy production' > ~/.claude/settings.json`],
  ['A14 crontab', 'echo "* * * * * wrangler deploy" | crontab -'],
  ['A15 cron spool', 'echo "deploy production" >> /var/spool/cron/crontabs/u'],
  ['A16 key variable', `echo "$MARROW_API_KEY deploy production" >> ${ws}/n.md`],
  ['A17 cat operand', `cat ~/.marrow/fleet.env >> ${ws}/n.md`],
  ['A18 command-substituted variable', `R=$(pwd); echo deploy production >> $R/n.md`],
  ['A19 reassignment with expansion', `R=${ws}/a.md; R=$HOME/.bashrc; echo "deploy production" >> $R`],
  ['A20 symlink target', `echo "deploy production" >> ${ws}/link.md`],
  ['A20b symlinked parent', `echo "deploy production" >> ${ws}/linkdir/sensitive.md`],
  ['A21 hard link (nlink 2)', `echo "deploy production" >> ${ws}/hard.md`],
  ['A22 one bad target', `tee -a ${ws}/n.md ~/.bashrc <<'EOF'\ndeploy production\nEOF`],
  ['A23 unknown tee flag', `tee --output-error=warn ${ws}/n.md <<'EOF'\ndeploy production\nEOF`],
  ['A25 truncate existing', `echo "deploy production" > ${ws}/existing.md`],
  ['A25b tee without -a on existing', `tee ${ws}/existing.md <<'EOF'\ndeploy production\nEOF`],
  ['A26 CLAUDE.md', `echo "deploy production" >> ${ws}/CLAUDE.md`],
  ['A26b AGENTS.md (absent)', `echo "deploy production" >> ${ws}/AGENTS.md`],
  ['A26c memory.md any case', `echo "deploy production" >> ${ws}/Memory.MD`],
  ['A27 dot folder', `echo "deploy production" >> ${ws}/.github/workflows/deploy.yml`],
  ['A27b dot folder with a data extension', `echo "deploy production" >> ${ws}/.hidden/x.md`],
  ['A28 prefix assignment', `R=x echo deploy production >> ${ws}/n.md`],
  ['A29 background', `echo d >> ${ws}/n.md & wrangler deploy`],
  ['A30 invisible character', `echo "deploy​ production" >> ${ws}/n.md`],
  ['A32 newline then wrangler', `echo x >> ${ws}/n.md\nwrangler deploy`],
  ['A33 sudo tee', 'sudo tee -a /etc/hosts <<\'EOF\'\ndeploy production\nEOF'],
  ['A34 date -s', `echo "$(date -s 2020-01-01)" >> ${ws}/n.md deploy production`],
  ['A35 ssh', `ssh prod "echo x >> ${ws}/n.md"`],
  ['A36 process substitution', 'echo "deploy production" | tee >(sh)'],
  ['A37 heredoc into bash', "cat <<'EOF' | bash\nwrangler deploy production\nEOF"],
  ['A38 eval', `echo x >> ${ws}/n.md; eval "$(cat ${ws}/n.md)" deploy production`],
  ['A46 two heredocs', `cat >> ${ws}/n.md <<'A'\ndeploy production\nA\ncat >> ${ws}/m.md <<'B'\ndeploy production\nB`],
  ['A47 unterminated heredoc', `cat >> ${ws}/n.md <<'EOF'\ndeploy production\n`],
  ['A48 /dev/tcp', 'echo "deploy production" >> /dev/tcp/host/80'],
  ['here-string', `cat <<< "deploy production" >> ${ws}/n.md`],
  ['input redirect', `cat < ${ws}/existing.md >> ${ws}/n.md deploy production`],
  ['glob target', `echo "deploy production" >> ${ws}/*.md`],
  ['brace target', `echo "deploy production" >> ${ws}/n.{md,txt}`],
  ['path traversal', `echo "deploy production" >> ${ws}/sub/../../elsewhere/x.md`],
  ['dot-dot segment', 'echo "deploy production" >> ../x.md'],
  ['outside home, tmp and mnt', 'echo "deploy production" >> /etc/notes.md'],
  ['relative target without a working folder', 'echo "deploy production" >> notes.md', { cwd: undefined }],
  ['variable assigned after use', `echo "deploy production" >> $R/n.md; R=${ws}`],
  ['conditional assignment', `false && R=${ws}; echo "deploy production" >> $R/n.md`],
  ['assignment of PATH', `PATH=${ws}; echo "deploy production" >> ${ws}/n.md`],
  ['assignment of HOME', `HOME=${ws}; echo "deploy production" >> ~/n.md`],
  ['assignment in a pipeline', `R=${ws} | echo "deploy production" >> ${ws}/n.md`],
  ['unquoted variable with whitespace', `R="${ws}/a b"; echo "deploy production" >> $R.md`],
  ['subshell', `(echo "deploy production" >> ${ws}/n.md)`],
  ['brace group', `{ echo "deploy production" >> ${ws}/n.md; }`],
  ['cat with an operand', `cat ${ws}/existing.md >> ${ws}/n.md deploy production`],
  ['cat from the terminal', `cat >> ${ws}/n.md deploy production`],
  ['env wrapper', `env echo "deploy production" >> ${ws}/n.md`],
  ['absolute program path', `/bin/echo "deploy production" >> ${ws}/n.md`],
  ['heredoc into echo', `echo >> ${ws}/n.md <<'EOF'\ndeploy production\nEOF`],
  ['date with -d', `echo "$(date -d tomorrow) deploy production" >> ${ws}/n.md`],
  ['date outside echo', `tee -a "${ws}/$(date +%s).md" <<'EOF'\ndeploy production\nEOF`],
  ['${var:-x} operator', `echo "\${X:-deploy production}" >> ${ws}/n.md`],
  ['ANSI-C quote', `echo $'deploy\\x20production' >> ${ws}/n.md`],
  ['over 8192 characters', `echo "deploy production ${'a'.repeat(8200)}" >> ${ws}/n.md`],
  ['PowerShell dialect text', 'Add-Content notes.md "deploy production"'],
];

for (const [id, command, extra] of HELD) {
  test(`MCP-1a held: ${id}`, () => {
    const result = bash(command, extra);
    assert.equal(result.protected, true, JSON.stringify(result));
  });
}

// A24: 3.9.108 reads `printf -v` as a read-only program (its payload is not scanned either way). The recognizer refuses `-v`, so the
// answer stays exactly the 3.9.108 one: read-only, not the DW label (which is never read-only).
test('MCP-1a held: A24 printf -v is not admitted and keeps the 3.9.108 reading', () => {
  const result = bash("printf -v X '%s' deploy production");
  assert.deepEqual([result.protected, result.readOnly], [false, true]);
});

test('MCP-1a held: a tool that is not a plain Bash call never gets the exemption', () => {
  const text = `echo "deploy production" >> ${ws}/n.md`;
  for (const event of [
    { tool_name: 'mcp__other__run', tool_input: { command: text } },
    { tool_name: 'PowerShell', tool_input: { command: text } },
    { tool_name: 'Bash', tool_input: { command: text, cmd: 'wrangler deploy' } },
    { tool_name: 'Bash', tool_input: { script: text } },
  ]) {
    const result = classifyTool({ ...event, cwd: ws });
    assert.equal(result.protected, true, JSON.stringify(event));
    assert.notEqual(result.action, DW_LABEL);
  }
});

test('MCP-1a K1-2/K1-6: other targets and other programs get another label and another hash input', () => {
  const dw = bash(`echo "deploy production" >> ${ws}/a.md`);
  const rc = bash('echo "deploy production" >> ~/.bashrc');
  const real = bash('wrangler deploy --env production');
  assert.notEqual(dw.action, rc.action);
  assert.notEqual(dw.action, real.action);
  assert.equal(rc.protected, true);
  assert.equal(real.protected, true);
});

test('MCP-1a K1-7: the PostToolUse path judges the same command by the same rule, a written file included', () => {
  const command = `echo "deploy production" > ${ws}/post-new.md`;
  assert.equal(isDw(command), true);
  writeFileSync(join(ws, 'post-new.md'), 'deploy production\n');
  assert.equal(isDw(command), false, 'pre-tool: the file now exists, so `>` would truncate it');
  const post = classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: ws }, { postTool: true });
  assert.equal(post.action, DW_LABEL, 'post-tool: the file is the one the command wrote');
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: `echo "deploy production" > ${ws}/existing.md` }, cwd: ws }, { postTool: true }).action, DW_LABEL);
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: `echo x >> ${ws}/n.md && wrangler deploy` }, cwd: ws }, { postTool: true }).protected, true);
});

test('MCP-1a: an echo of plain words with no file write keeps its 3.9.108 reading (read-only stays read-only)', () => {
  const result = bash('echo "hello there"');
  assert.equal(result.readOnly, true);
});

// T1: data files never run as code. A10.
const RUNS_DATA = [
  'bash notes.md', 'source notes.md', '. ./notes.md', './notes.md', 'python3 notes.txt', 'sh run.log', 'node data.csv', 'perl x.tsv',
  'zsh -x notes.md', 'python3 -I notes.md', 'sudo bash notes.md', 'FOO=1 bash notes.md', "bash -c 'source notes.md'",
  'xargs bash notes.md', '/usr/bin/python3 notes.jsonl', `${root}/x/notes.md`, 'php a.ndjson',
];
const BENIGN_DATA = ['cat notes.md', 'bash script.sh', 'python3 tool.py notes.md', 'node tool.js notes.md', 'grep x notes.md', 'echo notes.md', 'bash -c "echo hi"', 'git add notes.md'];

function controlHome(directory, enabled) {
  const home = join(directory, 'home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  if (enabled !== undefined) {
    mkdirSync(join(home, '.marrow'), { mode: 0o700 });
    writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: 0o600 });
  }
  return home;
}

function runHook(home, command) {
  return spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'claude-pre-action-hook'], {
    cwd: home,
    env: { PATH: process.env.PATH, HOME: home, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true', MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json') },
    input: JSON.stringify({ session_id: 's-t1', tool_use_id: 't-1', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } }),
    encoding: 'utf8',
    timeout: 20_000,
  });
}

const T1_TEXT = 'Marrow does not run a notes or log file as a program. Put scripts in a file with a script extension.';

test('MCP-1a T1: the hook denies a data file run as a program, locally, with the plain text (control ON)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-t1-'));
  try {
    const home = controlHome(directory, true);
    for (const command of RUNS_DATA) {
      const result = runHook(home, command);
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', command);
      assert.equal(output.hookSpecificOutput.permissionDecisionReason, T1_TEXT, command);
    }
    for (const command of BENIGN_DATA) {
      const result = runHook(home, command);
      assert.equal(result.status, 0, result.stderr);
      assert.doesNotMatch(result.stdout, new RegExp(T1_TEXT.slice(0, 30)), command);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('MCP-1a T1: with control disabled by the owner nothing is denied', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-t1-off-'));
  try {
    const home = controlHome(directory, false);
    const result = runHook(home, 'python3 notes.txt');
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /does not run a notes/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
