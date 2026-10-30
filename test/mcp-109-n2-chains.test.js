const assert = require('node:assert/strict');
const { tmpdir } = require('node:os');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { backendCategories, missing } = require('./support/mcp-109-n2-categories.cjs');

// mcp-109-n2 (reaudit-mcp109 B1/B2, CLASS_SWEEP): a segment that the MCP-10 route or the T2 self-protect early return holds must not replace
// the classification of the rest of the command. For every chain `hold-segment OP return-segment` and `return-segment OP hold-segment` the
// classification of the chain gives (a) every backend category and every local category the hold segment gives ON ITS OWN (its own
// classification has no early return, so it is 3.9.108's), (b) secrets_security, (c) the strictest type (`security`), every surface of the
// hold segment, protected and high risk. Operators: && ; || | newline &. Also inside bash -c, a subshell and a brace group, and through the
// tools that carry shell text.
const RETURNS = [
  ['mcp10', 'npx @getmarrow/install control disable'],
  ['mcp10', 'pnpm dlx @getmarrow/install uninstall --yes'],
  ['t2-control', "echo '{}' > ~/.marrow/control.json"],
  ['t2-control', 'rm ~/.claude/settings.json'],
  ['t2-control', 'cp x.json ~/.codex/hooks.json'],
  ['t2-persist', 'echo x >> ~/.bashrc'],
  ['t2-persist', 'crontab cron.txt'],
  ['t2-persist', 'cp u.service ~/.config/systemd/user/u.service'],
];
const HOLDS = [
  ['deploy', 'wrangler deploy --env production'],
  ['deploy', 'vercel --prod'],
  ['deploy', 'kubectl apply -f prod.yaml'],
  ['deploy', 'terraform apply -auto-approve'],
  ['publish', 'npm publish'],
  ['publish', 'pnpm publish --no-git-checks'],
  ['publish', 'npm unpublish pkg@1.0.0'],
  ['merge', 'gh pr merge 1'],
  ['merge', 'git merge main'],
  ['merge', 'git push origin main'],
  ['migration', 'wrangler d1 migrations apply prod-db'],
  ['migration', 'npx prisma migrate deploy'],
  ['secret', 'cat ~/.aws/credentials'],
  ['secret', 'cat .env'],
  ['wk5', 'git apply p.diff'],
  ['wk5', 'git am'],
  ['financial', 'stripe charges create --amount 100'],
  ['benign', 'ls -la'],
  ['benign', 'git status'],
];
const OPERATORS = [' && ', '; ', ' || ', ' | ', '\n', ' & '];
const WRAPS = {
  'bash -c': (text) => `bash -c '${text.replaceAll("'", `'\\''`)}'`,
  subshell: (text) => `( ${text} )`,
  brace: (text) => `{ ${text}; }`,
};
const bash = (command) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: tmpdir() });
const catsOf = (c) => backendCategories(c.action, c.type, c.surfaces);

const problems = [];
// `held`: the return segment is recognised as a hold in this form (it always is bare; a wrapper such as bash -c hides some T2 forms from the
// parser, exactly as in 3.9.109 before this fix, and then the chain keeps its 3.9.108 classification, which the same rows still bound below).
function check(label, chain, alone, held = true) {
  const got = bash(chain);
  const bad = (what) => problems.push(`${label}: ${what} (sent ${got.action})`);
  if (alone.protected && got.protected !== true) bad('not protected');
  if (got.risk === 'low' || (alone.risk === 'high' && got.risk !== 'high')) bad(`risk ${got.risk}`);
  if (held && got.protected !== true) bad('not protected');
  if (held && got.risk !== 'high') bad(`risk ${got.risk}`);
  if (held && got.type !== 'security') bad(`type ${got.type}`);
  // The hold keeps its label (marrow:security, host:security), and the runtime role is the one 3.9.108 sent for the rest of the chain.
  if (held && !/^(?:marrow|host):security$/.test(got.target)) bad(`target ${got.target}`);
  if (held && alone.role !== 'general' && got.role !== alone.role) bad(`role ${got.role}, ${alone.role} alone`);
  const lost = missing(catsOf(alone), catsOf(got));
  if (lost.length) bad(`backend category lost ${lost.join('+')}`);
  const lostLocal = missing(localApprovalCategories(alone), localApprovalCategories(got));
  if (lostLocal.length) bad(`local category lost ${lostLocal.join('+')}`);
  const lostSurface = missing(alone.surfaces.filter((surface) => surface !== 'workspace'), got.surfaces);
  if (lostSurface.length) bad(`surface lost ${lostSurface.join('+')}`);
  if (held && !catsOf(got).includes('secrets_security')) bad('no secrets_security');
  if (held && !localApprovalCategories(got).includes('secrets_security')) bad('no local secrets_security');
}
const finish = (rows) => {
  const list = problems.splice(0);
  assert.deepEqual(list.slice(0, 12), [], `${list.length} problem(s) in ${rows} chains (category, surface or hold lost)`);
};

test('mcp-109-n2 chains: every return segment is a hold on its own', () => {
  for (const [rn, ret] of RETURNS) assert.equal(bash(ret).type, 'security', `${rn}: ${ret}`);
});

test('mcp-109-n2 chains: every operator, either order, keeps the hold segment\'s categories and surfaces', () => {
  let rows = 0;
  for (const [hn, hold] of HOLDS) {
    const alone = bash(hold);
    for (const [rn, ret] of RETURNS) {
      for (const op of OPERATORS) {
        check(`${rn} ${JSON.stringify(op)} ${hn}`, `${ret}${op}${hold}`, alone);
        check(`${hn} ${JSON.stringify(op)} ${rn}`, `${hold}${op}${ret}`, alone);
        rows += 2;
      }
    }
  }
  assert.equal(rows, HOLDS.length * RETURNS.length * OPERATORS.length * 2);
  finish(rows);
});

test('mcp-109-n2 chains: inside bash -c, a subshell and a brace group', () => {
  let rows = 0;
  for (const [hn, hold] of HOLDS) {
    const alone = bash(hold);
    for (const [rn, ret] of RETURNS) {
      for (const [wn, wrap] of Object.entries(WRAPS)) {
        const held = bash(wrap(ret)).type === 'security';
        check(`${wn}(${rn} && ${hn})`, wrap(`${ret} && ${hold}`), alone, held);
        check(`${wn}(${hn} ; ${rn})`, wrap(`${hold}; ${ret}`), alone, held);
        rows += 2;
      }
    }
  }
  finish(rows);
});

test('mcp-109-n2 chains: the tools that carry shell text merge the same way', () => {
  const holds = HOLDS.filter(([name]) => ['deploy', 'publish', 'merge', 'migration'].includes(name));
  let rows = 0;
  for (const tool of ['PowerShell', 'Monitor']) {
    for (const [hn, hold] of holds) {
      const alone = classifyTool({ tool_name: tool, tool_input: { command: hold }, cwd: tmpdir() });
      for (const [rn, ret] of RETURNS) {
        const got = classifyTool({ tool_name: tool, tool_input: { command: `${ret}; ${hold}` }, cwd: tmpdir() });
        const label = `${tool} ${rn} ${hn}`;
        rows += 1;
        if (got.protected !== true) problems.push(`${label}: not protected`);
        const lost = missing(catsOf(alone), catsOf(got));
        if (lost.length) problems.push(`${label}: backend category lost ${lost.join('+')} (sent ${got.action})`);
        const lostLocal = missing(localApprovalCategories(alone), localApprovalCategories(got));
        if (lostLocal.length) problems.push(`${label}: local category lost ${lostLocal.join('+')}`);
        if (!catsOf(got).includes('secrets_security')) problems.push(`${label}: no secrets_security`);
      }
    }
  }
  finish(rows);
});

test('mcp-109-n2 chains: a hold segment of a file tool call keeps its own categories (T2 target + deploy words in the content)', () => {
  // A file tool is judged by its target only: words in the content are not actions, before and after.
  const got = classifyTool({ tool_name: 'Write', tool_input: { file_path: `${tmpdir()}/x/.bashrc`, content: 'wrangler deploy --env production' }, cwd: tmpdir() });
  assert.equal(got.type, 'security');
  assert.deepEqual(got.surfaces, ['persistence']);
  assert.equal(got.action, 'classified Write action: security on persistence');
});

test('mcp-109-n2 chains: the local mirror reads the action, the type and the surfaces the server reads', () => {
  // A merged hold: the surfaces and the displaced-type sentence each carry what the hold's own label does not.
  assert.deepEqual(localApprovalCategories({ action: 'classified Bash action: security on marrow-control', type: 'security', surfaces: ['production', 'marrow-control'] }), ['production_deploy', 'secrets_security']);
  assert.deepEqual(localApprovalCategories({ action: 'classified Bash action: security on persistence', type: 'security', surfaces: ['github', 'persistence'] }), ['source_control', 'secrets_security']);
  assert.deepEqual(localApprovalCategories({ action: 'classified Bash action: security on database', type: 'security', surfaces: ['database'] }), ['data_migration', 'secrets_security']);
  assert.deepEqual(localApprovalCategories({ action: 'classified Bash action: security on npm, persistence; classified Bash action: publish on npm', type: 'security', surfaces: ['npm', 'persistence'] }), ['package_publish', 'secrets_security']);
});
