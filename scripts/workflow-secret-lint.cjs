#!/usr/bin/env node
'use strict';

// Workflow secret lint. Reads every .github/workflows/*.yml and fails when a secret can reach a command line,
// a URL, a log line, an artifact, a cache or a pull request run. It is a small line reader, not a YAML library:
// any form it does not understand (tabs, anchors, compact sequences, duplicate keys, text under a scalar) is
// reported as R0 and fails the run, so an odd file can never pass by being unreadable.
// Output: one `file:line RULE` per finding, never the line text. Exit 0: clean. Exit 1: findings.
//
// A secret expression is any ${{ }} that names the secrets context or github.token.
//   R1  a secret expression anywhere except as the whole value of a step-level env entry (run text, a URL, with,
//       if, name, a comment, job-level or workflow-level env, a flow map, or an alias such as env.NAME)
//   R2  the env name bound to a secret is named in the step's run text, except in the one sanctioned shape
//       curl --config <(printf 'header = "Authorization: Bearer %s"\n' "$NAME") to https://api.github.com/ for a
//       github.token binding (never for secrets.*); or the step is not a run step
//   R3  in a step that holds a secret: shell tracing, an environment dump, eval, indirect expansion or a /proc read
//   R4  a uses: line that is not a full 40-hex commit SHA (or a local ./ path, or a docker digest)
//   R5  a workflow that binds a secrets.* value: a trigger other than a tag push or workflow_dispatch without
//       inputs, a missing or non-read permissions block, a job without environment, timeout and a master-only if,
//       an expression inside run text, secrets passed to a called workflow, or an artifact, cache or debug switch
const fs = require('node:fs');
const path = require('node:path');

const EXPR = /\$\{\{([\s\S]*?)\}\}/g;
const SECRETISH = /(?:^|[^A-Za-z0-9_])secrets(?![A-Za-z0-9_])|github\s*\.\s*token(?![A-Za-z0-9_])|github\s*\[\s*['"]token['"]\s*\]/i;
const SECRETS_CTX = /(?:^|[^A-Za-z0-9_])secrets(?![A-Za-z0-9_])/i;
const WHOLE_BINDING = /^\$\{\{\s*(?:secrets\.[A-Za-z_][A-Za-z0-9_-]*|github\.token)\s*\}\}$/i;
const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;
const KEY = /^((?:[A-Za-z0-9_./-]+)|'[^']*'|"[^"]*"):(?:\s+(.*))?$/;
const USES_OK = /^(?:\.\/\S*|[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}|docker:\/\/\S+@sha256:[0-9a-f]{64})$/;
const BLOCK = /^[|>][+-]?[0-9]?$/;
const DUMPS = [
  /(?:^|[\s;&|(])set\s+-[A-Za-z]*[xv]/, /\bset\s+-o\s+(?:xtrace|verbose)/, /\b(?:ba|da|z)?sh\s+-[A-Za-z]*[xv]/, /\bPS4\b/, /\bBASH_XTRACEFD\b/,
  /\beval\b/, /\$\{!/, /\bprintenv\b/, /(?:^|[\s;&|(])env(?:\s|$)/, /\bexport\s+-p\b/, /\bdeclare\s+-[A-Za-z]*p/, /\bcompgen\b/,
  /\/proc\//, /\benviron\b/i, /\bgetenv\b/i, /\bENV\b/, /\bprocess\.env\b/, /\bawk\b/, /\btrap\b/,
  /(?:^|[\s;&|(])(?:node|nodejs|deno|bun)\s+(?:-[A-Za-z]*[ep]\b|--eval|--print)/, /(?:^|[\s;&|(])(?:python[0-9.]*|ruby|php)\s+-[A-Za-z]*[cer]\b/, /(?:^|[\s;&|(])perl\s+-[A-Za-z]*e/, /\bsource\b/, /(?:^|[\s;&|(])\.\s+\S/,
];

const indentOf = (s) => /^ */.exec(s)[0].length;
const unquote = (v) => (/^'[^']*'$|^"[^"]*"$/.test(v) ? v.slice(1, -1) : v);

function stripComment(v) {
  if (v.startsWith("'") || v.startsWith('"')) {
    const end = v.indexOf(v[0], 1);
    return end < 0 ? v : v.slice(0, end + 1) + (/^\s*(?:#.*)?$/.test(v.slice(end + 1)) ? '' : v.slice(end + 1));
  }
  return v.replace(/\s+#.*$/, '').trimEnd();
}

// Entries: { line, path, key, value, block, flow }. path is the key names from the root; list items are '#1', '#2'.
function readWorkflow(text) {
  const entries = [];
  const errors = [];
  const lines = text.split('\n');
  const root = { indent: -1, key: '', keys: new Set(), item: false, count: 0 };
  const stack = [root];
  let block = null;
  const top = () => stack[stack.length - 1];
  const keys = () => stack.slice(1).map((f) => f.key);

  function addKey(n, col, content) {
    const m = KEY.exec(content);
    if (!m) { errors.push({ line: n, why: 'line form' }); return; }
    while (stack.length > 1 && top().indent >= col) stack.pop();
    const parent = top();
    if (parent.scalar) { errors.push({ line: n, why: 'text under a scalar' }); return; }
    const key = unquote(m[1]);
    if (parent.keys.has(key)) { errors.push({ line: n, why: 'duplicate key' }); return; }
    parent.keys.add(key);
    let value = stripComment((m[2] || '').trim());
    const entry = { line: n, path: [...keys(), key], key, value, block: null, flow: false };
    if (BLOCK.test(value)) { entry.block = []; entry.value = ''; block = { indent: col, entry }; value = ''; }
    else if (/^[&*!%@`]/.test(value)) errors.push({ line: n, why: 'anchor, alias or tag' });
    else if (/^[{[]/.test(value)) {
      entry.flow = true;
      if (!/[}\]]$/.test(value)) errors.push({ line: n, why: 'multi-line flow collection' });
    } else if (/^['"]/.test(value) && !/^'[^']*'$|^"[^"]*"$/.test(value)) errors.push({ line: n, why: 'multi-line quoted scalar' });
    entries.push(entry);
    stack.push({ indent: col, key, keys: new Set(), item: false, count: 0, scalar: value !== '' && !entry.block });
  }

  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i].replace(/\r$/, '');
    const n = i + 1;
    if (block) {
      if (/^\s*$/.test(raw) || indentOf(raw) > block.indent) { block.entry.block.push({ line: n, text: raw }); continue; }
      block = null;
    }
    if (/^\s*(?:#.*)?$/.test(raw)) continue;
    if (/\t/.test(raw.slice(0, indentOf(raw) + 1))) { errors.push({ line: n, why: 'tab' }); continue; }
    if (/^(?:---|\.\.\.)\s*$/.test(raw)) { if (n !== 1) errors.push({ line: n, why: 'document marker' }); continue; }
    const dash = /^( *)-(\s+)(.*)$/.exec(raw);
    if (!dash) { addKey(n, indentOf(raw), raw.trim()); continue; }
    const d = dash[1].length;
    while (stack.length > 1 && top().indent > d) stack.pop();
    if (top().indent === d) {
      if (!top().item) { errors.push({ line: n, why: 'compact sequence' }); continue; }
      stack.pop();
    }
    const parent = top();
    if (parent.scalar) { errors.push({ line: n, why: 'text under a scalar' }); continue; }
    parent.count += 1;
    stack.push({ indent: d, key: `#${parent.count}`, keys: new Set(), item: true, count: 0 });
    const rest = stripComment(dash[3].trim());
    if (rest === '') continue;
    if (KEY.test(rest) && !/^['"]/.test(rest)) addKey(n, d + 1 + dash[2].length, rest);
    else entries.push({ line: n, path: keys(), key: null, value: rest, block: null, flow: false });
  }
  return { entries, errors };
}

const blockText = (e) => (e.block ? e.block.map((b) => b.text.trim()).join('\n') : e.value);
const stepOf = (e) => (e.path[0] === 'jobs' && e.path[2] === 'steps' && /^#\d+$/.test(e.path[3] || '') ? `${e.path[1]}/${e.path[3]}` : null);
const isStepEnv = (e) => stepOf(e) !== null && e.path.length === 6 && e.path[4] === 'env' && ENV_NAME.test(e.path[5]);
const lineOf = (text, at) => text.slice(0, at).split('\n').length;

function lintWorkflow(text) {
  const out = [];
  const add = (line, rule) => out.push({ line, rule });
  const { entries, errors } = readWorkflow(text);
  for (const e of errors) add(e.line, `R0 unreadable (${e.why})`);

  // Secret bindings per step: the env entries whose whole value is one secrets.NAME or github.token expression.
  const bound = new Map();
  const bindingLines = new Set();
  let secretsClass = false;
  for (const e of entries) {
    if (!isStepEnv(e) || !WHOLE_BINDING.test(e.value)) continue;
    const step = stepOf(e);
    bound.set(step, [...(bound.get(step) || []), { name: e.path[5], secret: SECRETS_CTX.test(e.value) }]);
    bindingLines.add(e.line);
    if (SECRETS_CTX.test(e.value)) secretsClass = true;
  }
  const allNames = new Set([...bound.values()].flat().map((b) => b.name));

  // R1: every secret expression, found in the raw text so comments and block text are covered too.
  for (const m of text.matchAll(EXPR)) {
    const line = lineOf(text, m.index);
    const alias = [...allNames].some((n) => new RegExp(`\\benv\\s*\\.\\s*${n}\\b`, 'i').test(m[1])) || /\benv\s*\[|toJSON\s*\(\s*env/i.test(m[1]);
    if (!SECRETISH.test(m[1]) && !alias) continue;
    const sameLine = [...text.split('\n')[line - 1].matchAll(EXPR)].length;
    if (!bindingLines.has(line) || sameLine !== 1 || m[0].includes('\n')) add(line, 'R1 secret expression outside a step env binding');
  }
  if (/\$\{\{[^}]*$/m.test(text.replace(EXPR, ''))) add(1, 'R0 unreadable (open expression)');

  // R2 and R3: per step that holds a secret.
  const shapes = new Map();
  for (const [step, names] of bound) {
    const own = entries.filter((e) => stepOf(e) === step);
    const run = own.find((e) => e.path.length === 5 && e.path[4] === 'run');
    if (!run) { add(own[0].line, 'R2 a step that holds a secret must be a run step'); continue; }
    let body = blockText(run).replace(/\\\n\s*/g, ' ');
    for (const { name, secret } of names) {
      const shape = `--config\\s+<\\(printf\\s+'header = "[A-Za-z][A-Za-z-]*: (?:Bearer )?%s"\\\\n'\\s+"\\$(?:${name}|\\{${name}\\})"\\)`;
      // Only github.token, and only on a line whose every URL is on api.github.com, may use the config-pipe shape.
      body = body.split('\n').map((ln) => {
        const urls = ln.match(/https?:\/\/[^\s"')]+/g) || [];
        if (secret || urls.length === 0 || urls.some((u) => !u.startsWith('https://api.github.com/')) || !new RegExp(shape).test(ln)) return ln;
        return ln.replace(new RegExp(shape, 'g'), '--config <(sanctioned)');
      }).join('\n');
      if (new RegExp(`(?:^|[^A-Za-z0-9_])${name}(?![A-Za-z0-9_])`).test(body)) add(run.line, `R2 ${name} named in run text`);
    }
    if (DUMPS.some((re) => re.test(body))) add(run.line, 'R3 trace, environment dump or indirect read in a step that holds a secret');
    const shell = own.find((e) => e.path.length === 5 && e.path[4] === 'shell');
    if (shell && /\s-[A-Za-z]*[xv]|\{0\}\s*\S/.test(shell.value)) add(shell.line, 'R3 shell flags in a step that holds a secret');
    shapes.set(step, run.line);
  }

  // R4: pins.
  for (const e of entries) {
    if (e.key === 'uses' && !USES_OK.test(unquote(e.value))) add(e.line, 'R4 uses is not a full commit SHA');
  }

  // R5: a workflow that binds secrets.* may only run from a tag push or a master dispatch.
  if (secretsClass) {
    const on = entries.filter((e) => e.path[0] === 'on' || e.path[0] === 'true');
    const kids = on.filter((e) => e.path.length === 2 && e.key !== null);
    const head = on.find((e) => e.path.length === 1);
    if (!head || head.value !== '' || kids.length === 0) add(head ? head.line : 1, 'R5 triggers must be a plain mapping');
    for (const k of kids) {
      if (!['push', 'workflow_dispatch'].includes(k.key)) add(k.line, `R5 trigger ${k.key} may reach a secret`);
      if (k.flow || (k.value !== '' && k.value !== '{}' && !k.block)) add(k.line, `R5 trigger ${k.key} must be a plain mapping`);
    }
    for (const e of on.filter((x) => x.path.length === 3)) {
      if (e.path[1] === 'workflow_dispatch') add(e.line, 'R5 workflow_dispatch may not take inputs');
      if (e.path[1] === 'push' && e.key !== 'tags') add(e.line, `R5 push may only filter by tags (${e.key})`);
    }
    if (!kids.some((k) => k.key === 'push' || k.key === 'workflow_dispatch')) add(head ? head.line : 1, 'R5 no tag or dispatch trigger');
    const pushTags = entries.some((e) => e.path[0] === 'on' && e.path[1] === 'push' && e.path[2] === 'tags');
    if (kids.some((k) => k.key === 'push') && !pushTags) add(1, 'R5 push without a tags filter');

    const perm = entries.filter((e) => e.path.includes('permissions'));
    if (!entries.some((e) => e.path.length === 1 && e.key === 'permissions')) add(1, 'R5 no workflow-level permissions block');
    for (const p of perm) {
      const v = blockText(p);
      if (p.path.length === 1 && v !== '' && v !== '{}') add(p.line, 'R5 permissions must be a mapping');
      if (p.path.length > 1 && v !== '' && !/^(?:read|none|\{\})$/.test(v)) add(p.line, 'R5 permissions beyond read');
    }
    for (const step of bound.keys()) {
      const job = step.split('/')[0];
      const own = (k) => entries.find((e) => e.path.length === 3 && e.path[0] === 'jobs' && e.path[1] === job && e.key === k);
      if (!own('environment') || own('environment').value === '') add(shapes.get(step), `R5 job ${job} has no environment`);
      if (!own('timeout-minutes')) add(shapes.get(step), `R5 job ${job} has no timeout`);
      const cond = own('if');
      if (!cond || !/github\.ref\s*==\s*'refs\/heads\/master'/.test(blockText(cond))) add(shapes.get(step), `R5 job ${job} has no master-only if`);
    }
    for (const e of entries) {
      if (e.key === 'run' && blockText(e).includes('${{')) add(e.line, 'R5 expression in run text (use an env entry)');
      if (e.key === 'secrets' && e.path[0] === 'jobs' && e.path.length === 3) add(e.line, 'R5 secrets passed to a called workflow');
      if (e.key === 'uses' && /upload-artifact|download-artifact|actions\/cache|\/cache(?:\/|@)/i.test(e.value)) add(e.line, 'R5 artifact or cache step');
      if (e.key !== null && /^(?:cache|cache-dependency-path)$/.test(e.key)) add(e.line, 'R5 cache input');
      if (e.key === 'package-manager-cache' && e.value !== 'false') add(e.line, 'R5 package-manager-cache must be false');
      if (e.key !== null && /^(?:ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG|RUNNER_DEBUG)$/.test(e.key)) add(e.line, 'R5 debug switch');
    }
  }
  return out;
}

function lintDir(dir) {
  const result = {};
  for (const f of fs.readdirSync(dir).filter((x) => /\.ya?ml$/.test(x)).sort()) {
    result[f] = lintWorkflow(fs.readFileSync(path.join(dir, f), 'utf8'));
  }
  return result;
}

module.exports = { lintWorkflow, lintDir, readWorkflow };

if (require.main === module) {
  const dir = path.resolve(process.argv[2] || path.join(__dirname, '..', '.github', 'workflows'));
  const result = lintDir(dir);
  let bad = 0;
  for (const [f, list] of Object.entries(result)) {
    for (const v of list) { bad += 1; process.stdout.write(`${f}:${v.line} ${v.rule}\n`); }
  }
  process.stdout.write(`workflow-secret-lint: ${Object.keys(result).length} files, ${bad} findings\n`);
  process.exitCode = bad === 0 && Object.keys(result).length > 0 ? 0 : 1;
}
