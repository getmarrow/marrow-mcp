'use strict';

// MCPWF1 part B: runs the npm-publish.yml step "Verify the published version and its provenance" with bash,
// PATH-first stubs for npm, sleep and curl, and the real jq, base64, od and tr. Rows W1-W9: the registry wait
// is bounded at 40 polls, the integrity compare is exact and every provenance condition still fails closed.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const WF = path.join(__dirname, '..', '.github', 'workflows', 'npm-publish.yml');
const STEP = '      - name: Verify the published version and its provenance';
const SLSA = 'https://slsa.dev/provenance/v1';

function extractRun(text) {
  const lines = text.split('\n');
  const at = lines.flatMap((l, i) => (l === STEP ? [i] : []));
  assert.equal(at.length, 1, 'the verify step exists exactly once');
  let i = at[0] + 1;
  for (; lines[i] !== '        run: |'; i += 1) assert.ok(i < lines.length && !lines[i].startsWith('      - '), 'the step has a run block');
  const out = [];
  for (i += 1; i < lines.length && (lines[i] === '' || lines[i].startsWith('          ')); i += 1) out.push(lines[i].slice(10));
  return `${out.join('\n').trimEnd()}\n`;
}
const SCRIPT = extractRun(fs.readFileSync(WF, 'utf8'));
const BOUND = Number((/\$\(seq 1 (\d+)\)/.exec(SCRIPT) || [])[1]);

const HAS_JQ = spawnSync('jq', ['--version']).status === 0;
const SKIP = !HAS_JQ && !process.env.CI ? 'jq is not installed (a skip outside CI only)' : false;

const [VERSION, SHA, REPO, PKG] = [`3.9.${crypto.randomInt(1000, 9999)}`, crypto.randomBytes(20).toString('hex'), 'getmarrow/marrow-mcp', '@getmarrow/mcp'];
const TAG = `v${VERSION}`;
const sha512 = (bytes, enc) => crypto.createHash('sha512').update(bytes).digest(enc);
const TARBALL = crypto.randomBytes(64);
const INTEGRITY = `sha512-${sha512(TARBALL, 'base64')}`;
const DIGEST = sha512(TARBALL, 'hex');
const PUBLISHED = `Published ${PKG}@${VERSION} with provenance for ${SHA}`;

function attestations({ digest = DIGEST, ref = `refs/tags/${TAG}`, repo = `https://github.com/${REPO}`,
  wfPath = '.github/workflows/npm-publish.yml', commit = SHA, count = 1 } = {}) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: `pkg:npm/%40getmarrow/mcp@${VERSION}`, digest: { sha512: digest } }],
    predicateType: SLSA,
    predicate: { buildDefinition: { externalParameters: { workflow: { ref, repository: repo, path: wfPath } },
      resolvedDependencies: [{ uri: `git+https://github.com/${REPO}@${ref}`, digest: { gitCommit: commit } }] } },
  };
  const one = { predicateType: SLSA, bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') } } };
  const publish = { predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1', bundle: { dsseEnvelope: { payload: '' } } };
  return JSON.stringify({ attestations: [...Array(count).fill(one), publish] });
}

const STUBS = {
  npm: `#!/usr/bin/env bash
s="$STUB_STATE"
[ "$1 $2" = "view $EXPECTED_PACKAGE@$VERSION" ] || exit 9
case "$3" in
  dist.integrity)
    n=$(( $(cat "$s/polls") + 1 )); echo "$n" > "$s/polls"
    if [ -f "$s/int.$n" ]; then cat "$s/int.$n"; elif [ -f "$s/int.any" ]; then cat "$s/int.any"; else echo 'npm error code E404' >&2; exit 1; fi ;;
  dist.attestations.provenance.predicateType) [ ! -f "$s/pred" ] || cat "$s/pred" ;;
  *) exit 9 ;;
esac
`,
  sleep: `#!/usr/bin/env bash
n=$(( $(cat "$STUB_STATE/sleeps") + 1 )); echo "$n" > "$STUB_STATE/sleeps"
[ "$*" = 15 ] && [ "$n" -le 60 ]
`,
  curl: `#!/usr/bin/env bash
case "$*" in
  *"https://registry.npmjs.org/-/npm/v1/attestations/%40getmarrow%2fmcp@$VERSION"*) cat "$STUB_STATE/att" ;;
  *) exit 22 ;;
esac
`,
};

// answers: { <poll n>: text } and/or any: text (every other poll); a poll without an answer is a 404.
function runStep({ answers = {}, any, pred = SLSA, att = attestations() } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-verify-wait-'));
  try {
    const [bin, state] = [path.join(dir, 'bin'), path.join(dir, 'state')];
    for (const d of [bin, state]) fs.mkdirSync(d);
    for (const [name, body] of Object.entries(STUBS)) fs.writeFileSync(path.join(bin, name), body, { mode: 0o755 });
    for (const f of ['polls', 'sleeps']) fs.writeFileSync(path.join(state, f), '0');
    for (const [n, text] of Object.entries(answers)) fs.writeFileSync(path.join(state, `int.${n}`), text);
    if (any !== undefined) fs.writeFileSync(path.join(state, 'int.any'), any);
    if (pred !== null) fs.writeFileSync(path.join(state, 'pred'), `${pred}\n`);
    fs.writeFileSync(path.join(state, 'att'), att);
    fs.writeFileSync(path.join(dir, 'step.sh'), SCRIPT);
    const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', path.join(dir, 'step.sh')], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 60000,
      env: { PATH: `${bin}:${process.env.PATH}`, HOME: dir, LC_ALL: 'C', STUB_STATE: state, VERSION, EXPECTED_INTEGRITY: INTEGRITY,
        TAG, GITHUB_SHA: SHA, GITHUB_REPOSITORY: REPO, EXPECTED_PACKAGE: PKG },
    });
    const count = (f) => Number(fs.readFileSync(path.join(state, f), 'utf8'));
    return { code: r.status, out: `${r.stdout}${r.stderr}`, polls: count('polls'), sleeps: count('sleeps') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const ok = `${INTEGRITY}\n`;
function passes(r, polls) {
  assert.equal(r.code, 0, r.out);
  assert.ok(r.out.includes(PUBLISHED));
  assert.deepEqual([r.polls, r.sleeps], [polls, polls - 1]);
}
function failsAtBound(r, message) {
  assert.notEqual(r.code, 0);
  assert.ok(r.out.includes(`::error::${message}`), r.out);
  assert.ok(!r.out.includes(PUBLISHED));
  assert.ok(r.polls <= 40, `at most 40 integrity polls, saw ${r.polls}`);
  assert.deepEqual([r.polls, r.sleeps], [BOUND, BOUND]);
}

test('the step script is plain bash with one bounded poll loop', { skip: SKIP }, () => {
  assert.ok(HAS_JQ, 'jq is required under CI');
  assert.ok(!SCRIPT.includes('${{'));
  assert.ok(BOUND >= 1 && BOUND <= 40, `bound ${BOUND}`);
});
test('W1: integrity visible at poll 1 passes with 1 poll and 0 sleeps', { skip: SKIP }, () => passes(runStep({ answers: { 1: ok } }), 1));
test('W2: integrity visible at poll 21 passes', { skip: SKIP }, () => passes(runStep({ answers: { 21: ok } }), 21));
test('W3: integrity visible at poll 40 passes after 39 sleeps', { skip: SKIP }, () => passes(runStep({ answers: { 40: ok } }), 40));
test('W4: integrity never visible fails after the bound, never more than 40 polls', { skip: SKIP }, () => failsAtBound(runStep(), 'Published integrity does not match.'));
test('W5: a different sha512 value on every poll never passes', { skip: SKIP }, () => {
  const answers = {};
  for (let n = 1; n <= 45; n += 1) answers[n] = `sha512-${sha512(crypto.randomBytes(16), 'base64')}\n`;
  failsAtBound(runStep({ answers }), 'Published integrity does not match.');
});
test('W6: near misses of the audited integrity fail', { skip: SKIP }, () => {
  const body = INTEGRITY.slice(7);
  const at = body.search(/[A-Za-z]/);
  const flipped = body.slice(0, at) + (body[at] === body[at].toUpperCase() ? body[at].toLowerCase() : body[at].toUpperCase()) + body.slice(at + 1);
  for (const any of [`${INTEGRITY} \n`, `sha512-${flipped}\n`, `${body}\n`, `${INTEGRITY}\n${INTEGRITY}\n`]) {
    failsAtBound(runStep({ any }), 'Published integrity does not match.');
  }
});
test('W7: a missing or older provenance predicate fails', { skip: SKIP }, () => {
  for (const pred of [null, '', 'https://slsa.dev/provenance/v0.2']) {
    const r = runStep({ answers: { 1: ok }, pred });
    assert.notEqual(r.code, 0);
    assert.ok(r.out.includes('::error::Provenance attestation is missing.'), r.out);
    assert.ok(!r.out.includes(PUBLISHED));
  }
});
test('W8: any provenance field that differs, or two provenance attestations, fails', { skip: SKIP }, () => {
  for (const change of [{ digest: sha512(crypto.randomBytes(8), 'hex') }, { wfPath: '.github/workflows/other.yml' },
    { ref: 'refs/tags/v0.0.1' }, { repo: 'https://github.com/someone-else/marrow-mcp' }, { commit: crypto.randomBytes(20).toString('hex') },
    { count: 2 }]) {
    const r = runStep({ answers: { 1: ok }, att: attestations(change) });
    assert.notEqual(r.code, 0, JSON.stringify(Object.keys(change)));
    assert.ok(r.out.includes('::error::Provenance does not match this tarball, commit and tag.'), r.out);
    assert.ok(!r.out.includes(PUBLISHED));
  }
});
test('W9: everything right after 30 polls passes with the Published line', { skip: SKIP }, () => passes(runStep({ answers: { 30: ok } }), 30));
