'use strict';
// `marrow keys create` --name / --type / --expires, the same rule as --scopes and --agents:
// absent is the default (live key, no expiry); `--flag value`, `--flag=value`, `-n`/`-t` with a
// space or `=` are all read; the first occurrence wins; a flag that is present but blank is a
// usage error (exit 2, nothing sent). Before this, `--expires=<date>` was silently ignored and
// made a key that never expires, and `--type=test` made a live key. Every request is answered by
// the local stub; key values are runtime dummies and are never printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const STUB = path.join(__dirname, 'support', 'keys-fetch-stub.cjs');
const dummy = () => `dummykey_${crypto.randomBytes(12).toString('hex')}`;

function run(argv) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-create-flags-'));
  const capture = path.join(dir, 'cap.jsonl');
  fs.writeFileSync(capture, '');
  const created = dummy();
  try {
    const child = spawnSync(process.execPath, ['--require', STUB, CLI, 'keys', 'create', ...argv], {
      cwd: dir,
      env: {
        PATH: process.env.PATH,
        HOME: dir,
        MARROW_API_KEY: dummy(),
        MARROW_AUTO_HOOK: 'false',
        MARROW_AUTO_ENROLL: 'false',
        CAPTURE_FILE: capture,
        STUB_KEY: created,
      },
      encoding: 'utf8',
      timeout: 20_000,
      killSignal: 'SIGKILL',
    });
    const requests = fs.readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
    const posts = requests.filter((r) => r.method === 'POST' && r.url.endsWith('/v1/auth/keys')).map((r) => JSON.parse(r.body));
    return { status: child.status, stdout: child.stdout || '', stderr: child.stderr || '', requests, posts, created };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const sent = (...argv) => {
  const r = run(argv);
  assert.equal(r.status, 0, `${JSON.stringify(argv)}: ${r.stderr}`);
  assert.equal(r.posts.length, 1, JSON.stringify(argv));
  assert.equal(r.stderr.includes(r.created), false);
  return r.posts[0];
};

const EXP = '2030-01-01T00:00:00Z';

test('keys create: the equals form of --expires, --type and --name is read (was ignored: no expiry, a live key, "--name required")', () => {
  assert.deepEqual(sent('--name', 'n', `--expires=${EXP}`), { name: 'n', key_type: 'live', expires_at: EXP });
  assert.deepEqual(sent('--name', 'n', '--type=test'), { name: 'n', key_type: 'test' });
  assert.deepEqual(sent('--name=n'), { name: 'n', key_type: 'live' });
  assert.deepEqual(sent('-n=n', '-t=test'), { name: 'n', key_type: 'test' });
  assert.deepEqual(sent('-n', 'n', '-t', 'test', '--expires', EXP), { name: 'n', key_type: 'test', expires_at: EXP });
  assert.deepEqual(sent('--name=a=b', '--expires=x=y'), { name: 'a=b', key_type: 'live', expires_at: 'x=y' }, 'only the first = splits');
});

test('keys create: absent --type / --expires keep the defaults and send no expiry', () => {
  const body = sent('--name', 'n');
  assert.deepEqual(body, { name: 'n', key_type: 'live' });
  assert.equal(Object.hasOwn(body, 'expires_at'), false);
});

test('keys create: --name, --type or --expires present but blank is a usage error and sends nothing', () => {
  const blanks = [
    ['--expires='], ['--expires', ''], ['--expires', ' \t'], ['--expires'],
    ['--type='], ['--type', ''], ['--type', '  '], ['--type'], ['-t='], ['-t', ''],
  ];
  for (const flags of blanks) {
    const r = run(['--name', 'n', ...flags]);
    const flag = flags[0].startsWith('-t') ? '--type' : flags[0].replace(/=.*$/, '');
    assert.equal(r.status, 2, JSON.stringify(flags));
    assert.deepEqual(r.requests, [], `${JSON.stringify(flags)}: no request`);
    assert.equal(r.stdout, '');
    assert.equal(r.stderr, `Error: ${flag} needs a value, or omit ${flag} for the default\n`, JSON.stringify(flags));
  }
  for (const flags of [['--name='], ['--name', ''], ['--name', ' '], ['--name'], ['-n='], ['-n', '']]) {
    const r = run(flags);
    assert.equal(r.status, 2, JSON.stringify(flags));
    assert.deepEqual(r.requests, []);
    assert.equal(r.stderr, 'Error: --name needs a value, or omit --name for the default\n');
  }
  const none = run(['--type', 'test']);
  assert.equal(none.status, 1, 'no --name at all keeps the 3.9.102 error');
  assert.equal(none.stderr, 'Error: --name required\n');
  assert.deepEqual(none.requests, []);
});

test('keys create: a blank first flag is not rescued by a later one; the first of repeated flags wins in any form', () => {
  for (const flags of [['--expires=', '--expires', EXP], ['--expires', '', `--expires=${EXP}`], ['--type=', '--type', 'test']]) {
    const r = run(['--name', 'n', ...flags]);
    assert.equal(r.status, 2, JSON.stringify(flags));
    assert.deepEqual(r.requests, []);
  }
  assert.deepEqual(sent('--name', 'n', `--expires=${EXP}`, '--expires', '2031-01-01T00:00:00Z').expires_at, EXP);
  assert.deepEqual(sent('--name', 'n', '--expires', EXP, '--expires='), { name: 'n', key_type: 'live', expires_at: EXP });
  assert.equal(sent('--name', 'n', '--type=test', '--type', 'live').key_type, 'test');
  assert.equal(sent('--name', 'n', '-t', 'test', '--type=live').key_type, 'test');
  assert.equal(sent('--name=first', '--name', 'second').name, 'first');
});

test('keys create: values are sent as typed (the server validates them)', () => {
  assert.equal(sent('--name', 'n', '--expires', ' 2030-01-01 ').expires_at, ' 2030-01-01 ');
  assert.equal(sent('--name', 'n', '--type=Test').key_type, 'Test');
  assert.equal(sent('--name', 'n', '--type', 'prod').key_type, 'prod');
  // Only ASCII blanks make a value blank (the --scopes rule): a non-breaking space is sent for the server to judge.
  assert.equal(sent('--name', ' ').name, ' ');
  assert.equal(sent('--name', 'n', '--expires= ').expires_at, ' ');
});
