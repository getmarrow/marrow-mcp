// The chmod repair advice must target the real refused file: real path, shell
// quoted, or no path operand at all when the path cannot be printed safely.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { resolveMarrowEnv } = require('../dist/env.js');

const dummyKey = () => `synthetic-advice-${crypto.randomBytes(12).toString('hex')}`;
const mode = (f) => fs.statSync(f).mode & 0o777;
const skip = process.platform === 'win32';

function root(label) {
  const base = process.env.MARROW_TEST_TMP || os.tmpdir();
  return fs.mkdtempSync(path.join(base, `marrow-advice-${label}-`));
}

// A home named `name` holding a 0644 (refused) ~/.marrow/env; returns paths.
function makeHome(top, name, key) {
  const home = path.join(top, name);
  const dir = path.join(home, '.marrow');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'env');
  fs.writeFileSync(file, `MARROW_API_KEY=${key}\n`, { mode: 0o644 });
  fs.chmodSync(file, 0o644);
  return { home, dir, file };
}

function notice(top, h) {
  const cwd = path.join(top, 'work');
  fs.mkdirSync(cwd, { recursive: true });
  const r = resolveMarrowEnv({ cwd, home: h.home, env: {} });
  const fix = r.exactFix;
  assert.ok(fix.includes('Ignored the Marrow key'), 'refusal notice present');
  return fix.slice(fix.indexOf('Fix:'));
}

function runAdvice(top, fix) {
  const m = /^Fix: (chmod .*?) \(replace a symlink/.exec(fix);
  assert.ok(m, `advice has a command: ${fix.slice(0, 120)}`);
  const r = spawnSync('sh', ['-c', m[1]], { cwd: top, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
}

test('a home with a space gets a quoted operand; running it fixes the right file only', { skip }, () => {
  const top = root('space');
  const key = dummyKey();
  const real = makeHome(top, 'Jo Smith', key);
  const sibling = makeHome(top, 'Jo Smithx', key);
  const fix = notice(top, real);
  assert.ok(fix.includes(`'${real.file}'`), 'file operand quoted');
  runAdvice(top, fix);
  assert.equal(mode(real.file), 0o600);
  assert.equal(mode(sibling.file), 0o644, 'sibling untouched');
  assert.equal(JSON.stringify(fix).includes(key), false);
});

test('a single quote, dollar-paren, backtick and glob characters are quoted and run literally', { skip }, () => {
  for (const name of ["o'brien", 'a$(touch pwned)b', 'a`touch pwned`b', 'g*lob', 'q[1]x', '-dash name']) {
    const top = root('meta');
    const real = makeHome(top, name, dummyKey());
    const sibling = makeHome(top, name.replace(/[*\[\]?]/g, 'Z').replace(/^.$/, 'Z') + 'S', dummyKey());
    const fix = notice(top, real);
    runAdvice(top, fix);
    assert.equal(mode(real.file), 0o600, name);
    assert.equal(mode(sibling.file), 0o644, `${name}: sibling untouched`);
    assert.equal(fs.existsSync(path.join(top, 'pwned')), false, `${name}: nothing executed`);
    assert.equal(fs.existsSync(path.join(top, 'work', 'pwned')), false, `${name}: nothing executed`);
  }
});

test('a path over 200 chars gets no truncated operand', { skip }, () => {
  const top = root('long');
  const real = makeHome(top, 'h'.repeat(210), dummyKey());
  const fix = notice(top, real);
  assert.doesNotMatch(fix, /chmod \d+ ['/]/, 'no path operand');
  assert.equal(fix.includes('hhhhhhhhhh'), false, 'no path text in the advice');
  assert.match(fix, /chmod 600 on the file named above and chmod 700 on its folder/);
});

test('a U+202E component gets no operand with ? or the raw character', { skip }, () => {
  const top = root('bidi');
  const real = makeHome(top, 'h‮e', dummyKey());
  const sibling = makeHome(top, 'hXe', dummyKey());
  const fix = notice(top, real);
  assert.equal(fix.includes('?'), false);
  assert.equal(fix.includes('‮'), false);
  assert.doesNotMatch(fix, /chmod \d+ ['/]/);
  assert.equal(mode(sibling.file), 0o644);
});

test('control characters (newline) in a path give no operand', { skip }, () => {
  const top = root('nl');
  const real = makeHome(top, 'a\nb', dummyKey());
  const fix = notice(top, real);
  assert.doesNotMatch(fix, /chmod \d+ ['/]/);
  assert.equal(fix.includes('\n'), false);
});

test('an unsafe home operand drops the path-based command but still mentions the home', { skip }, () => {
  const top = root('badhome');
  const real = makeHome(top, 'h‮e', dummyKey());
  fs.chmodSync(real.home, 0o775);
  const fix = notice(top, real);
  assert.match(fix, /chmod 700 on its folder and chmod go-w on your home folder/);
  assert.doesNotMatch(fix, /chmod \d+ ['\/]|go-w ['\/]/);
});

test('a short ordinary path still gets the working command (home go-w included)', { skip }, () => {
  const top = root('plain');
  const real = makeHome(top, 'home', dummyKey());
  fs.chmodSync(real.home, 0o775);
  const fix = notice(top, real);
  assert.ok(fix.includes(`chmod 600 ${real.file} && chmod 700 ${real.dir} && chmod go-w ${real.home}`), fix);
  runAdvice(top, fix);
  assert.equal(mode(real.file), 0o600);
  assert.equal(mode(real.dir), 0o700);
  assert.equal(mode(real.home) & 0o022, 0);
});

test('a symlinked directory: advice targets the real path as named, not a shortened one', { skip }, () => {
  const top = root('symdir');
  const real = makeHome(top, 'realhome', dummyKey());
  const link = path.join(top, 'link home');
  fs.symlinkSync(real.home, link);
  const cwd = path.join(top, 'work');
  fs.mkdirSync(cwd, { recursive: true });
  const r = resolveMarrowEnv({ cwd, home: link, env: {} });
  assert.ok(r.exactFix.includes('Ignored the Marrow key'));
  const fix = r.exactFix.slice(r.exactFix.indexOf('Fix:'));
  assert.ok(fix.includes(`'${path.join(link, '.marrow', 'env')}'`), fix);
});
