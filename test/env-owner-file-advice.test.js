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

// Everything chmod-shaped in the advice, run through the link, must change nothing.
function runAnyChmod(top, fix) {
  for (const m of fix.matchAll(/chmod (?:600|700|go-w) (\S+)/g)) {
    spawnSync('sh', ['-c', `chmod 600 ${m[1]}`], { cwd: top });
  }
}

test('a symlinked owner file: no chmod operand, advice says replace the link, target untouched', { skip }, () => {
  const top = root('symfile');
  const real = makeHome(top, 'home', dummyKey());
  const target = path.join(top, 'target-env');
  fs.writeFileSync(target, `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o644 });
  fs.chmodSync(target, 0o644);
  fs.rmSync(real.file);
  fs.symlinkSync(target, real.file);
  const fix = notice(top, real);
  assert.doesNotMatch(fix, /chmod \d+ \S*\//, 'no chmod operand');
  assert.match(fix, /replace the symlink with the real file/);
  assert.equal(fix.includes(real.file), false, 'operand-free fix');
  runAnyChmod(top, fix);
  assert.equal(mode(target), 0o644, 'link target unchanged');
  assert.equal(fs.lstatSync(real.file).isSymbolicLink(), true);
});

test('a symlinked folder or ancestor: no chmod operand, advice says remove the link from the chain', { skip }, () => {
  const top = root('symchain');
  const real = makeHome(top, 'realhome', dummyKey());
  const link = path.join(top, 'link-home');
  fs.symlinkSync(real.home, link);
  const cwd = path.join(top, 'work');
  fs.mkdirSync(cwd, { recursive: true });
  // ancestor symlink (home itself is the link)
  const r1 = resolveMarrowEnv({ cwd, home: link, env: {} });
  const fix1 = r1.exactFix.slice(r1.exactFix.indexOf('Fix:'));
  assert.doesNotMatch(fix1, /chmod \d+ \S*\//);
  assert.match(fix1, /remove the symlink from the folder chain/);
  runAnyChmod(top, fix1);
  assert.equal(mode(real.file), 0o644);
  assert.equal(mode(real.dir), 0o700);
  // ~/.marrow itself is a symlink
  const home2 = path.join(top, 'home2');
  fs.mkdirSync(home2, { mode: 0o700 });
  fs.symlinkSync(real.dir, path.join(home2, '.marrow'));
  const r2 = resolveMarrowEnv({ cwd, home: home2, env: {} });
  const fix2 = r2.exactFix.slice(r2.exactFix.indexOf('Fix:'));
  assert.doesNotMatch(fix2, /chmod \d+ \S*\//);
  assert.match(fix2, /remove the symlink from the folder chain/);
  runAnyChmod(top, fix2);
  assert.equal(mode(real.file), 0o644);
});

// Guard boundaries of shellOperand/printablePath.
test('U+2028 and U+2029 in a path component give no operand', { skip }, () => {
  for (const ch of ['\u2028', '\u2029']) {
    const top = root('zl');
    const real = makeHome(top, `h${ch}e`, dummyKey());
    const fix = notice(top, real);
    assert.doesNotMatch(fix, /chmod \d+ ['/]/, `U+${ch.codePointAt(0).toString(16)}`);
    assert.equal(fix.includes(ch), false);
    assert.match(fix, /chmod 600 on the file named above/);
  }
});

test('file path of exactly 200 code points gets an operand; 201 does not', { skip }, () => {
  const top = root('len');
  const base = path.join(top, 'x');
  // makeHome file = <top>/<name>/.marrow/env ; pad name so the file path hits the target length.
  const overhead = path.join(top, '', '.marrow', 'env').length + 1;
  for (const [len, expectOperand] of [[200, true], [201, false]]) {
    const name = 'n'.repeat(len - overhead);
    const real = makeHome(top, name, dummyKey());
    assert.equal(Array.from(real.file).length, len);
    const fix = notice(top, real);
    if (expectOperand) assert.match(fix, /chmod 600 \S+ && chmod 700/, `len ${len}`);
    else assert.doesNotMatch(fix, /chmod \d+ ['/]/, `len ${len}`);
  }
  assert.ok(base);
});
