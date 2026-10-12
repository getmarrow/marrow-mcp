const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  codexOfficialMarrowServer,
  cursorOfficialMarrowServer,
  isOfficialMarrowMcpEventOnHost,
  npmProjectConfigIsHarmless: harmless,
  resetOwnServerIdentityCache,
} = require('../dist/own-server-identity.js');
const { MARROW_OWN_TOOL_NAMES } = require('../dist/own-tool.js');

const OWN = [...MARROW_OWN_TOOL_NAMES];
const OFFICIAL_TOML = '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n';
const BIN_TOML = '[mcp_servers.marrow]\ncommand = "marrow-mcp"\nargs = []\n';
const EVIL = 'https://evil.example/';
const DUMMY = randomBytes(12).toString('hex');

/** The npx form on Codex over a real project folder; the config comes from an in-memory reader. */
function codexNpx(proj, home, { toml = OFFICIAL_TOML, env = {} } = {}) {
  const codexHome = join(home, '.codex');
  const table = { [join(codexHome, 'config.toml')]: toml };
  const read = (path) => (Object.prototype.hasOwnProperty.call(table, path) ? { state: 'ok', text: table[path] } : { state: 'missing' });
  return codexOfficialMarrowServer({ env: { CODEX_HOME: codexHome, ...env }, read, processArgs: null, processCwd: proj, userHome: home });
}

function scratch(fn) {
  const root = mkdtempSync(join(tmpdir(), 'r3-npmcfg-'));
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  mkdirSync(home);
  mkdirSync(proj);
  try { return fn({ root, home, proj }); } finally { rmSync(root, { recursive: true, force: true }); }
}

/** Write a project config file with the given text (a Buffer for raw bytes). */
const put = (dir, content) => writeFileSync(join(dir, '.npmrc'), content);

// ------------------------------------------------------------------ the parser: neighbours (proven)

const ALLOWLIST = [
  'save-exact=true', 'save-prefix=~', 'engine-strict=true', 'fund=false', 'audit=false', 'audit-level=high', 'loglevel=warn', 'progress=false',
  'color=always', 'unicode=false', 'update-notifier=false',
  'package-lock=false', 'package-lock-only=true', 'lockfile-version=3', 'legacy-peer-deps=true', 'strict-peer-deps=true',
  'git-tag-version=false', 'sign-git-tag=true', 'tag-version-prefix=v', 'message=chore: release %s',
  'init-author-name=A Person', 'init-author-email=a@example.test', 'init-license=MIT', 'init-version=0.0.1',
  'auto-install-peers=true', 'shamefully-hoist=true', 'strict-peer-dependencies=false', 'node-linker=hoisted',
  'link-workspace-packages=true', 'prefer-workspace-packages=true',
];

test('npm project config parser: every allowlisted key alone is harmless (30 keys)', () => {
  assert.equal(ALLOWLIST.length, 30);
  for (const line of ALLOWLIST) assert.equal(harmless(`${line}\n`), true, line);
  for (const line of ALLOWLIST) assert.equal(harmless(line), true, `${line} (no final newline)`);
  assert.equal(harmless(`${ALLOWLIST.join('\n')}\n`), true, 'all together');
});

test('npm project config parser: realistic files, comments, empty and the default registry credential line are harmless', () => {
  const ok = [
    '',
    '\n',
    '   \n\t\n',
    '; only a comment\n# another\n',
    'save-exact=true\nengine-strict=true\n',
    '# project settings\nsave-exact=true\n; keep versions\nengine-strict=true\n',
    'save-exact = true\nengine-strict = true\n',
    '\tsave-exact\t=\ttrue\t\n',
    'save-exact=true ; inline comment\nengine-strict=true # inline comment\n',
    // a commented-out redirect is a comment (real npm leaves the registry alone: out/evidence/npm-probe.tsv)
    '; registry=https://evil.example/\nsave-exact=true\n',
    '# @getmarrow:registry=https://evil.example/\n',
    'engine-strict="true"\n',
    "engine-strict='false'\n",
    'save-exact=true\r\nengine-strict=true\r\n',
    'legacy-peer-deps=true\naudit=false\nfund=false\n',
    // the value of a default registry credential line is never read: a token, an env reference, or nothing
    `//registry.npmjs.org/:_authToken=${DUMMY}\n`,
    '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nsave-exact=true\n',
    `//registry.npmjs.org/:_auth=${DUMMY}\n`,
    `//registry.npmjs.org/:_password=${DUMMY}\n`,
    '//registry.npmjs.org/:username=someone\n',
    '//registry.npmjs.org/:email=someone@example.test\n',
    '//registry.npmjs.org/:always-auth=true\n',
    // last duplicate wins: a bad first engine-strict then a good one
    'engine-strict=maybe\nengine-strict=true\n',
    'engine-strict=true\nengine-strict=false\n',
  ];
  for (const text of ok) assert.equal(harmless(text), true, JSON.stringify(text));
});

// ------------------------------------------------------------------ the parser: abuse (held)

const DENIED = [
  'registry', 'replace-registry-host', 'cafile', 'ca', 'cert', 'key', 'strict-ssl', 'proxy', 'https-proxy', 'noproxy', 'cache', 'prefix',
  'globalconfig', 'userconfig', 'script-shell', 'node-options', 'ignore-scripts', 'before', 'include', 'omit', 'global', 'location',
  'workspace', 'workspaces', 'npm-version', '@getmarrow:registry', '@modelcontextprotocol:registry', '@acme:registry',
];

test('npm project config parser: every redirecting or trust-changing key is held, alone and beside harmless keys', () => {
  for (const key of DENIED) {
    assert.equal(harmless(`${key}=${EVIL}\n`), false, key);
    assert.equal(harmless(`save-exact=true\n${key}=${EVIL}\nengine-strict=true\n`), false, `${key} between harmless keys`);
    assert.equal(harmless(`${key}=${EVIL}\nsave-exact=true\n`), false, `${key} first`);
    assert.equal(harmless(`${key}=\n`), false, `${key} with an empty value`);
  }
});

test('npm project config parser: key spelling tricks are held', () => {
  const held = [
    // case: npm keys are case-sensitive, and only the exact lower-case names are listed
    'REGISTRY=https://evil.example/\n', 'Registry=https://evil.example/\n', '@GetMarrow:Registry=https://evil.example/\n', 'Save-Exact=true\n', 'SAVE-EXACT=true\n',
    // padding, quoting, arrays, sections, comment marks and expansion inside the key
    '  registry  =  https://evil.example/\n', '\tregistry\t=\thttps://evil.example/\n',
    '"registry"=https://evil.example/\n', "'registry'=https://evil.example/\n", '"save-exact"=true\n',
    'registry[]=https://evil.example/\n', '@getmarrow:registry[]=https://evil.example/\n', 'save-exact[]=true\n',
    '[section]\nsave-exact=true\n', '[registry]\nsave-exact=true\n', '[x]\nregistry=https://evil.example/\n', ' [x]\nsave-exact=true\n',
    'registry;x=https://evil.example/\n', 'registry#x=https://evil.example/\n', 'save-exact;registry=true\n',
    '${HOME}registry=https://evil.example/\n', 'save-exact${X}=true\n', '${save-exact}=true\n',
    'registry\n', 'save-exact\n', '=true\n', '=\n', '__proto__=1\n',
    // non-ASCII look-alikes, zero-width, no-break space, BOM
    'registгy=https://evil.example/\n', 'regis​try=https://evil.example/\n', ' registry=https://evil.example/\n', 'registry =https://evil.example/\n',
    '﻿registry=https://evil.example/\n', '﻿save-exact=true\n', '﻿; comment\nsave-exact=true\n',
    // NUL and the other control characters
    'regis\0try=https://evil.example/\n', 'save-exact=true\0\n', 'save-exact\u0001=true\n',
  ];
  for (const text of held) assert.equal(harmless(text), false, JSON.stringify(text));
});

test('npm project config parser: line-ending and continuation tricks are held', () => {
  const held = [
    'save-exact=true\r\nregistry=https://evil.example/\r\n',
    'save-exact=true\rregistry=https://evil.example/\n', // npm splits at a lone CR
    'save-exact=true\r\rregistry=https://evil.example/\n',
    '\rregistry=https://evil.example/\n',
    'save-exact=true\r',
    'save-exact=true\r\r\n',
    'save-exact=true \\\nregistry=https://evil.example/\n',
    '; comment \\\nregistry=https://evil.example/\n',
    'save-exact=true \\\nfund=false\n',
    'save-exact=true\\\n',
    'message=release \\ \n',
    'save-exact=true registry=https://evil.example/\n',
    'save-exact=true registry=https://evil.example/\n',
    'registry=https://evil.example/ x\n',
    'save-exact=true\u000Bregistry=https://evil.example/\n',
    'save-exact=true\u000Cregistry=https://evil.example/\n',
    'save-exact=true\u0085registry=https://evil.example/\n',
    'save-exact=true\u007Fregistry=https://evil.example/\n',
    '; comment \n',
  ];
  for (const text of held) assert.equal(harmless(text), false, JSON.stringify(text));
});

test('npm project config parser: duplicates, engine-strict values and the default registry shape', () => {
  const held = [
    'registry=https://registry.npmjs.org/\nregistry=https://evil.example/\n', // good then evil
    'registry=https://evil.example/\nregistry=https://registry.npmjs.org/\n', // evil then good: still present
    'engine-strict=true\nengine-strict=maybe\n', // the last one wins and is not a boolean
    'engine-strict=maybe\n', 'engine-strict=\n', 'engine-strict=TRUE\n', 'engine-strict=1\n', 'engine-strict=${X}\n', 'engine-strict=true,false\n', 'engine-strict="true\n',
    // credential-shaped keys that are not the default registry's own credential fields
    `//evil.example/:_authToken=${DUMMY}\nregistry=${EVIL}\n`, `//evil.example/:_authToken=${DUMMY}\n`, `//127.0.0.1:1/:_authToken=${DUMMY}\n`,
    `//registry.npmjs.org.evil/:_authToken=${DUMMY}\n`, `//registry.npmjs.org.evil.example/:_authToken=${DUMMY}\n`,
    `//registry.npmjs.org/evil/:_authToken=${DUMMY}\n`, `//registry.npmjs.org/:_authToken/x=${DUMMY}\n`, `//registry.npmjs.org//:_authToken=${DUMMY}\n`,
    `//registry.npmjs.org:_authToken=${DUMMY}\n`, `//registry.npmjs.org/_authToken=${DUMMY}\n`, `registry.npmjs.org/:_authToken=${DUMMY}\n`,
    `//REGISTRY.NPMJS.ORG/:_authToken=${DUMMY}\n`, `//Registry.npmjs.org/:_authToken=${DUMMY}\n`, `//registry.npmjs.org/:_AUTHTOKEN=${DUMMY}\n`,
    `//registry.npmjs.org/:registry=${EVIL}\n`, `//registry.npmjs.org/:cafile=./ca.pem\n`, `//registry.npmjs.org/:certfile=./c.pem\n`, `//registry.npmjs.org/:keyfile=./k.pem\n`,
    `//registry.npmjs.org/:_authToken\n`, `//registry.npmjs.org/:\n`, `//registry.npmjs.org/\n`,
    `//registry.npmjs.org/:_authToken=${DUMMY}\nregistry=${EVIL}\n`,
    `@getmarrow:registry=${EVIL}\n//registry.npmjs.org/:_authToken=${DUMMY}\n`,
  ];
  for (const text of held) assert.equal(harmless(text), false, JSON.stringify(text));
});

test('npm project config parser: a long blank run or a long key is linear', () => {
  const started = process.hrtime.bigint();
  const blanks = `${' '.repeat(60000)}x\n`;
  assert.equal(harmless(blanks), false);
  assert.equal(harmless(`${'\t'.repeat(30000)}save-exact=true${' '.repeat(30000)}\n`), true);
  assert.equal(harmless(`save-exact=${'x'.repeat(60000)}\n`), true);
  assert.equal(harmless(`${'a'.repeat(60000)}=1\n`), false);
  assert.equal(harmless(`${'#'.repeat(60000)}\n${';'.repeat(60000)}\n`), true);
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 1000, 'under a second');
});

// ------------------------------------------------------------------ the walk: files on disk, the npx form

test('B4 follow-up neighbours: a harmless project config keeps the README npx form proven (Codex and Cursor)', () => {
  const cases = [
    ['save-exact only', 'save-exact=true\n'],
    ['save-exact + engine-strict + comment', '# settings\nsave-exact=true\nengine-strict=true\n'],
    ['empty', ''],
    ['comments only', '; nothing here\n'],
    ['default registry credential line only', `//registry.npmjs.org/:_authToken=${DUMMY}\n`],
    ['CRLF', 'save-exact=true\r\nengine-strict=true\r\n'],
    ['exactly 64 KB', `${'#'.repeat(65535)}\n`],
    ['every allowlisted key', `${ALLOWLIST.join('\n')}\n`],
  ];
  for (const [label, text] of cases) {
    scratch(({ home, proj }) => {
      put(proj, text);
      assert.deepEqual(codexNpx(proj, home), { official: true, reason: 'official' }, `codex: ${label}`);
      const cursor = cursorOfficialMarrowServer({
        home,
        processCwd: proj,
        env: {},
        onlyServer: false,
        read: (path) => (path === join(home, '.cursor', 'mcp.json') ? { state: 'ok', text: JSON.stringify({ mcpServers: { marrow: { command: 'npx', args: ['-y', '@getmarrow/mcp'] } } }) } : { state: 'missing' }),
      });
      assert.deepEqual(cursor, { official: true, reason: 'official' }, `cursor: ${label}`);
    });
  }
});

test('B4 follow-up neighbours: a harmless config in the working dir, a parent and a grandparent, each fine', () => {
  scratch(({ root, home }) => {
    const deep = join(root, 'a', 'b', 'c');
    mkdirSync(deep, { recursive: true });
    put(join(root, 'a'), 'save-exact=true\n');
    put(join(root, 'a', 'b'), 'engine-strict=true\n');
    put(deep, 'legacy-peer-deps=true\n');
    assert.equal(codexNpx(deep, home).official, true);
  });
});

test('B4 follow-up: a project config that redirects or changes trust is held, wherever it sits in the walk', () => {
  const bad = [
    `registry=${EVIL}\n`,
    `@getmarrow:registry=${EVIL}\n`,
    `save-exact=true\nregistry=${EVIL}\n`,
    `//evil.example/:_authToken=${DUMMY}\nregistry=${EVIL}\n`,
    'cafile=./ca.pem\n', 'before=2000-01-01\n', 'cache=./c\n', 'node-options=--require=./x.js\n', 'prefix=./p\n', 'script-shell=/bin/sh\n',
    `//registry.npmjs.org.evil/:_authToken=${DUMMY}\n`,
    'REGISTRY=https://evil.example/\n', '[x]\nsave-exact=true\n', 'registry[]=https://evil.example/\n', '"registry"=https://evil.example/\n',
    'save-exact=true\r\nregistry=https://evil.example/\r\n', 'save-exact=true\rregistry=https://evil.example/\n', '﻿registry=https://evil.example/\n',
    'save-exact=true \\\nregistry=https://evil.example/\n', 'engine-strict=maybe\n',
  ];
  for (const text of bad) {
    scratch(({ root, home, proj }) => {
      put(proj, text);
      assert.equal(codexNpx(proj, home).official, false, `project: ${JSON.stringify(text)}`);
    });
    scratch(({ root, home }) => {
      const sub = join(root, 'p', 'q');
      mkdirSync(sub, { recursive: true });
      put(join(root, 'p'), text); // the bad config is in an ancestor of the working dir; the working dir has none
      assert.equal(codexNpx(sub, home).official, false, `ancestor: ${JSON.stringify(text)}`);
    });
  }
});

test('B4 follow-up: an ancestor config that is bad beside a project one that is fine (and the reverse) is held', () => {
  scratch(({ root, home }) => {
    const sub = join(root, 'p', 'q');
    mkdirSync(sub, { recursive: true });
    put(join(root, 'p'), `registry=${EVIL}\n`);
    put(sub, 'save-exact=true\n');
    assert.equal(codexNpx(sub, home).official, false);
  });
  scratch(({ root, home }) => {
    const sub = join(root, 'p', 'q');
    mkdirSync(sub, { recursive: true });
    put(join(root, 'p'), 'save-exact=true\n');
    put(sub, `@getmarrow:registry=${EVIL}\n`);
    assert.equal(codexNpx(sub, home).official, false);
  });
  scratch(({ root, home }) => {
    // two working dirs (hook cwd and payload cwd): one fine, one bad
    const a = join(root, 'a');
    const b = join(root, 'b');
    mkdirSync(a);
    mkdirSync(b);
    put(a, 'save-exact=true\n');
    put(b, `registry=${EVIL}\n`);
    const codexHome = join(home, '.codex');
    const read = (path) => (path === join(codexHome, 'config.toml') ? { state: 'ok', text: OFFICIAL_TOML } : { state: 'missing' });
    const verdict = codexOfficialMarrowServer({ env: { CODEX_HOME: codexHome }, read, processArgs: null, processCwd: a, cwds: [b], userHome: home });
    assert.equal(verdict.official, false);
  });
});

test('B4 follow-up: the file itself — size, NUL, UTF-8, links, folders and pipes', () => {
  // 64 KB is read; one byte more is not proven
  scratch(({ home, proj }) => {
    put(proj, `${'#'.repeat(65535)}\n`);
    assert.equal(codexNpx(proj, home).official, true, '65536 bytes');
    put(proj, `${'#'.repeat(65536)}\n`);
    assert.equal(codexNpx(proj, home).official, false, '65537 bytes');
    put(proj, `save-exact=true\n${'#'.repeat(70000)}\n`);
    assert.equal(codexNpx(proj, home).official, false, 'harmless but over the cap');
  });
  // NUL and invalid UTF-8 (a harmless-looking key beside them)
  for (const bytes of [
    Buffer.from('save-exact=true\n\0'),
    Buffer.from('save-exact=tr\0ue\n'),
    Buffer.concat([Buffer.from('save-exact=true\n# '), Buffer.from([0xff, 0xfe, 0xfd]), Buffer.from('\n')]),
    Buffer.concat([Buffer.from('message='), Buffer.from([0xc3, 0x28]), Buffer.from('\n')]), // a bad two-byte sequence
    Buffer.concat([Buffer.from('message='), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from('\n')]), // a UTF-16 surrogate in UTF-8
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('save-exact=true\n', 'utf16le')]), // UTF-16LE with BOM
  ]) {
    scratch(({ home, proj }) => {
      put(proj, bytes);
      assert.equal(codexNpx(proj, home).official, false, JSON.stringify([...bytes].slice(0, 12)));
    });
  }
  // valid multi-byte text in a value is fine
  scratch(({ home, proj }) => {
    put(proj, 'init-author-name=Zoë Müller 山田\n');
    assert.equal(codexNpx(proj, home).official, true);
  });
  // a U+FFFD that is really in the file round-trips and is valid text
  scratch(({ home, proj }) => {
    put(proj, 'message=café �\n');
    assert.equal(codexNpx(proj, home).official, true);
  });
  // a link to a device, a link to a regular file, a dangling link, a link loop, a folder, a pipe
  scratch(({ root, home, proj }) => {
    symlinkSync('/dev/zero', join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'symlink to /dev/zero');
  });
  scratch(({ root, home, proj }) => {
    symlinkSync('/dev/null', join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'symlink to /dev/null (a device, even though it reads empty)');
  });
  scratch(({ root, home, proj }) => {
    writeFileSync(join(root, 'real-ok'), 'save-exact=true\n');
    symlinkSync(join(root, 'real-ok'), join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, true, 'symlink to a harmless regular file');
  });
  scratch(({ root, home, proj }) => {
    writeFileSync(join(root, 'real-bad'), `registry=${EVIL}\n`);
    symlinkSync(join(root, 'real-bad'), join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'symlink to a redirecting regular file');
  });
  scratch(({ root, home, proj }) => {
    symlinkSync(join(root, 'does-not-exist'), join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, true, 'dangling symlink: npm reads nothing');
  });
  scratch(({ root, home, proj }) => {
    symlinkSync(join(proj, '.npmrc'), join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'symlink loop');
  });
  scratch(({ root, home, proj }) => {
    symlinkSync(root, join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'symlink to a folder');
  });
  scratch(({ home, proj }) => {
    mkdirSync(join(proj, '.npmrc'));
    assert.equal(codexNpx(proj, home).official, false, 'a folder named like the file');
  });
  scratch(({ home, proj }) => {
    const made = spawnSync('mkfifo', [join(proj, '.npmrc')]);
    assert.equal(made.status, 0, 'mkfifo');
    assert.equal(codexNpx(proj, home).official, false, 'a named pipe');
  });
  if (process.getuid && process.getuid() !== 0) {
    scratch(({ home, proj }) => {
      put(proj, 'save-exact=true\n');
      chmodSync(join(proj, '.npmrc'), 0o000);
      assert.equal(codexNpx(proj, home).official, false, 'unreadable file');
    });
  }
});

test('B4 follow-up: what stays as round 2 built it (user config, bin and installer forms, npm_config_* env, local copies)', () => {
  // $HOME/.npmrc is npm's user config, not project content: any content, still proven (the project sits under the home, so the walk reaches it)
  scratch(({ home }) => {
    const underHome = join(home, 'work', 'proj');
    mkdirSync(underHome, { recursive: true });
    put(home, `registry=${EVIL}\n`);
    assert.equal(codexNpx(underHome, home).official, true, 'user config with a registry');
    put(home, '[x]\n\0 not even text\n');
    assert.equal(codexNpx(underHome, home).official, true, 'user config that is not parsable');
    // ... but a project config beside it is still judged on its own
    put(join(home, 'work'), `registry=${EVIL}\n`);
    assert.equal(codexNpx(underHome, home).official, false, 'a project config under the home is not the user config');
  });
  // the installed bin form never reads a project config
  scratch(({ home, proj }) => {
    put(proj, `registry=${EVIL}\n`);
    assert.equal(codexNpx(proj, home, { toml: BIN_TOML }).official, true);
  });
  // npm_config_* in the hook env is still any-means-held, with or without a harmless project config
  for (const name of ['npm_config_registry', 'NPM_CONFIG_REGISTRY', 'npm_config_userconfig', 'NPM_CONFIG_GLOBALCONFIG', 'npm_config_save_exact']) {
    scratch(({ home, proj }) => {
      assert.equal(codexNpx(proj, home, { env: { [name]: 'x' } }).official, false, name);
      put(proj, 'save-exact=true\n');
      assert.equal(codexNpx(proj, home, { env: { [name]: 'x' } }).official, false, `${name} + harmless project config`);
    });
  }
  // a planted local copy still unproves the npx form (a harmless project config does not change that)
  scratch(({ home, proj }) => {
    put(proj, 'save-exact=true\n');
    mkdirSync(join(proj, 'node_modules', '@getmarrow', 'mcp'), { recursive: true });
    assert.equal(codexNpx(proj, home).official, false);
  });
});

test('B4 follow-up end to end: the README npx form with a harmless project config skips all 58 own tools; a redirecting one holds all 58', () => {
  assert.equal(OWN.length, 58);
  const saved = { HOME: process.env.HOME, CODEX_HOME: process.env.CODEX_HOME };
  const run = (text) => scratch(({ home, proj }) => {
    const codexHome = join(home, '.codex');
    mkdirSync(codexHome, { recursive: true });
    writeFileSync(join(codexHome, 'config.toml'), OFFICIAL_TOML);
    put(proj, text);
    process.env.HOME = home;
    process.env.CODEX_HOME = codexHome;
    try {
      let skipped = 0;
      for (const name of OWN) {
        resetOwnServerIdentityCache();
        if (isOfficialMarrowMcpEventOnHost('codex', { tool_name: `mcp__marrow__${name}` }, { cwd: proj })) skipped += 1;
      }
      return skipped;
    } finally {
      process.env.HOME = saved.HOME;
      if (saved.CODEX_HOME === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = saved.CODEX_HOME;
      resetOwnServerIdentityCache();
    }
  });
  assert.equal(run('save-exact=true\n'), 58);
  assert.equal(run('save-exact=true\nengine-strict=true\n# note\n'), 58);
  assert.equal(run(''), 58);
  assert.equal(run(`//registry.npmjs.org/:_authToken=${DUMMY}\n`), 58);
  assert.equal(run(`registry=${EVIL}\n`), 0);
  assert.equal(run(`save-exact=true\n@getmarrow:registry=${EVIL}\n`), 0);
});
