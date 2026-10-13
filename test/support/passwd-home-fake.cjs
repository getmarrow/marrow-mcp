'use strict';

// Test-only preload (never ships). Receipts, mode evidence and keys live under the passwd home
// (os.userInfo().homedir), which an environment variable cannot change. A hook process the tests
// spawn would therefore read and write the real machine's ~/.marrow. test/support/isolated-environment.cjs
// puts this file on NODE_OPTIONS of every child the suite starts, with SBT_PASSWD_HOME pointing at an
// empty scratch directory, so os.userInfo().homedir is that directory and never the real home.
const os = require('node:os');

const fake = process.env.SBT_PASSWD_HOME;
if (fake && fake.startsWith('/') && !os.userInfo.__sbtPasswdFake) {
  const real = os.userInfo;
  os.userInfo = function userInfo(options) {
    return { ...real.call(os, options), homedir: fake };
  };
  os.userInfo.__sbtPasswdFake = true;
}
