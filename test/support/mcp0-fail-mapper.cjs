'use strict';

// Test-only (never ships). Preloaded with --require: makes the seatbelt mapper fail to load, as a broken install would, so a test can ask what the
// keyed hook does when the mapper cannot answer (M2: a call naming the installer or a control word is a hold).
const Module = require('node:module');
const load = Module._load;
Module._load = function patched(request, parent, isMain) {
  if (/(?:^|[\\/])seatbelt[\\/]mapper(?:\.js)?$/.test(String(request))) throw new Error('mapper unavailable (test)');
  return load.call(this, request, parent, isMain);
};
