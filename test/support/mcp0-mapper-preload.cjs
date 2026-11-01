'use strict';

// Test-only (never ships). Preloaded with --require: the seatbelt mapper the keyed hook loads answers the way a failing mapper does, so a test can ask
// what the hook does with it (a call that names the installer or a control-off word is a hold, never a pass). MCP0_MAPPER_MODE:
//   error-stub: the mapper returns its own fixed stop, a `mapper_error` hit
//   error-real: the real mapper fails inside (its env cannot be read), so it answers with its own fail-closed `mapper_error` stop
//   throws:     the mapper throws out of evaluateSeatbeltShell
const Module = require('node:module');
const load = Module._load;
const mode = process.env.MCP0_MAPPER_MODE;
const STOP = {
  decision: 'stop', category: 'Sx', rule: 'Sx', reasons: ['mapper_error'], hits: [{ category: 'Sx', reason: 'mapper_error' }],
  flags: ['parse_unparsed'], parse: 'unparsed', recognized: true, shell: false, risk: [],
};
Module._load = function patched(request, parent, isMain) {
  const loaded = load.call(this, request, parent, isMain);
  if (!/(?:^|[\\/])seatbelt[\\/]mapper(?:\.js)?$/.test(String(request))) return loaded;
  if (mode === 'error-stub') return { ...loaded, evaluateSeatbeltShell: () => STOP };
  if (mode === 'throws') return { ...loaded, evaluateSeatbeltShell() { throw new Error('mapper exploded (test)'); } };
  if (mode === 'error-real') {
    return { ...loaded, evaluateSeatbeltShell: (command, env) => loaded.evaluateSeatbeltShell(command, new Proxy(env, { get() { throw new Error('env unreadable (test)'); } })) };
  }
  return loaded;
};
