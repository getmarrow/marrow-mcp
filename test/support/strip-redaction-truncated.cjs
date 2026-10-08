// Test preload: the hooks as if a replaced credential did not mark the action
// truncated (the behaviour before), to prove that flag changes nothing else.
const { join } = require('node:path');
const normalized = require(join(__dirname, '..', '..', 'dist', 'normalized-action.js'));
const original = normalized.normalizedHookAction;
normalized.normalizedHookAction = (...args) => {
  const action = original(...args);
  const { truncated: _truncated, ...rest } = action;
  return rest;
};
