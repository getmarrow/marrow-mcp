'use strict';

// Test-only (never ships). The backend's risk-category matcher (RISK_CATEGORY_PATTERNS of its risk-categories module, as recorded for
// reaudit-mcp109), applied to the three inputs the hook sends with a runtime call: the synthetic action text, the type and the surfaces.
// package_publish and destructive_action need the backend's action-intent module, which is not reproduced here: publish follows the MCP's
// own mirror (type `publish` or the word), destructive follows the mirror's word list. The rows therefore judge what the text and labels
// CARRY; the owner locks the backend applies to them are the backend's.
const PATTERNS = [
  ['production_deploy', /\b(deploy|release|rollback|rollout|production|prod)\b/i],
  ['source_control', /\b(merge|pull request|pr|github|main|master)\b/i],
  ['data_migration', /\b(migration|migrate|schema|database|sql|table|column)\b/i],
  ['secrets_security', /\b(secret|token|key|credential|rotate|revoke|security|waf|auth)\b/i],
  ['billing_access', /\b(billing|payment|invoice|subscription|plan|tier|permission|access)\b/i],
  ['destructive_action', /\b(?:delete|drop|truncate|purge|destroy|remove all|wipe)\b/i],
];

/** The categories the backend matcher gives (action, type, surfaces) as a sorted array. */
function backendCategories(action, type, surfaces) {
  const text = `${action} ${type} ${(surfaces || []).join(' ')}`;
  const found = new Set(PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([category]) => category));
  if (String(type).toLowerCase() === 'publish' || /\bpublish\b/i.test(text)) found.add('package_publish');
  return [...found].sort();
}

/** Categories in `wanted` that `got` lacks. */
const missing = (wanted, got) => [...wanted].filter((category) => !got.includes(category));

/**
 * A hold (the MCP-10 route, a T2 write) is merged with the classification of the whole call: its label stays the first sentence of the
 * action, the call's other surfaces join the surface list and the types they displaced follow after `; classified `. This is the hold's own
 * label (`classified <tool> action: security on <hold surface>`), what the call alone gives.
 */
function heldLabel(action) {
  const first = String(action).split('; classified ')[0];
  const at = first.indexOf(' on ');
  if (at < 0) return first;
  const surfaces = first.slice(at + 4).split(', ').filter((surface) => surface === 'marrow-control' || surface === 'persistence');
  return `${first.slice(0, at + 4)}${surfaces.join(', ')}`;
}

module.exports = { backendCategories, missing, heldLabel };
