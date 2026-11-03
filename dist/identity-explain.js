"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.printableAgentId = printableAgentId;
exports.explainAgentIdSource = explainAgentIdSource;
exports.explanationLabelJson = explanationLabelJson;
exports.agentIdSourceSentence = agentIdSourceSentence;
const env_1 = require("./env");
const redact_1 = require("./redact");
// Where did this process get its agent id? resolveMarrowEnv says which variable and which origin won (names
// only); this module words them for the tool 403. It prints the agent id, a variable name and an origin: never a key,
// never an env block. Nothing here feeds a hook decision, a request header or a key choice. Only an owner-file id
// names a file, by its `~/...` label; every other origin has `file: null`.
const UNSAFE_ID = '<unsafe id>';
const MAX_PRINTED_ID = 64;
/**
 * The id as printed: exact, unless it fails the hook head's SAFE_AGENT_ID check (spaces, blank, control, format and
 * look-alike characters), is over 64 characters, or the redactor would hide part of it (an API key pasted into the
 * id variable by mistake is never echoed).
 */
function printableAgentId(value) {
    if (!value)
        return null;
    if (!env_1.SAFE_AGENT_ID.test(value) || value.length > MAX_PRINTED_ID)
        return UNSAFE_ID;
    return (0, redact_1.redactSensitiveText)(value) === value ? value : UNSAFE_ID;
}
/**
 * Explains where `resolved.agentId` came from: the variable and the origin resolveMarrowEnv picked. An owner-file id
 * names that owner file; every other origin has no file. No id: origin none.
 */
function explainAgentIdSource(resolved) {
    const source = resolved.agentIdSource;
    const id = resolved.agentId;
    if (!source || source.origin === 'none' || !source.variable || !id) {
        return { agent_id: null, variable: null, origin: 'none', file: null, fileLabel: null };
    }
    const base = { agent_id: printableAgentId(id), variable: source.variable, origin: source.origin, ...(source.keyVariable ? { keyVariable: source.keyVariable } : {}) };
    const file = source.origin === 'owner_file' ? source.ownerFile ?? null : null;
    return { ...base, file, fileLabel: file };
}
/** The four keys with `file` as the label: the form that goes into the tool 403 (`agent_id_source`). */
function explanationLabelJson(lookup) {
    return { agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.fileLabel };
}
/**
 * The one sentence for the tool 403. Empty when no id is set. It names the variable and the origin only: no key,
 * no env block, no command that changes identity.
 */
function agentIdSourceSentence(lookup, subject = 'This server') {
    if (lookup.origin === 'none' || !lookup.variable)
        return '';
    if (lookup.origin === 'owner_file')
        return `${subject} took the id from ${lookup.variable} in ${lookup.fileLabel ?? '~/.marrow/env'}.`;
    let text = `${subject} took the id from ${lookup.variable} in this server's environment (set by the host or its launcher).`;
    if (lookup.origin === 'fleet_key_match' && lookup.keyVariable && /^MARROW_KEY_[A-Z0-9]+$/.test(lookup.keyVariable)) {
        text += ` The key was picked by that id from ${lookup.keyVariable}.`;
    }
    return text;
}
//# sourceMappingURL=identity-explain.js.map