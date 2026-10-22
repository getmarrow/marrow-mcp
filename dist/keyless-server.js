"use strict";
/**
 * Keyless start of the MCP server. With no Marrow key anywhere the server reads
 * one, the server used to print "MARROW_API_KEY environment variable is
 * required" and exit 1, which hosts show as a broken server. It now answers the
 * MCP protocol with zero tools and an `instructions` string that says how the
 * owner connects a key.
 *
 * Fail closed: keylessStart is true only for a clear "no key". A key, anything
 * key-shaped, a refused owner key file, a base URL the server would refuse, or
 * any doubt runs the real server path exactly as before.
 *
 * The keyless server judges, checks and records nothing. It starts no child
 * process, opens no network and no file, reads no environment, and writes only
 * to stdout and stderr. Hooks are separate entrypoints and are not touched.
 * Wording and protocol handling match the plugin launcher's keyless stub
 * (marrow-plugins plugins/<plugin>/scripts/marrow-launch.cjs, serveKeyless).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.KEYLESS_NOTICE = exports.KEYLESS_INSTRUCTIONS = void 0;
exports.keylessStart = keylessStart;
exports.keylessProtocolVersion = keylessProtocolVersion;
exports.serveKeylessMcp = serveKeylessMcp;
const index_1 = require("./index");
exports.KEYLESS_INSTRUCTIONS = 'This Marrow server started without a Marrow key on this machine, so it has no tools. '
    + 'It does not judge, check or record any action. '
    + 'Marrow hooks, where they are set up on this machine, are separate from this server and keep their free keyless seatbelt; this server does not show whether any are set up. '
    + 'To connect a Marrow account, the owner creates a key at https://getmarrow.ai/signup and runs npx -y @getmarrow/install@latest activate in their own terminal, then restarts this agent host. '
    + 'A key can not be added from this chat.';
exports.KEYLESS_NOTICE = 'Marrow: no Marrow key on this machine, so the Marrow MCP server started with no tools. Marrow hooks, where they are set up, keep their free keyless seatbelt.';
// The real server's protocolVersion rule (cli.ts noteClientCapabilities): the requested version only when it is one
// of these AND the client's capabilities.elicitation is an object; every other input gets 2024-11-05.
const ELICITATION_PROTOCOL_VERSIONS = ['2025-06-18', '2025-11-25'];
const DEFAULT_PROTOCOL_VERSION = '2024-11-05';
const MAX_LINE_BYTES = 1024 * 1024;
/**
 * Whether the MCP server starts keyless. `resolved` must be the server's own resolveMarrowEnv() result.
 * True only when it found no key (an empty MARROW_API_KEY or MARROW_KEY counts as none, a whitespace one does
 * not), no owner key file was refused, no `--key` argument is given in any form, no fleet key
 * (MARROW_KEY_<SUFFIX>) is set, and the base URL passes the server's own check.
 */
function keylessStart(resolved, argv, env) {
    try {
        if (argv.some((arg) => typeof arg !== 'string' || arg.startsWith('--key')))
            return false;
        if (resolved === null || typeof resolved !== 'object')
            return false;
        const result = resolved;
        if (result.apiKey !== '' || result.missing !== true || result.source !== null || result.ownerFileRefused !== undefined)
            return false;
        // The resolver uses a fleet key only with a direct key and a matching agent identity; one set without them is still a key.
        if (Object.keys(env).some((name) => name.startsWith('MARROW_KEY_') && Boolean(env[name])))
            return false;
        const baseUrl = result.baseUrl || 'https://api.getmarrow.ai';
        if (typeof baseUrl !== 'string')
            return false;
        (0, index_1.validateBaseUrl)(baseUrl);
        return true;
    }
    catch {
        return false;
    }
}
function keylessProtocolVersion(params) {
    const record = params && typeof params === 'object' ? params : {};
    const capabilities = record.capabilities && typeof record.capabilities === 'object' ? record.capabilities : {};
    const requested = typeof record.protocolVersion === 'string' ? record.protocolVersion : '';
    const elicits = Boolean(capabilities.elicitation && typeof capabilities.elicitation === 'object')
        && ELICITATION_PROTOCOL_VERSIONS.includes(requested);
    return elicits ? requested : DEFAULT_PROTOCOL_VERSION;
}
/** Newline-delimited JSON-RPC 2.0 on stdio with zero tools. Exits 0 when stdin ends. */
function serveKeylessMcp(serverVersion, notice) {
    const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
    const send = (id, body) => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, ...body })}\n`);
    const refuse = (id, code, message) => send(id, { error: { code, message } });
    let initialized = false;
    function handle(text) {
        let msg;
        try {
            msg = JSON.parse(text);
        }
        catch {
            refuse(null, -32700, 'Parse error.');
            return;
        }
        if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
            refuse(null, -32600, 'Invalid request.');
            return;
        }
        const request = msg;
        if (request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
            refuse(null, -32600, 'Invalid request.');
            return;
        }
        if (!has(request, 'id'))
            return; // a notification gets no reply
        const id = request.id;
        if (!(typeof id === 'string' || id === null || (typeof id === 'number' && Number.isFinite(id)))) {
            refuse(null, -32600, 'Invalid request.');
            return;
        }
        if (request.method === 'initialize') {
            initialized = true;
            send(id, {
                result: {
                    protocolVersion: keylessProtocolVersion(request.params),
                    capabilities: { tools: { listChanged: false } },
                    serverInfo: { name: 'marrow', version: serverVersion },
                    instructions: exports.KEYLESS_INSTRUCTIONS,
                },
            });
            return;
        }
        if (!initialized) {
            refuse(id, -32002, 'Server not initialized. Send initialize first.');
            return;
        }
        switch (request.method) {
            case 'ping':
                send(id, { result: {} });
                return;
            case 'tools/list':
                send(id, { result: { tools: [] } });
                return;
            case 'prompts/list':
                send(id, { result: { prompts: [] } });
                return;
            case 'resources/list':
                send(id, { result: { resources: [] } });
                return;
            case 'resources/templates/list':
                send(id, { result: { resourceTemplates: [] } });
                return;
            case 'tools/call':
                refuse(id, -32602, 'This server has no tools.');
                return;
            default: refuse(id, -32601, 'Method not found.');
        }
    }
    function dispatch(chunks) {
        const text = Buffer.concat(chunks).toString('utf8');
        if (!text.trim())
            return;
        try {
            handle(text);
        }
        catch {
            refuse(null, -32603, 'Internal error.');
        }
    }
    let chunks = [];
    let size = 0;
    let skipping = false; // inside a line over the limit: dropped up to the next newline, never buffered
    process.stdout.on('error', () => process.exit(0));
    process.stdin.on('error', () => { process.exitCode = 1; });
    process.stdin.on('data', (data) => {
        const chunk = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
        let from = 0;
        while (from < chunk.length) {
            const newline = chunk.indexOf(10, from);
            const to = newline === -1 ? chunk.length : newline;
            if (!skipping) {
                size += to - from;
                if (size > MAX_LINE_BYTES) {
                    skipping = true;
                    chunks = [];
                    size = 0;
                    refuse(null, -32600, 'Request too large.');
                }
                else if (to > from) {
                    chunks.push(chunk.subarray(from, to));
                }
            }
            if (newline === -1)
                return;
            if (!skipping)
                dispatch(chunks);
            chunks = [];
            size = 0;
            skipping = false;
            from = newline + 1;
        }
    });
    process.stdin.on('end', () => {
        if (!skipping)
            dispatch(chunks);
    });
    try {
        process.stderr.write(notice);
    }
    catch {
        // a closed stderr changes nothing
    }
}
//# sourceMappingURL=keyless-server.js.map