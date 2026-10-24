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
 * Protocol handling matches the plugin launcher's keyless stub
 * (marrow-plugins plugins/<plugin>/scripts/marrow-launch.cjs, serveKeyless).
 *
 * Never looser than the exit 1 it replaces: until a valid `initialize` request has
 * been answered, a frame that is not JSON-RPC 2.0 (a Cursor or Claude hook payload
 * piped to the entry, a parse error, an oversize line) or an end of stdin ends the
 * process with the no-key refusal on stderr, nothing on stdout, and exit 1. After
 * an initialize, the end of stdin is exit 0.
 *
 * The key text (URL, activate command, plugin steps, the refusal) is owned by cli.ts
 * and passed in; this file holds no second copy of it.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.KEYLESS_NOTICE = void 0;
exports.keylessInstructions = keylessInstructions;
exports.keylessStart = keylessStart;
exports.keylessProtocolVersion = keylessProtocolVersion;
exports.serveKeylessMcp = serveKeylessMcp;
const index_1 = require("./index");
/** The `instructions` string of the initialize answer. */
function keylessInstructions(parts) {
    const connect = parts.pluginSteps
        ? `To connect a Marrow account, the owner follows these steps. ${parts.pluginSteps} `
        : `To connect a Marrow account, the owner creates a key at ${parts.getKeyUrl} and runs ${parts.activateCommand} in their own terminal, then restarts this agent host. `;
    return 'This Marrow server started without a Marrow key on this machine, so it has no tools. '
        + 'It does not judge, check or record any action. '
        + (parts.pluginSteps ? '' : 'Marrow hooks, where they are set up on this machine, are separate from this server and keep their free keyless seatbelt; this server does not show whether any are set up. ')
        + connect
        + 'A key can not be added from this chat.';
}
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
/** Newline-delimited JSON-RPC 2.0 on stdio with zero tools. Exits 0 when stdin ends after an initialize, 1 for a non-MCP start. */
function serveKeylessMcp(serverVersion, texts) {
    const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
    const send = (id, body) => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, ...body })}\n`);
    const refuse = (id, code, message) => send(id, { error: { code, message } });
    let initialized = false;
    // Today's no-key exit: the refusal on stderr, nothing on stdout, exit 1.
    function exitAsNoKey() {
        try {
            process.stderr.write(texts.refusal);
        }
        catch {
            // a closed stderr changes nothing
        }
        process.exit(1);
    }
    // A frame that is not a usable JSON-RPC 2.0 message. Before an initialize it proves the process was not started by an MCP host.
    function badFrame(id, code, message) {
        if (!initialized)
            exitAsNoKey();
        refuse(id, code, message);
    }
    function handle(text) {
        let msg;
        try {
            msg = JSON.parse(text);
        }
        catch {
            badFrame(null, -32700, 'Parse error.');
            return;
        }
        if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
            badFrame(null, -32600, 'Invalid request.');
            return;
        }
        const request = msg;
        if (request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
            badFrame(null, -32600, 'Invalid request.');
            return;
        }
        if (!has(request, 'id'))
            return; // a notification gets no reply
        const id = request.id;
        if (!(typeof id === 'string' || id === null || (typeof id === 'number' && Number.isFinite(id)))) {
            badFrame(null, -32600, 'Invalid request.');
            return;
        }
        if (request.method === 'initialize') {
            initialized = true;
            try {
                process.stderr.write(texts.notice);
            }
            catch {
                // a closed stderr changes nothing
            }
            send(id, {
                result: {
                    protocolVersion: keylessProtocolVersion(request.params),
                    capabilities: { tools: { listChanged: false } },
                    serverInfo: { name: 'marrow', version: serverVersion },
                    instructions: texts.instructions,
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
            badFrame(null, -32603, 'Internal error.');
        }
    }
    let chunks = [];
    let size = 0;
    let skipping = false; // inside a line over the limit: dropped up to the next newline, never buffered
    process.stdout.on('error', () => process.exit(initialized ? 0 : 1));
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
                    badFrame(null, -32600, 'Request too large.');
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
        if (!initialized)
            exitAsNoKey(); // empty stdin, or an end before any initialize: no MCP host ever spoke
    });
}
//# sourceMappingURL=keyless-server.js.map