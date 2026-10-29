"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KEYLESS_NOTICE_TEXT = void 0;
exports.armKeylessNotice = armKeylessNotice;
const session_marker_1 = require("./session-marker");
/**
 * MCP-5: a hook that runs with local control on and no API key records nothing, so nothing tells the person that holds and approvals are
 * not being recorded. This puts one user-visible notice per host session through the host's `systemMessage` field: the first keyless hook
 * call of a session (a local marker keyed by a hash of the session id, mode 600, says it was sent) adds it to the hook's own JSON output,
 * or prints it alone when the hook prints nothing. Names only: no variable value is ever read into the text. Claude Code only, the one
 * host whose hook output carries `systemMessage` for every event; other hosts keep their exact output.
 */
exports.KEYLESS_NOTICE_TEXT = 'Marrow hooks in this session have no API key, so holds and approvals are NOT recorded. Put MARROW_API_KEY in ~/.marrow/env (chmod 600) or start the host with it, then restart the session.';
let armed = false;
function armKeylessNotice(harness, sessionId) {
    if (armed || harness !== 'claude-code' || typeof sessionId !== 'string' || !sessionId)
        return false;
    if (!(0, session_marker_1.claimSessionMarker)('keyless-notice', sessionId))
        return false;
    armed = true;
    const write = process.stdout.write.bind(process.stdout);
    let carried = false;
    process.stdout.write = ((chunk, ...rest) => {
        if (!carried && typeof chunk === 'string' && chunk.trim().startsWith('{')) {
            try {
                const parsed = JSON.parse(chunk);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('systemMessage' in parsed)) {
                    carried = true;
                    return write(JSON.stringify({ ...parsed, systemMessage: exports.KEYLESS_NOTICE_TEXT }), ...rest);
                }
            }
            catch { /* not JSON: written unchanged */ }
        }
        return write(chunk, ...rest);
    });
    process.on('exit', () => {
        if (!carried) {
            carried = true;
            try {
                write(JSON.stringify({ systemMessage: exports.KEYLESS_NOTICE_TEXT }));
            }
            catch { /* the notice is best effort */ }
        }
    });
    return true;
}
//# sourceMappingURL=keyless-notice.js.map