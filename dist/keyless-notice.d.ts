/**
 * MCP-5: a hook that runs with local control on and no API key records nothing, so nothing tells the person that holds and approvals are
 * not being recorded. This puts one user-visible notice per host session through the host's `systemMessage` field: the first keyless hook
 * call of a session (a local marker keyed by a hash of the session id, mode 600, says it was sent) adds it to the hook's own JSON output,
 * or prints it alone when the hook prints nothing. Names only: no variable value is ever read into the text. Claude Code only, the one
 * host whose hook output carries `systemMessage` for every event; other hosts keep their exact output.
 */
export declare const KEYLESS_NOTICE_TEXT = "Marrow hooks in this session have no API key, so holds and approvals are NOT recorded. Put MARROW_API_KEY in ~/.marrow/env (chmod 600) or start the host with it, then restart the session.";
export declare function armKeylessNotice(harness: string, sessionId: unknown): boolean;
//# sourceMappingURL=keyless-notice.d.ts.map