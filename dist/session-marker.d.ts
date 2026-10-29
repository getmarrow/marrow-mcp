/**
 * A once-per-host-session marker: a file named by the kind and a hash of the session id (never the id itself), created owner-only inside
 * `~/.marrow/session-markers` (mode 700). True only for the call that creates it; false for every later call of that session, and false
 * when the private folder cannot be used (a notice is then skipped rather than repeated on every hook call).
 */
export declare function claimSessionMarker(kind: string, sessionId: string, home?: string): boolean;
//# sourceMappingURL=session-marker.d.ts.map