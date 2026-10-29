export declare const CONTROL_STATUS_COMMAND = "npx @getmarrow/install control status";
/** Appended to the pre-action deny text: the fix first, so a host's length limit trims the path before it trims the fix. */
export declare function unreadableControlSuffix(home?: string): string;
/** One plain notice for the person: control stays ON, what to run, which file. */
export declare function unreadableControlNotice(home?: string): string;
/**
 * True when this session has not been told yet (and is now marked as told), false when it has.
 * The marker is an empty owner-only file named by a hash of the session key, under ~/.marrow/control-notice.
 * When a marker cannot be stored safely (no ~/.marrow, a link or another owner's directory) the answer is
 * true: a repeated notice is better than a silent one, and nothing is ever written through a link.
 */
export declare function claimUnreadableControlNotice(sessionKey: string, home?: string): boolean;
//# sourceMappingURL=control-notice.d.ts.map