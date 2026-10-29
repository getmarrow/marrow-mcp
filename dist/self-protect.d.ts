import type { ToolPolicyEvent } from './hook-tool-policy';
/**
 * T2 (control-file gap): a write, delete, move or chmod of Marrow's own control files, of the hooks settings of any host, or of the
 * files that make a command run later (shell rc and profile files, Claude Code shell snapshots, crontab, systemd user units) is a
 * `security` action. The kinds: `marrow-control` and `persistence`. The label is read by the backend as `secrets_security`, so the
 * action is held per account policy instead of passing as an `audit on secrets` action. Any tool and any shell form: a file tool is
 * judged by its target path (resolved, symlinks followed), a shell command by every redirect target and every word a program that
 * can write is given, a command the parser cannot read by its text. Reads (cat, grep, ls, crontab -l) are not stopped here.
 */
export type SelfProtectKind = 'marrow-control' | 'persistence';
/** The kind of protected file a path or word names, or null. Control files win over persistence files. */
export declare function protectedMention(text: string): SelfProtectKind | null;
/**
 * The kind of protected file a mutating call touches, or null. `cwd` resolves relative targets. Call it only for a call that is not
 * read-only: a Read of ~/.bashrc stays a read.
 */
export declare function selfProtectKind(event: ToolPolicyEvent, cwd?: string): SelfProtectKind | null;
//# sourceMappingURL=self-protect.d.ts.map