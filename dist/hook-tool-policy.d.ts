import { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool } from './own-tool';
export { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool };
type ToolPolicyEvent = {
    tool_name?: string;
    tool_input?: unknown;
};
export declare function normalizeHookToolName(value: unknown): string;
/** An MCP tool in any host form, including Codex's `functions.` namespace (repeated or padded). */
export declare function isMcpHookTool(value: unknown): boolean;
export declare function isProtectedShellMutation(command: string): boolean;
export declare function hookToolCommand(event: ToolPolicyEvent): string;
export type ShellSegment = {
    words: string[];
    outputs: string[];
    inputs: string[];
    expansions: string[];
};
export type ShellSegmentVerdict = 'read' | 'secret' | 'other';
/**
 * Splits a shell command into simple commands at |, ||, &&, ;, & and newlines,
 * honoring quotes. Returns null for syntax whose effect cannot be judged from
 * the words alone (command or process substitution, subshells, heredocs,
 * complex parameter expansion); callers then fall back to whole-command rules.
 */
export declare function parseShellSegments(command: string): ShellSegment[] | null;
/** Resolves ~, $HOME, ., .. and repeated slashes against the directory the command runs in. */
export declare function normalizedToolPath(value: string, base?: string): string;
/**
 * A SECRET_PATTERNS glob (src/secret-paths.ts) as a regex, the way the vendored classifier's globToRegex reads
 * it (the table holds only `**`/`*` globs, home-agnostic `**`/ prefixes and absolute paths).
 */
export declare function secretPatternRegex(pattern: string): RegExp;
/** True for a path that holds secret or credential material. */
export declare function isSecretPath(value: string, base?: string): boolean;
/** True for a secret file or Marrow's own local control state. */
export declare function isProtectedWriteTarget(value: string, base?: string): boolean;
/** True for an environment variable name that conventionally holds a secret. */
export declare function isSecretVariableName(value: string): boolean;
/** Classifies one simple command: a read-only inspection, a secret access, or anything else. */
export declare function shellSegmentVerdict(segment: ShellSegment, cwd?: string | null): ShellSegmentVerdict;
/** Files a file-reading or file-editing tool targets, including apply_patch file headers. */
export declare function toolTargetPaths(event: ToolPolicyEvent): string[];
/**
 * True when a tool reads secret or credential material, or writes a secret file
 * or Marrow's local control state. Unparseable shell falls back to a token scan.
 * A Monitor or PowerShell command, and any shell text another tool carries, is
 * read as Bash reads its command (toolPolicyReading).
 */
export declare function isSecretMaterialAccess(event: ToolPolicyEvent): boolean;
/** isSecretMaterialAccess for the call's own tool name only (every tool before PKG-H2). */
export declare function isSecretMaterialAccessAsNamed(event: ToolPolicyEvent): boolean;
/**
 * The text whose words decide a tool's action type, surfaces and keyword
 * protection. Read-only shell segments, task bookkeeping and the content an
 * editing tool writes are excluded: naming a word is not performing it.
 */
export declare function toolClassificationText(event: ToolPolicyEvent): string;
/** Editing and task tools are judged by their target, not by shell-like text in their input. */
export declare function isShellGovernedTool(event: ToolPolicyEvent): boolean;
/**
 * Whether a call only reads. A shell reading (Monitor, PowerShell, a native git
 * equivalent) is read-only exactly when Bash running its text is; any other
 * call carrying shell text is read-only only when both its own reading and
 * Bash running the text are (never more than before).
 */
export declare function isReadOnlyToolEvent(event: ToolPolicyEvent): boolean;
/** isReadOnlyToolEvent for the call's own tool name only (every tool before PKG-H2). */
export declare function isReadOnlyToolEventAsNamed(event: ToolPolicyEvent): boolean;
export type ToolPolicyReading = {
    /** How the call's own name is read: as named (every tool before PKG-H2), as Read, or as a call whose words are not actions. */
    base: 'named' | 'read' | 'non_acting';
    /** Bash calls the call amounts to: its command or script text, or a native tool's fixed git command. */
    shell: Array<{
        tool_name: string;
        tool_input: {
            command: string;
        };
    }>;
    /** Read exactly as Bash running `shell` (its own reading ignored); otherwise the stricter of both. */
    exact: boolean;
    /** An exact reading that is a shell tool (Monitor, PowerShell): classified under Bash's own label. */
    bashLabel: boolean;
};
export declare function toolPolicyReading(event: ToolPolicyEvent): ToolPolicyReading;
/** The Read call a Read-equivalent tool is read as (same input). */
export declare function readEquivalent(event: ToolPolicyEvent): ToolPolicyEvent;
/**
 * The shell text of a plain Monitor or PowerShell call (one command or script string, no field
 * that changes what runs besides it), else null. Only such a call is keyed as shell text.
 */
export declare function shellCommandToolText(event: ToolPolicyEvent): string | null;
/** A Claude Code built-in keyed by its whole input (a native git equivalent, Skill, or a call whose words are not actions). */
export declare function isWholeInputNativeTool(event: ToolPolicyEvent): boolean;
//# sourceMappingURL=hook-tool-policy.d.ts.map