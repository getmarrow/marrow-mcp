type ToolPolicyEvent = {
    tool_name?: string;
    tool_input?: unknown;
};
export declare function normalizeHookToolName(value: unknown): string;
export declare function isOfficialMarrowMcpTool(value: unknown): boolean;
export declare function isOfficialMarrowMcpEvent(event: ToolPolicyEvent): boolean;
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
/** True for a path that holds secret or credential material. */
export declare function isSecretPath(value: string): boolean;
/** True for an environment variable name that conventionally holds a secret. */
export declare function isSecretVariableName(value: string): boolean;
/** Classifies one simple command: a read-only inspection, a secret access, or anything else. */
export declare function shellSegmentVerdict(segment: ShellSegment): ShellSegmentVerdict;
/** Files a file-reading or file-editing tool targets, including apply_patch file headers. */
export declare function toolTargetPaths(event: ToolPolicyEvent): string[];
/**
 * True when a tool reads secret or credential material, or writes a secret file
 * or Marrow's local control state. Unparseable shell falls back to a token scan.
 */
export declare function isSecretMaterialAccess(event: ToolPolicyEvent): boolean;
/**
 * The text whose words decide a tool's action type, surfaces and keyword
 * protection. Read-only shell segments, task bookkeeping and the content an
 * editing tool writes are excluded: naming a word is not performing it.
 */
export declare function toolClassificationText(event: ToolPolicyEvent): string;
/** Editing and task tools are judged by their target, not by shell-like text in their input. */
export declare function isShellGovernedTool(event: ToolPolicyEvent): boolean;
export declare function isReadOnlyToolEvent(event: ToolPolicyEvent): boolean;
export {};
//# sourceMappingURL=hook-tool-policy.d.ts.map