export declare const SEATBELT_RULES_VERSION = "marrow.seatbelt.rules.v1";
export declare const LIMITS: Readonly<{
    maxCommandBytes: number;
    maxSegments: 256;
    maxDepth: 6;
    maxScriptBytes: number;
    maxPackageJsonBytes: number;
    maxConfigBytes: number;
    maxAliasExpansions: 5;
    maxWork: 4000;
    maxScriptExpansions: 150;
    maxVariants: 16;
    timeBudgetMs: 300;
    maxGlobMatches: 256;
    maxToolNodes: 200000;
    maxToolDepth: 12;
    maxTailTrials: 64;
    maxPathChars: 4096;
    maxToolJsonChars: number;
    maxWords: 1024;
    maxBraceChars: 1024;
    maxParseCost: 24000000;
    maxPsDepth: 4;
    maxEncodedChars: 32767;
}>;
export { PRESENT_SECRET_PATTERNS, SECRET_PATTERNS } from '../secret-paths';
export declare const KEY_EXTENSIONS: RegExp;
export declare const KEY_FIXTURE_SEGMENTS: Set<string>;
export declare const ENV_TEMPLATE_SUFFIX: RegExp;
export declare const SSH_PUBLIC: RegExp;
export declare function secretSamples(home: string, cwds: string[]): string[];
export declare const SECRET_VAR: RegExp;
export declare const PROD_ENV: RegExp;
export declare const S4_EXEMPT_PROGRAMS: Set<string>;
export declare const GIT_S4_EXEMPT_SUBS: Set<string>;
export declare const SHELLS: Set<string>;
export declare const INTERPRETERS: Set<string>;
export declare function interpreterTreeDelete(code: string): boolean;
export declare function interpreterDecodeToken(code: string): boolean;
export declare const INTERPRETER_EXEC: RegExp;
export declare const MARROW_OWNER_SUBS: Set<string>;
export declare const PACKAGE_BINS: Record<string, string>;
export declare const GIT_BUILTINS: Set<string>;
export declare const GIT_PUSH_LONG: string[];
export declare const GIT_PUSH_RISKY_LONG: Record<string, string>;
export declare const TRIPWIRE: ReadonlyArray<{
    re: RegExp;
    category: 'S0' | 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'Sx';
    reason: string;
}>;
export declare const NAME_TRIPWIRE: RegExp;
export declare const KNOWN_COMMANDS: Set<string>;
export declare const INERT_PROGRAMS: Set<string>;
export declare const SCRIPT_SUFFIX: RegExp;
export declare const NON_SCRIPT_NAMES: Set<string>;
export declare const EVAL_PRODUCERS: Set<string>;
export declare const NPM_COMMANDS: string[];
export declare const NPM_ALIASES: Record<string, string>;
export declare const NPM_VALUE_FLAGS: Set<string>;
export declare const NPM_BOOL_FLAGS: Set<string>;
export declare const GIT_EXEC_CONFIG: RegExp;
export declare const GIT_CONFIG_INCLUDE: RegExp;
export declare const GIT_CONFIG_ENV_FILES: string[];
export declare const SHELL_TOOL_NAMES: Set<string>;
export declare const FILE_TOOL_NAMES: Set<string>;
export declare const COMMAND_KEYS: Set<string>;
export declare function commandLikeKey(raw: string): boolean;
export declare const ARGV_KEYS: Set<string>;
export declare const ARGV_SEGMENTS: Set<string>;
export declare const ARGV_STRICT: Set<string>;
export declare const CODE_KEYS: Set<string>;
export declare function codeLikeKey(raw: string): boolean;
export declare const STDIN_KEYS: Set<string>;
export declare const TERMINAL_SEGMENTS: Set<string>;
export declare const BUILD_TOOLS: Set<string>;
export declare const HEAD_RUNNERS: Set<string>;
export declare const HEAD_CHANGERS: Set<string>;
export declare const GH_HEAD_SAFE: Set<string>;
export declare const TERMINAL_TEXT_KEYS: Set<string>;
export declare const ENV_KEYS: Set<string>;
export declare const CWD_KEYS: Set<string>;
export declare const OPTION_OBJECT_KEYS: Set<string>;
export declare const LANGUAGE_KEYS: Set<string>;
export declare const A3_REASONS: ReadonlySet<string>;
export declare const WIN_DELETE_VERBS: ReadonlySet<string>;
export declare const WIN_SHELL_DELETE_VERBS: ReadonlySet<string>;
/** A program word as Windows names it: both separators split the path, a .exe/.cmd/.bat/.com suffix goes, case folds. */
export declare function windowsProgramName(text: string): string;
/**
 * A3 rules (i) to (iv) for one command whose program is a delete verb. `words` are its arguments (null = not a literal:
 * a variable, a substitution, several values). True = stop: pipeline input, a recursion marker, an option outside the
 * known non-recursive set, or an argument that is not a plain literal (a `$` expression, a splat, a backtick, `%VAR%`,
 * `!VAR!`, a script block).
 */
export declare function windowsDeleteStops(words: ReadonlyArray<string | null>, piped: boolean): boolean;
/**
 * `windowsDeleteStops(words.slice(p + 1), piped && p === 0)` for every p, from one pass over `words`. A suffix stops when
 * it holds a word that stops on its own or no target at all, so the last word of each kind answers every p. The result is
 * a function of p; each call is constant time.
 */
export declare function windowsDeleteStopsFrom(words: ReadonlyArray<string>, pipedFirst: boolean): (p: number) => boolean;
export declare const WIN_DELETE_WORDS: RegExp;
export declare const WIN_CMDLET_WORD: RegExp;
export declare const PS_EVAL_WORDS: RegExp;
export declare const PS_DYNAMIC_CALL: RegExp;
export declare const PS_DYNAMIC_AMP: RegExp;
export declare const PS_BLOCK_CALL: RegExp;
export declare const PS_SNIFF: RegExp;
/**
 * .NET and COM deletes of a whole tree (rule v). The text is lower-cased with all white space removed, so padding and
 * spacing change nothing. `strict` (PowerShell / cmd text) also stops `.Delete(<anything but $false/0/false>)`; outside
 * it only the PowerShell-only forms count, so a C# search for `.Delete(true)` keeps its answer.
 */
export declare function dotNetTreeDelete(text: string, strict: boolean): boolean;
export type PsOptionKind = 'command' | 'encoded' | 'file' | 'value' | 'flag';
export declare function psOption(raw: string): {
    kind: PsOptionKind;
    name: string;
    attached: string | null;
} | null;
export declare const PS_EXECUTION_POLICIES: RegExp;
/** The text of a base64 UTF-16LE -EncodedCommand value, or null when it cannot be read (the caller then stops). */
export declare function decodeEncodedCommand(value: string): string | null;
/** PowerShell reads U+2013, U+2014 and U+2015 as the parameter dash and the smart quotes as quotes: the same text with plain ones. */
export declare function psNormalize(text: string): string;
/** PowerShell / cmd text with its escapes taken out: a backtick (PowerShell) or caret (cmd) before a line break joins the lines, any other one goes; dashes and quotes plain. */
export declare function psClean(text: string): string;
/**
 * The same PowerShell / cmd text with its block braces turned into line breaks and its call operators dropped, so
 * `& { ri -r x }`, `Invoke-Command -ScriptBlock { rd /s x }` and `% { rm $_ }` show their bodies as commands. Quotes and
 * `${name}` are left alone. A reading for the delete checks only; it never replaces the text's own reading.
 */
export declare function psFlatten(text: string): string;
export declare function psDynamicCode(text: string): boolean;
export declare function psDefaultParameters(text: string): boolean;
export interface PsStatement {
    words: string[];
    piped: boolean;
}
export declare const PS_KEYWORDS: ReadonlySet<string>;
export declare function psStatements(text: string, cmd: boolean): {
    statements: PsStatement[];
    ok: boolean;
};
export declare const PS_OUTPUT_CMDLETS: ReadonlySet<string>;
export declare const PS_BLOCK_WORDS: ReadonlySet<string>;
//# sourceMappingURL=tables.d.ts.map