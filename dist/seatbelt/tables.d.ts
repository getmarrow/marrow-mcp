export declare const SEATBELT_RULES_VERSION = "marrow.seatbelt.rules.v1";
export declare const LIMITS: Readonly<{
    maxCommandBytes: number;
    maxSegments: 64;
    maxDepth: 3;
    maxScriptBytes: number;
    maxPackageJsonBytes: number;
    maxConfigBytes: number;
    maxAliasExpansions: 5;
}>;
export declare const SECRET_PATTERNS: readonly string[];
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
export declare const INTERPRETER_TREE_DELETE: RegExp;
export declare const INTERPRETER_DECODE: RegExp;
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
//# sourceMappingURL=tables.d.ts.map