/** n: no value. v: a value, `--name=value` or the next word. o: an optional value, `--name=value` only. a: any of these (long lists whose modes do not matter). */
export type LongMode = 'n' | 'v' | 'o' | 'a';
export type LongList = ReadonlyMap<string, LongMode>;
/** A word of a command line; a null text is a word the mapper cannot read. */
export interface OptWord {
    readonly text: string | null;
}
/**
 * Builds a list from text. Tokens are separated by spaces: `name` (no value), `name=` (a value), `name[=]` (an
 * optional value), `name~` (any form). A leading `[no-]` adds the `no-name` form (no value).
 */
export declare function longList(text: string): LongList;
/**
 * The indexes of the long options in `words` that are not on `list` (exact name; `=value` only where the option
 * takes one); empty when every long option is on it. A bare `--` ends the options when `honourEnd` is set. A value
 * word that belongs to a listed option (`--name value`) is skipped. `dashes` is 2 for `--name`; find writes its
 * options as `-name` (1), where `=` is never part of an option. A word with no readable text is not a long option here
 * (each parser already treats it on its own).
 */
export declare function unknownLongAll(words: readonly OptWord[], list: LongList, dashes?: 1 | 2, honourEnd?: boolean): number[];
/** The index of the first long option that is not on `list` (see unknownLongAll), or -1. */
export declare function unknownLong(words: readonly OptWord[], list: LongList, dashes?: 1 | 2, honourEnd?: boolean): number;
/** True for a word that is exactly `--name` of a listed option that takes its value as the next word. */
export declare function takesNextWord(text: string, list: LongList): boolean;
/** The text after `=` of a `--name=value` word, or null when there is none. */
export declare function longValue(text: string): string | null;
export declare const NO_LONG: LongList;
export declare const CP_LONG: LongList;
export declare const MV_LONG: LongList;
export declare const LN_LONG: LongList;
export declare const INSTALL_LONG: LongList;
export declare const TAR_LONG: LongList;
export declare const SED_LONG: LongList;
export declare const CURL_LONG: LongList;
export declare const WGET_LONG: LongList;
export declare const RSYNC_LONG: LongList;
export declare const SCP_LONG: LongList;
export declare const CAT_LONG: LongList;
export declare const HEAD_LONG: LongList;
export declare const TAIL_LONG: LongList;
export declare const WC_LONG: LongList;
export declare const STAT_LONG: LongList;
export declare const LS_LONG: LongList;
export declare const DU_LONG: LongList;
export declare const DIFF_LONG: LongList;
export declare const CMP_LONG: LongList;
export declare const FILE_LONG: LongList;
export declare const GREP_LONG: LongList;
export declare const CHECKSUM_LONG: LongList;
export declare const JQ_LONG: LongList;
export declare const YQ_LONG: LongList;
export declare const BAT_LONG: LongList;
export declare const LESS_LONG: LongList;
export declare const MORE_LONG: LongList;
export declare const RG_LONG: LongList;
export declare const TREE_LONG: LongList;
export declare const PRETTIER_LONG: LongList;
export declare const ZIP_LONG: LongList;
export declare const GIT_READ_LONG: LongList;
export declare const GIT_GLOBAL_LONG: LongList;
export declare const GIT_RESET_LONG: LongList;
export declare const GIT_RM_LONG: LongList;
export declare const GIT_RESTORE_LONG: LongList;
export declare const FIND_LONG: LongList;
//# sourceMappingURL=longopts.d.ts.map