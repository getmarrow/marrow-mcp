export declare const CONTROL_STATE_VERSION = 1;
export declare const CONTROL_STATE_DIRECTORY = ".marrow";
export declare const CONTROL_STATE_FILENAME = "control.json";
export declare const CONTROL_CHANGED_BY = "owner_cli";
export declare const CONTROL_MAX_BYTES = 4096;
export declare const CONTROL_BYPASS_ACTION = "protected action bypassed while local control disabled";
export type LocalControlState = {
    enabled: true;
    state: 'default_enabled';
    changed_at: null;
} | {
    enabled: boolean;
    state: 'enabled' | 'disabled';
    changed_at: string;
    change_id: string;
};
export declare class UnsafeControlStateError extends Error {
    constructor();
}
export declare function controlStatePath(home?: string): string;
export declare function readLocalControlState(options?: {
    home?: string;
}): LocalControlState;
export declare function localControlEvidence(bypassRecordingAvailable: boolean): Record<string, unknown>;
//# sourceMappingURL=control-state.d.ts.map