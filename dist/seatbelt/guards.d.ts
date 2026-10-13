export interface AssignEvent {
    name: string;
    uncond: boolean;
    exhaustive: boolean;
    inLoop: boolean;
    declare: boolean;
    array?: string[] | null;
}
export declare function scanAssignments(src: string): AssignEvent[] | null;
//# sourceMappingURL=guards.d.ts.map