/**
 * Hook labels from command positions only (SPEC client-labels, section CLIENT-LABELS). Three closed shapes whose label
 * words sit in data positions get the labels of their command words: a `git commit` with one literal or quoted here-doc
 * message (LB-COMMIT), a `wrangler deploy` run that is a proven dry run (LB-DRYRUN), and a write or edit of a source file
 * (LB-PATH). Every matcher is a single-pass token loop over at most 4000 characters; anything it cannot prove (a doubt,
 * a thrown error, a switch off) answers null, which keeps the 3.9.114 labels. Nothing here logs, stores or echoes input.
 */
export type ShapeLabels = {
    type: string;
    surfaces: string[];
};
/** The labels of a call that is WHOLLY one closed shape, else null (keep 3.9.114). A thrown error is null. */
export declare function commandPositionLabels(event: unknown, cwd: string | undefined): ShapeLabels | null;
//# sourceMappingURL=hook-label-shapes.d.ts.map