"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordControlPathSample = recordControlPathSample;
exports.controlPathStats = controlPathStats;
exports.resetControlPathState = resetControlPathState;
const MAX_SAMPLES = 50;
const histories = new Map();
function percentile(values, quantile) {
    if (values.length === 0)
        return null;
    const ordered = [...values].sort((left, right) => left - right);
    return ordered[Math.max(0, Math.ceil(quantile * ordered.length) - 1)];
}
function recordControlPathSample(tool, elapsedMs, success) {
    const normalizedTool = String(tool || 'marrow_control').slice(0, 80);
    const current = histories.get(normalizedTool) || [];
    current.push({
        elapsed_ms: Math.max(0, Math.round(elapsedMs)),
        success,
        occurred_at: new Date().toISOString(),
    });
    if (current.length > MAX_SAMPLES)
        current.splice(0, current.length - MAX_SAMPLES);
    histories.set(normalizedTool, current);
    return controlPathStats(normalizedTool);
}
function controlPathStats(tool) {
    const normalizedTool = String(tool || 'marrow_control').slice(0, 80);
    const current = histories.get(normalizedTool) || [];
    const values = current.map((sample) => sample.elapsed_ms);
    const successes = current.filter((sample) => sample.success);
    return {
        tool: normalizedTool,
        current_ms: current.at(-1)?.elapsed_ms ?? null,
        p50_ms: percentile(values, 0.50),
        p99_ms: percentile(values, 0.99),
        sample_count: current.length,
        success_count: successes.length,
        failure_count: current.length - successes.length,
        last_success_at: successes.at(-1)?.occurred_at ?? null,
    };
}
function resetControlPathState() {
    histories.clear();
}
//# sourceMappingURL=control-path-state.js.map