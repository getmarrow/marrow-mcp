type ControlPathSample = {
  elapsed_ms: number;
  success: boolean;
  occurred_at: string;
};

export type ControlPathStats = {
  tool: string;
  current_ms: number | null;
  p50_ms: number | null;
  p99_ms: number | null;
  sample_count: number;
  success_count: number;
  failure_count: number;
  last_success_at: string | null;
};

const MAX_SAMPLES = 50;
const histories = new Map<string, ControlPathSample[]>();

function percentile(values: number[], quantile: number): number | null {
  if (values.length === 0) return null;
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(quantile * ordered.length) - 1)];
}

export function recordControlPathSample(tool: string, elapsedMs: number, success: boolean): ControlPathStats {
  const normalizedTool = String(tool || 'marrow_control').slice(0, 80);
  const current = histories.get(normalizedTool) || [];
  current.push({
    elapsed_ms: Math.max(0, Math.round(elapsedMs)),
    success,
    occurred_at: new Date().toISOString(),
  });
  if (current.length > MAX_SAMPLES) current.splice(0, current.length - MAX_SAMPLES);
  histories.set(normalizedTool, current);
  return controlPathStats(normalizedTool);
}

export function controlPathStats(tool: string): ControlPathStats {
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

export function resetControlPathState(): void {
  histories.clear();
}
