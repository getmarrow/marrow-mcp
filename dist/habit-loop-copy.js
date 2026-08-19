"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatHabitLoopCopy = formatHabitLoopCopy;
exports.extractModelUsageFromUnknown = extractModelUsageFromUnknown;
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function asString(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : null;
}
function formatHabitLoopCopy(source) {
    const root = asRecord(source);
    if (!root)
        return null;
    const nestedData = asRecord(root.data);
    const habit = asRecord(root.habit_loop)
        || asRecord(nestedData?.habit_loop)
        || (asString(root.contract) === 'marrow.habit-loop.v1' ? root : null);
    if (!habit || asString(habit.contract) !== 'marrow.habit-loop.v1')
        return null;
    const headline = asString(habit.headline) || 'Marrow is on.';
    const next = asString(habit.exact_next_action) || 'Stay quiet unless the work is deploy, merge, publish, migration, secrets, or billing.';
    const avoid = Array.isArray(habit.avoid)
        ? habit.avoid.map((item) => asString(item)).filter((item) => Boolean(item)).slice(0, 5)
        : [];
    const savingsRecord = asRecord(habit.session_savings);
    const savings = asString(savingsRecord?.message)
        || (savingsRecord?.evidence_backed === true
            ? 'Reuse produced evidence-backed savings.'
            : 'No reuse yet. Empty savings are honest.');
    return {
        contract: 'marrow.habit-loop.v1',
        headline,
        next,
        avoid,
        savings,
        text: [headline, `Next: ${next}`, ...(avoid.length ? [`Avoid: ${avoid[0]}`] : []), `Savings: ${savings}`].join('\n'),
    };
}
function extractModelUsageFromUnknown(source) {
    const root = asRecord(source);
    if (!root)
        return null;
    const usage = asRecord(root.usage)
        || asRecord(root.token_usage)
        || asRecord(asRecord(root.response)?.usage)
        || asRecord(asRecord(root.message)?.usage)
        || asRecord(root.usageMetadata);
    if (!usage)
        return null;
    const numberAt = (...keys) => {
        for (const key of keys) {
            const value = usage[key];
            if (typeof value === 'number' && Number.isFinite(value) && value >= 0)
                return Math.floor(value);
        }
        return undefined;
    };
    const inputTokens = numberAt('input_tokens', 'prompt_tokens', 'inputTokenCount', 'promptTokenCount');
    const outputTokens = numberAt('output_tokens', 'completion_tokens', 'outputTokenCount', 'candidatesTokenCount');
    const cachedTokens = numberAt('cached_tokens', 'cache_read_input_tokens', 'cachedContentTokenCount');
    const totalTokens = numberAt('total_tokens', 'totalTokenCount', 'totalTokens');
    if (inputTokens == null && outputTokens == null && cachedTokens == null && totalTokens == null)
        return null;
    const model = asString(root.model) || asString(root.modelVersion) || asString(asRecord(root.response)?.model);
    const provider = asString(root.provider) || undefined;
    return {
        provider,
        model: model || undefined,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        cached_tokens: cachedTokens,
        total_tokens: totalTokens,
    };
}
//# sourceMappingURL=habit-loop-copy.js.map