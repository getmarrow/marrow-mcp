"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redactSensitiveText = redactSensitiveText;
exports.redactSensitiveValue = redactSensitiveValue;
function redactSensitiveText(value) {
    return value
        .replace(/(\B--(?:password|pass|secret|api-key|apikey|token|auth|access-token|client-secret|private-key|key)=)([^\s"'`]+|"[^"]*"|'[^']*')/gi, '$1[REDACTED]')
        .replace(/(\B--(?:password|pass|secret|api-key|apikey|token|auth|access-token|client-secret|private-key|key)\s+)([^\s"'`]+|"[^"]*"|'[^']*')/gi, '$1[REDACTED]')
        .replace(/\b(Bearer|Token|ApiKey|API_KEY|MARROW_API_KEY|MARROW_KEY)\s+[\w.\-+/=]{12,}\b/gi, '$1 [REDACTED]')
        .replace(/\b([A-Z0-9_]*(?:SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*[:=]\s*['"]?[^'"\s,;]{6,}/gi, '$1=[REDACTED]')
        .replace(/\b(mrw_(?:live|test)_[A-Za-z0-9_\-]{8,})\b/g, '[REDACTED_MARROW_KEY]')
        .replace(/\bmrw_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Fa-f0-9]{16,}\b/gi, '[REDACTED_MARROW_KEY]')
        .replace(/\b(?:sk|pk|ghp|github_pat|npm|cfut)_[A-Za-z0-9_\-]{12,}\b/g, '[REDACTED_TOKEN]')
        .replace(/([?&])([^=&#\s]*(?:code|token|secret|signature|sig|credential|password|session|auth|api[_-]?key|apikey|client[_-]?secret|(?:^|[-_])key|key(?:[-_]|$))[^=&#\s]*=)[^&#\s]*/gi, '$1$2[redacted]')
        .replace(/([?&](?:token|key|secret|password|auth|signature|sig|session)=)[^&#\s]*/gi, '$1[redacted]');
}
function redactSensitiveValue(value, depth = 0) {
    if (depth > 4)
        return '[redacted-depth]';
    if (typeof value === 'string')
        return redactSensitiveText(value);
    if (typeof value === 'number' || typeof value === 'boolean' || value == null)
        return value;
    if (Array.isArray(value))
        return value.slice(0, 20).map((item) => redactSensitiveValue(item, depth + 1));
    if (typeof value === 'object') {
        const out = {};
        for (const [key, item] of Object.entries(value).slice(0, 40)) {
            out[key] = /(?:secret|token|api[_-]?key|password|credential|authorization|private[_-]?key)/i.test(key)
                ? '[redacted]'
                : redactSensitiveValue(item, depth + 1);
        }
        return out;
    }
    return String(value);
}
//# sourceMappingURL=redact.js.map