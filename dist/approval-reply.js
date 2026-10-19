"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.looksLikeApprovalReply = looksLikeApprovalReply;
// Does a short chat message look like an answer to an approval question ("yes", "go ahead")?
//
// Used only to show the user one line saying that a chat reply is not an approval (tier A3). The
// answer is a yes or no and nothing else: the text is never stored, logged, sent or returned.
const MAX_REPLY_LENGTH = 64;
// A longer message is not an answer; checked before the text is lowercased or trimmed.
const MAX_SCAN_LENGTH = 256;
const APPROVAL_REPLY = /^(?:y|yes|yep|yeah|ok|okay|sure|approve|approved|approve it|i approve|allow|allowed|allow it|confirm|confirmed|go|go ahead|do it|proceed|lgtm|ship it)[.! ]*$/;
function looksLikeApprovalReply(prompt) {
    if (typeof prompt !== 'string' || prompt.length > MAX_SCAN_LENGTH)
        return false;
    const text = prompt.trim().toLowerCase();
    return text.length > 0 && text.length <= MAX_REPLY_LENGTH && APPROVAL_REPLY.test(text);
}
//# sourceMappingURL=approval-reply.js.map