const assert = require('node:assert/strict');
const test = require('node:test');

const { redactSensitiveText, redactSensitiveValue } = require('../dist/redact.js');

test('redacts legacy Marrow keys and sensitive signed-url query parameters', () => {
  const leakedKey = 'mrw_123e4567-e89b-12d3-a456-426614174000_abcdefabcdefabcdefabcdefabcdefab';
  const input = [
    `key ${leakedKey}`,
    'https://example.com/callback?code=oauthsecret123&safe=ok',
    'https://storage.example.com/object?X-Amz-Signature=signedsecret456&X-Amz-Credential=credentialsecret789&key_id=keysecret123',
    'https://example.com/token?client_secret=clientsecret123&refresh_token=refreshsecret456&key-id=keydashsecret456',
  ].join(' ');

  const redacted = redactSensitiveText(input);
  assert.doesNotMatch(redacted, new RegExp(leakedKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(redacted, /oauthsecret123|signedsecret456|credentialsecret789|clientsecret123|refreshsecret456|keysecret123|keydashsecret456/);
  assert.match(redacted, /\[REDACTED_MARROW_KEY\]/);
  assert.match(redacted, /safe=ok/);
});

test('redacts nested runtime context and proof values', () => {
  const leakedKey = 'mrw_123e4567-e89b-12d3-a456-426614174000_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const redacted = redactSensitiveValue({
    action: `deploy ${leakedKey}`,
    nested: {
      url: 'https://example.com?authorization_code=authsecret123&X-Goog-Signature=googsecret456',
    },
    proof: {
      token: leakedKey,
    },
  });

  const text = JSON.stringify(redacted);
  assert.doesNotMatch(text, /authsecret123|googsecret456/);
  assert.doesNotMatch(text, new RegExp(leakedKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(text, /\[redacted\]|\[REDACTED_MARROW_KEY\]/);
});
