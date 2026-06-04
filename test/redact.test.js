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


test('context hook renders before-action intervention before legacy runtime text', () => {
  const { buildCombinedContextBlock } = require('../dist/hook-context.js');
  const context = buildCombinedContextBlock(
    {
      warnings: [],
      loopWarnings: [],
      similarCount: 0,
      patternsCount: 0,
      templatesAvailable: 0,
      primaryInsight: null,
      collectiveInsight: null,
      hasSignal: true,
    },
    null,
    null,
    {
      intervention: {
        contract: 'marrow.before-action-intervention.v1',
        decision: 'owner_approval_required',
        allow: false,
        must_stop: true,
        must_use_before_action: true,
        headline: 'Do not repeat prior deploy failure.',
        before_action: 'Use prior deploy playbook.',
        exact_next_action: 'Run dry-run and smoke before deploy.',
        relevant_prior_signal: { source: 'fleet_lesson' },
        playbook: {
          source: 'fleet_lesson',
          lesson: { lesson_id: 'lesson_123' },
          deployment_memory: null,
          template: null,
          required_steps: ['Run dry-run', 'Run smoke'],
          required_proof: ['summary', 'checks', 'rollback_target'],
          missing_proof: ['rollback_target'],
          rollback_required: true,
          smoke_required: true,
        },
        enforcement: {
          runtime_required_before_side_effects: true,
          completion_requires_outcome_commit: true,
          commit_endpoint: '/v1/agent/commit',
          proof_pack_required: true,
          owner_approval_required: true,
        },
        learning_loop: {
          records_warning_followed_or_ignored: true,
          records_lesson_reuse: true,
          success_updates_future_rankings: true,
          failure_becomes_future_warning: true,
        },
        agent_copy: 'Stop: use the prior deploy playbook before acting.',
      },
      before_you_act: 'Legacy before-you-act text',
      exact_next_action: 'Run dry-run and smoke before deploy.',
      risk_gate: { decision: 'review_required', risk_level: 'high', allow: false },
      proof_pack: { required: true, fields: ['summary', 'checks', 'rollback_target'], missing: ['rollback_target'] },
      auto_outcome_closure: { state: 'active', recent_coverage_24h: 1 },
    }
  );

  assert.match(context, /Intervention: owner_approval_required/);
  assert.match(context, /Stop: use the prior deploy playbook before acting\./);
  assert.match(context, /marrow\.before-action-intervention\.v1/);
  assert.match(context, /Action gate: REQUIRED\. Apply this Marrow intervention/);
  assert.match(context, /Playbook source: fleet_lesson/);
  assert.match(context, /Intervention required proof: summary, checks, rollback_target/);
});
