// Words for the keyless fallback: why a machine without a key is in the stricter `claimed_no_key`
// mode with no sign of an account, and what the person at the machine can do about it.
//
// Text only. The mode itself is decided by resolveSeatbeltMode() (src/seatbelt-mode.ts); this module
// reads the reason codes it already computed and never changes a mode or a decision. A resolution
// without a known reason gets the generic row (code `setup_unconfirmed`).

/** The reason codes of the resolver that can explain a fallback, in the order the text picks one. */
const REASON_ORDER = ['strict', 'key_rejected', 'home_unknown', 'home_unusable', 'env_home_unusable', 'home_mismatch', 'evidence_unknown'] as const;
export type FallbackReason = typeof REASON_ORDER[number];

export const FALLBACK_OTHER = 'setup_unconfirmed';

const DOCTOR = 'npx -y @getmarrow/install@latest doctor';

const REASON_TEXT: Record<FallbackReason | typeof FALLBACK_OTHER, string> = {
  strict: 'MARROW_SEATBELT_STRICT=1 is set',
  key_rejected: 'the Marrow key on this machine was rejected',
  home_unknown: 'it cannot find your login home folder (common in containers that run as a user with no home)',
  home_unusable: 'your login home folder is missing, is not a folder, or is /',
  env_home_unusable: 'HOME points to a folder that is missing, is not a folder, or is /',
  home_mismatch: 'HOME is not your login home folder',
  evidence_unknown: 'a folder or file it checks (your home folder, ~/.claude or ~/.marrow) can be written by other users, belongs to another user, or could not be read',
  [FALLBACK_OTHER]: 'it could not confirm this machine\'s setup',
};

const FIX_TEXT: Record<FallbackReason | typeof FALLBACK_OTHER, string> = {
  strict: 'unset MARROW_SEATBELT_STRICT',
  key_rejected: `run ${DOCTOR}`,
  home_unknown: 'run the agent as a user that has a home folder',
  home_unusable: 'give this user a real home folder',
  env_home_unusable: 'set HOME to your login home folder',
  home_mismatch: 'start the agent with HOME set to your login home folder',
  evidence_unknown: 'make sure it belongs to you, then run chmod go-w on it',
  [FALLBACK_OTHER]: `run ${DOCTOR}`,
};

/** The one code that explains the fallback: the first of the resolver's reasons in the fixed order, else the generic code. */
export function pickFallbackReason(reasons: unknown): FallbackReason | typeof FALLBACK_OTHER {
  if (!Array.isArray(reasons)) return FALLBACK_OTHER;
  for (const code of REASON_ORDER) if (reasons.includes(code)) return code;
  return FALLBACK_OTHER;
}

function known(code: unknown): FallbackReason | typeof FALLBACK_OTHER {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(REASON_TEXT, code) ? code as FallbackReason : FALLBACK_OTHER;
}

/** The sentence both fallback texts share. Fixed words only: no path, value or user name. */
export function fallbackSentence(code?: string | null): string {
  const picked = known(code);
  return `Marrow uses its stricter no-key mode here because ${REASON_TEXT[picked]}. Fix (for the person at this machine, not the agent): ${FIX_TEXT[picked]}, or add a Marrow key (getmarrow.ai/docs#start-here).`;
}

/** The code printed after "Code:" / "mode:" for a pick. */
export function fallbackCode(code?: string | null): string {
  return known(code);
}

/** The hold text for a protected action when the fallback is on and the seatbelt did not answer. */
export function setupUnconfirmedText(code?: string | null): string {
  return `Marrow stopped this action: there is no Marrow key on this machine, and ${fallbackSentence(code)} Agent: do not retry it another way and do not edit Marrow settings; tell the user why it was stopped. Code: ${fallbackCode(code)}.`;
}

/** Every hold text setupUnconfirmedText can return: one per row of the table, generated from it and from no input. */
export function setupUnconfirmedTexts(): string[] {
  return Object.keys(REASON_TEXT).map((code) => setupUnconfirmedText(code));
}
