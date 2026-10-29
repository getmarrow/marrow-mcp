import { createHash } from 'node:crypto';

/**
 * MCP-9: the Marrow session id a hook uses, one per agent. A host session that is resumed under another Marrow agent used to land on the
 * first agent's Marrow session row (the backend never changes a row's agent), so every full-path call came back MARROW_SESSION_AGENT_MISMATCH.
 * The id is the host-side base id plus a fixed-length suffix taken from the agent id, so a resumed host session gets a fresh Marrow session
 * for the agent it now runs as. Nothing of the other agent's session is read, written or rebound, and the backend's ownership check is
 * untouched. With no agent id (keyless, or none resolved) the id is the base itself, byte for byte as in 3.9.108.
 *
 * Neither a key nor any secret is part of the derivation; agent ids and session ids are not secrets. The suffix has the fixed shape
 * `.m` + 16 hex, so two ids are equal only when their bases and their tags are (a tag collision, 2^-64, still fails closed on the
 * backend's ownership check). A base over 110 characters is replaced by `h` + 32 hex of its SHA-256 first (deterministic, collision-resistant).
 *
 * Two departures from the spec text (§3.5), both found by running the hooks: the spec's `~m` is not in the id charset the client accepts
 * for a lifecycle event (`[A-Za-z0-9._:-]`, lifecycle-spool.ts safeId and hook-contract.ts), so a `~` made every lifecycle write throw; and
 * the same validators cut an id at 128 characters, which would drop the tag of a long base (the spec's 160). The id is therefore always
 * within the accepted charset and at most 128 characters. Both changes only add separation; neither can merge two sessions.
 */
const MAX_RAW_BASE = 110;

export function marrowSessionId(base: string, agentId: string | undefined | null): string {
  if (typeof base !== 'string' || !base) return base;
  const agent = typeof agentId === 'string' ? agentId : '';
  if (!agent) return base;
  const tag = createHash('sha256').update(`marrow-session-agent\n${agent}`).digest('hex').slice(0, 16);
  const head = base.length <= MAX_RAW_BASE ? base : `h${createHash('sha256').update(base).digest('hex').slice(0, 32)}`;
  return `${head}.m${tag}`;
}
