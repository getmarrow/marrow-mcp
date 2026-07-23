import { resolveMarrowEnv } from './env';
import { recordLifecycleEvent } from './lifecycle-spool';
import { marrowSessionEnd, validateBaseUrl } from './index';

export const SESSION_HOOK_COMMAND = 'npx -y @getmarrow/mcp session-hook';

function settingsPath(startDir: string): string {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  let dir = startDir;
  while (true) {
    const candidate = path.join(dir, '.claude', 'settings.json');
    if (fs.existsSync(candidate) || fs.existsSync(path.join(dir, '.git'))) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.join(startDir, '.claude', 'settings.json');
}

export function installSessionEndHook(startDir = process.cwd()): { settingsPath: string; installed: boolean } {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  const target = settingsPath(startDir);
  const settings = fs.existsSync(target) && fs.readFileSync(target, 'utf8').trim()
    ? JSON.parse(fs.readFileSync(target, 'utf8')) as Record<string, unknown>
    : {};
  const hooks = settings.hooks && typeof settings.hooks === 'object' && !Array.isArray(settings.hooks)
    ? settings.hooks as Record<string, unknown>
    : {};
  const stop = Array.isArray(hooks.Stop) ? [...hooks.Stop] : [];
  const installed = stop.some((entry) => JSON.stringify(entry).includes(SESSION_HOOK_COMMAND));
  if (!installed) stop.push({ hooks: [{ type: 'command', command: SESSION_HOOK_COMMAND }] });
  settings.hooks = { ...hooks, Stop: stop };
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(settings, null, 2) + '\n');
  return { settingsPath: target, installed: !installed };
}

export async function runSessionHookCommand(): Promise<void> {
  if (process.env.MARROW_AUTO_HOOK === 'false') return;
  const resolved = resolveMarrowEnv();
  if (!resolved.apiKey) return;
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  const sessionId = resolved.sessionId || undefined;
  const agentId = resolved.agentId || undefined;
  await recordLifecycleEvent({
    apiKey: resolved.apiKey,
    baseUrl,
    event: {
      event_type: 'session_completed',
      harness: 'claude-code',
      agent_id: agentId,
      session_id: sessionId,
      action: 'agent session ended',
      outcome_state: 'pending',
    },
  });
  try {
    await marrowSessionEnd(resolved.apiKey, baseUrl, false, sessionId, agentId);
  } catch {
    // The pending lifecycle receipt remains durable for later reconciliation.
  }
}
