import * as dns from 'node:dns';
import * as net from 'node:net';

let applied = false;

/**
 * N1: the pre-action hook dials the Marrow API with IPv4 tried first and happy eyeballs on, so an IPv6 address that does not
 * route (the resolver lists it first) cannot hold the hook past the host's budget. Transport only: the host, port, path and
 * headers of every request are unchanged. Set once, before the first request; an older Node without either setting skips it.
 */
export function preferIpv4FirstWithHappyEyeballs(): void {
  if (applied) return;
  applied = true;
  try { if (typeof dns.setDefaultResultOrder === 'function') dns.setDefaultResultOrder('ipv4first'); } catch { /* older Node */ }
  try { if (typeof net.setDefaultAutoSelectFamily === 'function') net.setDefaultAutoSelectFamily(true); } catch { /* older Node */ }
}
