/**
 * N1: the pre-action hook dials the Marrow API with IPv4 tried first and happy eyeballs on, so an IPv6 address that does not
 * route (the resolver lists it first) cannot hold the hook past the host's budget. Transport only: the host, port, path and
 * headers of every request are unchanged. Set once, before the first request; an older Node without either setting skips it.
 */
export declare function preferIpv4FirstWithHappyEyeballs(): void;
//# sourceMappingURL=ipv4-first.d.ts.map