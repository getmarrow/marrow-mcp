"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.preferIpv4FirstWithHappyEyeballs = preferIpv4FirstWithHappyEyeballs;
const dns = __importStar(require("node:dns"));
const net = __importStar(require("node:net"));
let applied = false;
/**
 * N1: the pre-action hook dials the Marrow API with IPv4 tried first and happy eyeballs on, so an IPv6 address that does not
 * route (the resolver lists it first) cannot hold the hook past the host's budget. Transport only: the host, port, path and
 * headers of every request are unchanged. Set once, before the first request; an older Node without either setting skips it.
 */
function preferIpv4FirstWithHappyEyeballs() {
    if (applied)
        return;
    applied = true;
    try {
        if (typeof dns.setDefaultResultOrder === 'function')
            dns.setDefaultResultOrder('ipv4first');
    }
    catch { /* older Node */ }
    try {
        if (typeof net.setDefaultAutoSelectFamily === 'function')
            net.setDefaultAutoSelectFamily(true);
    }
    catch { /* older Node */ }
}
//# sourceMappingURL=ipv4-first.js.map