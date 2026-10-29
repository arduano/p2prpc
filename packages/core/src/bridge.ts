/** Explicit trusted-Gateway admission and relay boundary. */
export { createBridgeHost } from './bridge/host.js';
export type { BridgeHostOptions, BridgeHost } from './bridge/host.js';
export { relayBridge } from './bridge/gateway.js';
export type { NativeBridgeOffer, OpenBridgeOptions } from './bridge/native.js';
export type { BridgeContext, BridgePeerDiagnostics } from './bridge/contracts.js';
export type { BinaryWebSocket } from './bridge/transport/contracts.js';
