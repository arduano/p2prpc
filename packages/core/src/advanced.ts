/** Explicit trust boundary for custom security, transports, and raw protocol components. */
export { createAdvancedP2PNode } from './node.js';
export type {
  AdvancedP2PNodeOptions,
  ConnectOptions,
  P2PNode,
  Peer,
  PeerContext
} from './node.js';

export { ShareRegistry, capabilityId } from './files/share.js';
export type {
  ShareRegistryOptions,
  ShareReservation,
  ShareReservationRequest
} from './files/share.js';
export type { PeerSharePolicy, SharePolicy } from './files/types.js';

export { irohLink, p2pRpcContext } from './rpc/link.js';
export type { IrohLinkOptions, P2PRpcOperationContext } from './rpc/link.js';
export { normalizeRpcHeaders } from './rpc/headers.js';
export type { RpcHeaderInput, RpcHeaderLimits, RpcHeaders } from './rpc/headers.js';

export type { SessionCredential, SessionSecurity } from './security/types.js';

export { assertTransportAdapterShape } from './transport/conformance.js';
export type { TransportAdapterConformanceReport } from './transport/conformance.js';
export { IrohEndpoint } from './transport/iroh.js';
export type {
  EndpointLocator,
  QuicBiStream,
  QuicConnection,
  QuicEndpoint,
  QuicRecvStream,
  QuicSendStream,
  StreamOpenOptions
} from './transport/types.js';
