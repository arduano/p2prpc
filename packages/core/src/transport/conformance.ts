import { P2PError } from '../errors.js';
import type { QuicEndpoint } from './types.js';

export interface TransportAdapterConformanceReport {
  readonly endpointId: string;
  readonly supportsSignedTickets: boolean;
  readonly supportsDiagnostics: boolean;
  readonly supportsDiscovery: boolean;
}

/**
 * Fail-closed shape check used by the advanced endpoint seam. Wire and stream
 * lifecycle conformance still requires the repository integration test kit.
 */
export function assertTransportAdapterShape(endpoint: QuicEndpoint): TransportAdapterConformanceReport {
  if (!endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint)) throw invalidAdapter();
  if (
    !safeString(endpoint.id, 2_048) ||
    !endpoint.address ||
    typeof endpoint.address !== 'object' ||
    !safeString(endpoint.address.ticket, 64 * 1024) ||
    typeof endpoint.accept !== 'function' ||
    typeof endpoint.connect !== 'function' ||
    typeof endpoint.close !== 'function'
  ) {
    throw invalidAdapter();
  }
  for (const optional of ['createTicket', 'connectLocator', 'diagnostics', 'advertise', 'browse'] as const) {
    if (endpoint[optional] !== undefined && typeof endpoint[optional] !== 'function') throw invalidAdapter();
  }
  return Object.freeze({
    endpointId: endpoint.id,
    supportsSignedTickets: endpoint.createTicket !== undefined,
    supportsDiagnostics: endpoint.diagnostics !== undefined,
    supportsDiscovery: endpoint.advertise !== undefined && endpoint.browse !== undefined
  });
}

function safeString(value: unknown, maximumBytes: number): value is string {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximumBytes;
}

function invalidAdapter(): P2PError {
  return new P2PError('INVALID_FRAME', 'Custom transport endpoint does not implement the required adapter contract');
}
