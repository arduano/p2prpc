/** Test-only helpers. Importing this subpath is an explicit insecure choice. */
export { createTestingP2PNode } from './node.js';
export type { P2PNode, Peer, TestingP2PNodeOptions } from './node.js';
export { dangerouslyAllowInsecureSessions } from './security/shared-secret.js';
