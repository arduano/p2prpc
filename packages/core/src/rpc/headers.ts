import { types } from 'node:util';
import { createRpcHeaderPolicy } from './portable-headers.js';

export { DEFAULT_RPC_HEADER_LIMITS } from './portable-headers.js';
export type { RpcHeaderInput, RpcHeaderLimits, RpcHeaders } from './portable-headers.js';

/** Native metadata boundary: reject Proxies before any user trap executes. */
export const nativeRpcHeaders = createRpcHeaderPolicy(types.isProxy);
export const { normalizeRpcHeaders, mergeRpcHeaders } = nativeRpcHeaders;
