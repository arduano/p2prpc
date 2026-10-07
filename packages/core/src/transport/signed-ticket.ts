import { createPublicKey, verify } from "node:crypto";
import { isIP } from "node:net";

export interface SignedTicket {
  readonly version: 3; readonly peerId: string; readonly directAddresses: string[];
  readonly relayUrl: string | null; readonly protocol: string;
  readonly issuedAt: number; readonly expiresAt: number;
}
interface TicketValidity { readonly now?: number; readonly allowExpired?: boolean; readonly maximumBytes?: number }
export interface SignedTicketVerification extends TicketValidity {
  readonly expectedPeerId: string; readonly expectedProtocol: string;
}
function parseTicket(raw: unknown): SignedTicket {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error();
  const value = raw as Record<string, unknown>;
  const keys = ["version", "peerId", "directAddresses", "relayUrl", "protocol", "issuedAt", "expiresAt"];
  if (Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key)) ||
      value.version !== 3 || typeof value.peerId !== "string" || !/^[a-z2-7]{52}$/.test(value.peerId) ||
      !Array.isArray(value.directAddresses) || value.directAddresses.length > 32 ||
      value.directAddresses.some(address => typeof address !== "string" || address.length < 3 || address.length > 512) ||
      value.relayUrl !== null && (typeof value.relayUrl !== "string" || value.relayUrl.length > 2048) ||
      typeof value.protocol !== "string" || value.protocol.length < 1 || value.protocol.length > 512 ||
      !Number.isSafeInteger(value.issuedAt) || (value.issuedAt as number) < 0 ||
      !Number.isSafeInteger(value.expiresAt) || (value.expiresAt as number) < 0) throw new Error();
  return value as unknown as SignedTicket;
}
function publicKeyBytes(endpoint: string): Buffer {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, accumulator = 0;
  const bytes: number[] = [];
  for (const character of endpoint) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character); bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  if (bytes.length !== 32 || (accumulator & ((1 << bits) - 1)) !== 0) throw new Error("Noncanonical endpoint");
  return Buffer.from(bytes);
}
function validAddress(value: string): boolean {
  const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(value);
  if (!match) return false;
  const address = match[1] ?? match[2]!;
  const [ip, scope, ...extra] = address.split("%");
  return extra.length === 0 && (scope === undefined || !!match[1] && /^[A-Za-z0-9_.-]{1,64}$/.test(scope)) &&
    isIP(ip!) === (match[1] ? 6 : 4) && Number(match[3]) > 0 && Number(match[3]) <= 65535;
}

/** No network, secrets or endpoint construction. Unsigned envelope times confer no freshness. */
export function verifyPinnedSignedTicket(ticket: string, options: SignedTicketVerification): SignedTicket {
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      typeof options.expectedPeerId !== "string" || !/^[a-z2-7]{52}$/.test(options.expectedPeerId) ||
      typeof options.expectedProtocol !== "string" || options.expectedProtocol.length < 1 || options.expectedProtocol.length > 512 ||
      options.allowExpired !== undefined && typeof options.allowExpired !== "boolean") {
    throw new Error("Locator signature, identity, protocol or validity rejected");
  }
  return decodeSignedTicket(ticket, options);
}

/** Shared signed-envelope verifier; transport dial policy is enforced separately. */
export function decodeSignedTicket(ticket: string, options: TicketValidity = {}): SignedTicket {
  const { now = Date.now(), allowExpired = false, maximumBytes = 64 * 1024 } = options;
  try {
    if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 64 * 1024 || Buffer.byteLength(ticket) > maximumBytes) throw new Error();
    const [prefix, encoded, signatureText, extra] = ticket.split(".");
    if (prefix !== "p2prpc3" || !encoded || !signatureText || extra !== undefined) throw new Error();
    const body = Buffer.from(encoded, "base64url"), signature = Buffer.from(signatureText, "base64url");
    if (body.toString("base64url") !== encoded || signature.toString("base64url") !== signatureText || signature.length !== 64) throw new Error();
    const value = parseTicket(JSON.parse(body.toString("utf8")));
    if (("expectedPeerId" in options && value.peerId !== options.expectedPeerId) || ("expectedProtocol" in options && value.protocol !== options.expectedProtocol) ||
        value.issuedAt >= value.expiresAt || value.issuedAt > now + 60_000 ||
        (!allowExpired && value.expiresAt <= now) || value.expiresAt - value.issuedAt > 30 * 24 * 60 * 60_000 ||
        !value.directAddresses.every(validAddress)) throw new Error();
    if (value.relayUrl !== null) {
      const url = new URL(value.relayUrl);
      if (!/^https:\/\/[^/?#\\@%\s]+\/?$/iu.test(value.relayUrl) ||
          url.protocol !== "https:" || url.username || url.password || url.hash || url.search || url.port === "0" || url.pathname !== "/") throw new Error();
    }
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKeyBytes(value.peerId)]), format: "der", type: "spki" });
    if (!verify(null, Buffer.concat([Buffer.from("p2prpc-signed-ticket-v3\0"), body]), key, signature)) throw new Error();
    return value;
  } catch { throw new Error("Locator signature, identity, protocol or validity rejected"); }
}
