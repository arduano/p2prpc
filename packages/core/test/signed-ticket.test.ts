import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyPinnedSignedTicket } from '../src/transport/signed-ticket.js';
const now = 1_800_000_000_000, protocol = 'fixture-contract';
function base32(bytes: Buffer) {
  let bits = 0, value = 0, text = ''; const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; text += alphabet[(value >>> bits) & 31]; } }
  if (bits) text += alphabet[(value << (5 - bits)) & 31]; return text;
}
function fixture() {
  const key = generateKeyPairSync('ed25519');
  const peerId = base32(key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const ticket = (fields: Record<string, unknown> = {}) => {
    const body = Buffer.from(JSON.stringify({version:3,peerId,protocol,directAddresses:['127.0.0.1:49121','[::1]:49121'],relayUrl:null,issuedAt:now-1000,expiresAt:now+1000,...fields}));
    return `p2prpc3.${body.toString('base64url')}.${sign(null,Buffer.concat([Buffer.from('p2prpc-signed-ticket-v3\0'),body]),key.privateKey).toString('base64url')}`;
  };
  return {ticket, options:{expectedPeerId:peerId,expectedProtocol:protocol,now}};
}
describe('offline pinned signed-ticket contract', () => {
  it('verifies native Ed25519 identity without constructing or dialing an endpoint', () => {
    const f=fixture();expect(verifyPinnedSignedTicket(f.ticket(),f.options)).toMatchObject({peerId:f.options.expectedPeerId,protocol});
    expect(()=>verifyPinnedSignedTicket(f.ticket(),{...f.options,expectedProtocol:'other'})).toThrow();
    expect(()=>verifyPinnedSignedTicket(f.ticket(),{...f.options,expectedPeerId:fixture().options.expectedPeerId})).toThrow();
  });
  it.each([{issuedAt:now+61000,expiresAt:now+62000},{expiresAt:now},{issuedAt:-1},{issuedAt:now+2000},{directAddresses:['hostname:3']},{directAddresses:['[::1]:0']},{relayUrl:'https://relay.example.test/?token=fixture'},{unexpected:true}])('rejects signed malformed or out-of-policy structure %j', fields => {
    const f=fixture();expect(()=>verifyPinnedSignedTicket(f.ticket(fields),f.options)).toThrow();
  });
  it('expired signatures require explicit historical verification and confer no freshness', () => {
    const f=fixture(),value=f.ticket({issuedAt:now-3000,expiresAt:now-1000});
    expect(()=>verifyPinnedSignedTicket(value,f.options)).toThrow();
    expect(verifyPinnedSignedTicket(value,{...f.options,allowExpired:true}).expiresAt).toBeLessThan(now);
  });
  it('bounds input and rejects tampered or noncanonical encodings', () => {
    const f=fixture(),value=f.ticket();expect(()=>verifyPinnedSignedTicket(value,{...f.options,maximumBytes:10})).toThrow();
    expect(()=>verifyPinnedSignedTicket(value+'=',f.options)).toThrow();
    const parts=value.split('.');parts[1]=Buffer.from('{}').toString('base64url');expect(()=>verifyPinnedSignedTicket(parts.join('.'),f.options)).toThrow();
  });
});
