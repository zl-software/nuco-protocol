// The payload encoded in a contact QR code. Public data only, never a private key.
// One person scans the other's card in person, which anchors the other's identity
// key by physical presence. Since v2 the card also carries the signed prekey, so the
// scanner can run X3DH entirely offline; the relay is not involved in producing,
// reading, or acting on this. Since v3 the card may also carry the owner's relay URL,
// so the scanner can warn when the two people are not on the same relay.

import type { SignedPreKeyPublic } from './prekeys.js';

export const CONTACT_CARD_VERSION = 3;

export interface ContactCard {
  readonly v: number; // ContactCard schema version (CONTACT_CARD_VERSION)
  readonly handle: string; // routing handle on the relay
  readonly identityKey: string; // base64 public identity key (the trust anchor)
  readonly registrationId: number; // Signal registration id, needed for X3DH
  readonly signedPreKey: SignedPreKeyPublic; // lets the scanner establish the session offline
  readonly fingerprint: string; // human readable fingerprint of the identity key
  readonly displayName: string; // shareable, not private
  readonly server?: string; // resolved relay ws(s) URL of the card owner (since v3); absent on v1/v2 cards
}

// A loose runtime check used when decoding a scanned QR before trusting it.
export function isContactCard(v: unknown): v is ContactCard {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    typeof c.v === 'number' &&
    typeof c.handle === 'string' &&
    typeof c.identityKey === 'string' &&
    typeof c.registrationId === 'number' &&
    Number.isInteger(c.registrationId) &&
    c.registrationId >= 0 &&
    isCardSignedPreKey(c.signedPreKey) &&
    typeof c.fingerprint === 'string' &&
    typeof c.displayName === 'string' &&
    (c.server === undefined || (typeof c.server === 'string' && c.server.length > 0))
  );
}

function isCardSignedPreKey(v: unknown): v is SignedPreKeyPublic {
  if (typeof v !== 'object' || v === null) return false;
  const k = v as Record<string, unknown>;
  return (
    typeof k.keyId === 'number' &&
    Number.isInteger(k.keyId) &&
    k.keyId >= 0 &&
    typeof k.publicKey === 'string' &&
    k.publicKey.length > 0 &&
    typeof k.signature === 'string' &&
    k.signature.length > 0
  );
}
