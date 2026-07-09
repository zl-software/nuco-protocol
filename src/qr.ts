// The payload encoded in a contact QR code. Public data only, never a private key.
// One person scans the other's card in person, which anchors the other's identity
// key by physical presence. Since v2 the card also carries the signed prekey, so the
// scanner can run X3DH entirely offline; the relay is not involved in producing,
// reading, or acting on this. Since v3 the card may also carry the owner's relay URL,
// so the scanner can warn when the two people are not on the same relay. Since v4
// (protocol 3.0) the card carries the signed Kyber prekey too, the initial key
// agreement is PQXDH, and the card travels as a binary CBOR payload in base45 (see
// card-codec.ts) instead of JSON, because the Kyber public key does not fit a
// scannable JSON QR code. The derivable fingerprint field of v1 to v3 is gone.

import type { SignedPreKeyPublic, KyberPreKeyPublic } from './prekeys.js';
import {
  IDENTITY_KEY_LEN,
  SIGNED_PREKEY_PUB_LEN,
  KYBER_PREKEY_PUB_LEN,
  PREKEY_SIGNATURE_LEN,
} from './prekeys.js';

export const CONTACT_CARD_VERSION = 4;

// Bounds for the variable length card fields, enforced by the codec on both encode and
// decode. The handle bound matches the relay's LIMITS.handleMaxLen, the name bound the
// content layer's NAME_MAX_LEN.
export const CARD_HANDLE_MAX_LEN = 128;
export const CARD_NAME_MAX_LEN = 64;
export const CARD_SERVER_MAX_LEN = 256;

export interface ContactCard {
  readonly v: number; // ContactCard schema version (CONTACT_CARD_VERSION)
  readonly handle: string; // routing handle on the relay
  readonly identityKey: string; // base64 public identity key (the trust anchor)
  readonly registrationId: number; // Signal registration id, needed for PQXDH
  readonly signedPreKey: SignedPreKeyPublic; // lets the scanner establish the session offline
  readonly kyberPreKey: KyberPreKeyPublic; // the ML-KEM-1024 half of PQXDH (since v4)
  readonly displayName: string; // shareable, not private
  readonly server?: string; // resolved relay ws(s) URL of the card owner (since v3); absent on v1/v2 cards
}

// Exact base64 string lengths of the fixed size binary fields (standard padded base64:
// 4 * ceil(n / 3) characters for n bytes).
const b64Len = (n: number): number => 4 * Math.ceil(n / 3);
const IDENTITY_KEY_B64_LEN = b64Len(IDENTITY_KEY_LEN);
const SIGNED_PREKEY_PUB_B64_LEN = b64Len(SIGNED_PREKEY_PUB_LEN);
const KYBER_PREKEY_PUB_B64_LEN = b64Len(KYBER_PREKEY_PUB_LEN);
const PREKEY_SIGNATURE_B64_LEN = b64Len(PREKEY_SIGNATURE_LEN);

// A strict runtime check used when handling a decoded card before trusting it.
export function isContactCard(v: unknown): v is ContactCard {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    typeof c.v === 'number' &&
    typeof c.handle === 'string' &&
    c.handle.length > 0 &&
    c.handle.length <= CARD_HANDLE_MAX_LEN &&
    typeof c.identityKey === 'string' &&
    c.identityKey.length === IDENTITY_KEY_B64_LEN &&
    typeof c.registrationId === 'number' &&
    Number.isInteger(c.registrationId) &&
    c.registrationId >= 0 &&
    isCardSignedPreKey(c.signedPreKey) &&
    isCardKyberPreKey(c.kyberPreKey) &&
    typeof c.displayName === 'string' &&
    c.displayName.length <= CARD_NAME_MAX_LEN &&
    (c.server === undefined ||
      (typeof c.server === 'string' && c.server.length > 0 && c.server.length <= CARD_SERVER_MAX_LEN))
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
    k.publicKey.length === SIGNED_PREKEY_PUB_B64_LEN &&
    typeof k.signature === 'string' &&
    k.signature.length === PREKEY_SIGNATURE_B64_LEN
  );
}

function isCardKyberPreKey(v: unknown): v is KyberPreKeyPublic {
  if (typeof v !== 'object' || v === null) return false;
  const k = v as Record<string, unknown>;
  return (
    typeof k.keyId === 'number' &&
    Number.isInteger(k.keyId) &&
    k.keyId >= 0 &&
    typeof k.publicKey === 'string' &&
    k.publicKey.length === KYBER_PREKEY_PUB_B64_LEN &&
    typeof k.signature === 'string' &&
    k.signature.length === PREKEY_SIGNATURE_B64_LEN
  );
}
