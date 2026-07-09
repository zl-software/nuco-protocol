// The signed prekeys as they travel inside the QR contact card (see qr.ts). Public data
// only: no private key ever appears in the protocol or reaches the relay. Since 2.0 the
// relay stores and serves no prekeys at all; the card is the only distribution channel,
// so possessing a peer's signed prekey proves their QR code was scanned. Since 3.0 the
// card also carries one signed Kyber prekey, because the initial key agreement is PQXDH:
// classic elliptic curve agreement plus an ML-KEM-1024 encapsulation.

export interface SignedPreKeyPublic {
  readonly keyId: number;
  readonly publicKey: string; // base64 public key
  readonly signature: string; // base64 signature over publicKey by the identity key
}

// The signed Kyber (ML-KEM-1024) prekey. Like the elliptic curve signed prekey there is
// exactly one per install, distributed only via the card, reusable for the account's
// lifetime (a last resort prekey in Signal terms; no one time prekeys exist).
export interface KyberPreKeyPublic {
  readonly keyId: number;
  readonly publicKey: string; // base64 serialized ML-KEM-1024 public key (1569 bytes)
  readonly signature: string; // base64 signature over publicKey by the identity key
}

// Exact decoded byte lengths of the binary card fields, shared by the card codec and any
// consumer that wants to sanity check key material before use. libsignal serializes
// public keys with a one byte type prefix: 32 + 1 for the curve keys, 1568 + 1 for
// ML-KEM-1024. XEd25519 signatures are 64 bytes.
export const IDENTITY_KEY_LEN = 33;
export const SIGNED_PREKEY_PUB_LEN = 33;
export const KYBER_PREKEY_PUB_LEN = 1569;
export const PREKEY_SIGNATURE_LEN = 64;
