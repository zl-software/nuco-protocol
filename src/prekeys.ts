// The signed prekey as it travels inside the QR contact card (see qr.ts). Public data
// only: no private key ever appears in the protocol or reaches the relay. Since 2.0 the
// relay stores and serves no prekeys at all; the card is the only distribution channel,
// so possessing a peer's signed prekey proves their QR code was scanned.

export interface SignedPreKeyPublic {
  readonly keyId: number;
  readonly publicKey: string; // base64 public key
  readonly signature: string; // base64 signature over publicKey by the identity key
}
