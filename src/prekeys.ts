// Public prekey material. Every key here is a base64 encoded PUBLIC key. No private
// key ever appears in the protocol or reaches the relay.

export interface SignedPreKeyPublic {
  readonly keyId: number;
  readonly publicKey: string; // base64 public key
  readonly signature: string; // base64 signature over publicKey by the identity key
}

export interface OneTimePreKeyPublic {
  readonly keyId: number;
  readonly publicKey: string; // base64 public key
}

// What a device uploads to the relay so others can start a session with it.
export interface PreKeyUpload {
  readonly signedPreKey: SignedPreKeyPublic;
  readonly oneTimePreKeys: readonly OneTimePreKeyPublic[];
}

// What the relay serves for a handle. The relay pops one one time prekey per fetch;
// oneTimePreKey is absent when the pool is exhausted (the session can still form,
// with slightly weaker forward secrecy for the first message).
export interface PreKeyBundle {
  readonly handle: string;
  readonly deviceId: number;
  readonly registrationId: number;
  readonly identityKey: string; // base64 public identity key, the trust anchor
  readonly signedPreKey: SignedPreKeyPublic;
  readonly oneTimePreKey?: OneTimePreKeyPublic;
}
