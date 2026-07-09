// The contact card QR codec (card v4, protocol 3.0). The card is a fixed position,
// definite length CBOR array (RFC 8949 subset: unsigned integers, byte strings, text
// strings, one array, null), base45 encoded (RFC 9285) and prefixed with `NC4:` so a
// scanner can recognize it cheaply. CBOR because the Kyber public key is 1569 raw bytes
// and JSON plus base64 would overflow what a phone camera scans reliably; base45 because
// its alphabet is the QR alphanumeric set, which packs 5.5 bits per character. Strict on
// decode: any deviation, including non canonical CBOR, yields null. Encoding only, never
// crypto; the identity anchoring happens at the scan and in the verification layer.
//
// Array layout (12 elements, in order):
//   [v, handle, identityKey, registrationId,
//    spkId, spkPub, spkSig,
//    kyberId, kyberPub, kyberSig,
//    displayName, server or null]

import { base45Encode, base45Decode } from './base45.js';
import type { ContactCard } from './qr.js';
import {
  CONTACT_CARD_VERSION,
  CARD_HANDLE_MAX_LEN,
  CARD_NAME_MAX_LEN,
  CARD_SERVER_MAX_LEN,
  isContactCard,
} from './qr.js';
import {
  IDENTITY_KEY_LEN,
  SIGNED_PREKEY_PUB_LEN,
  KYBER_PREKEY_PUB_LEN,
  PREKEY_SIGNATURE_LEN,
} from './prekeys.js';

export const CARD_QR_PREFIX = 'NC4:';

// The QR alphanumeric capacity of a version 40 code at error correction level M. An
// encoded card must stay under this or the QR generator silently degrades legibility.
export const CARD_QR_MAX_LEN = 3391;

const CARD_FIELD_COUNT = 12;
const UINT_MAX = 0xffffffff; // ids and registration ids are uint32 at most

// Base64 helpers, dependency free so the protocol package stays portable (Hermes has no
// Buffer and no atob). Standard alphabet with padding, strict on decode.

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_REVERSE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) table[B64.charCodeAt(i)] = i;
  return table;
})();

function bytesToBase64(bytes: Uint8Array): string {
  const out: string[] = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] as number) : 0;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] as number) : 0;
    out.push(B64.charAt(b0 >> 2), B64.charAt(((b0 & 3) << 4) | (b1 >> 4)));
    out.push(i + 1 < bytes.length ? B64.charAt(((b1 & 15) << 2) | (b2 >> 6)) : '=');
    out.push(i + 2 < bytes.length ? B64.charAt(b2 & 63) : '=');
  }
  return out.join('');
}

function base64ToBytes(text: string): Uint8Array | null {
  if (text.length % 4 !== 0 || text.length === 0) return null;
  let pad = 0;
  if (text.endsWith('==')) pad = 2;
  else if (text.endsWith('=')) pad = 1;
  const body = text.length - pad;
  const out = new Uint8Array((text.length / 4) * 3 - pad);
  let pos = 0;
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < body; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? (B64_REVERSE[code] as number) : -1;
    if (value < 0) return null;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos++] = (buffer >> bits) & 0xff;
    }
  }
  // Reject non canonical padding bits (e.g. "AB==" where the low bits are not zero).
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
  return pos === out.length ? out : null;
}

// CBOR subset writer. Majors: 0 unsigned int, 2 byte string, 3 text string, 4 array.

// TextEncoder/TextDecoder are standard globals on both runtimes we target (Node and
// Hermes) but the ES2022 lib has no types for them (same pattern as content.ts).
interface TextEncoderLike {
  encode(input: string): Uint8Array;
}
interface TextDecoderLike {
  decode(input: Uint8Array): string;
}
declare const TextEncoder: { new (): TextEncoderLike };
declare const TextDecoder: { new (label?: string): TextDecoderLike };

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function pushHeader(out: number[], major: number, len: number): void {
  const base = major << 5;
  if (len < 24) out.push(base | len);
  else if (len < 256) out.push(base | 24, len);
  else if (len < 65536) out.push(base | 25, len >> 8, len & 0xff);
  else out.push(base | 26, (len / 16777216) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
}

function pushUint(out: number[], value: number): void {
  pushHeader(out, 0, value);
}

function pushBytes(out: number[], bytes: Uint8Array): void {
  pushHeader(out, 2, bytes.length);
  for (let i = 0; i < bytes.length; i++) out.push(bytes[i] as number);
}

function pushText(out: number[], text: string): void {
  const bytes = utf8Encoder.encode(text);
  pushHeader(out, 3, bytes.length);
  for (let i = 0; i < bytes.length; i++) out.push(bytes[i] as number);
}

const CBOR_NULL = 0xf6;

// CBOR subset reader. Enforces minimal length encodings so every card has exactly one
// valid byte representation (paired with the full re-encode comparison in decode).

class CborReader {
  private pos = 0;
  constructor(private readonly data: Uint8Array) {}

  private byte(): number {
    if (this.pos >= this.data.length) throw new Error('truncated');
    return this.data[this.pos++] as number;
  }

  private header(expectedMajor: number): number {
    const first = this.byte();
    if (first >> 5 !== expectedMajor) throw new Error('major mismatch');
    const info = first & 31;
    if (info < 24) return info;
    if (info === 24) {
      const v = this.byte();
      if (v < 24) throw new Error('non minimal');
      return v;
    }
    if (info === 25) {
      const v = this.byte() * 256 + this.byte();
      if (v < 256) throw new Error('non minimal');
      return v;
    }
    if (info === 26) {
      const v = this.byte() * 16777216 + this.byte() * 65536 + this.byte() * 256 + this.byte();
      if (v < 65536) throw new Error('non minimal');
      return v;
    }
    throw new Error('unsupported length');
  }

  arrayHeader(): number {
    return this.header(4);
  }

  uint(max: number): number {
    const v = this.header(0);
    if (v > max) throw new Error('uint out of range');
    return v;
  }

  bytes(exactLen: number): Uint8Array {
    const len = this.header(2);
    if (len !== exactLen) throw new Error('byte length mismatch');
    if (this.pos + len > this.data.length) throw new Error('truncated');
    const out = this.data.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  text(maxLen: number): string {
    const len = this.header(3);
    if (len > maxLen * 4) throw new Error('text too long'); // bytes, chars checked after decode
    if (this.pos + len > this.data.length) throw new Error('truncated');
    const out = utf8Decoder.decode(this.data.subarray(this.pos, this.pos + len));
    this.pos += len;
    return out;
  }

  nullOrText(maxLen: number): string | undefined {
    if (this.pos >= this.data.length) throw new Error('truncated');
    if (this.data[this.pos] === CBOR_NULL) {
      this.pos++;
      return undefined;
    }
    return this.text(maxLen);
  }

  done(): boolean {
    return this.pos === this.data.length;
  }
}

function encodeCardBytes(card: ContactCard): Uint8Array {
  const identityKey = base64ToBytes(card.identityKey);
  const spkPub = base64ToBytes(card.signedPreKey.publicKey);
  const spkSig = base64ToBytes(card.signedPreKey.signature);
  const kyberPub = base64ToBytes(card.kyberPreKey.publicKey);
  const kyberSig = base64ToBytes(card.kyberPreKey.signature);
  if (
    identityKey?.length !== IDENTITY_KEY_LEN ||
    spkPub?.length !== SIGNED_PREKEY_PUB_LEN ||
    spkSig?.length !== PREKEY_SIGNATURE_LEN ||
    kyberPub?.length !== KYBER_PREKEY_PUB_LEN ||
    kyberSig?.length !== PREKEY_SIGNATURE_LEN
  ) {
    throw new Error('contact card has malformed key material');
  }
  const out: number[] = [];
  pushHeader(out, 4, CARD_FIELD_COUNT);
  pushUint(out, card.v);
  pushText(out, card.handle);
  pushBytes(out, identityKey);
  pushUint(out, card.registrationId);
  pushUint(out, card.signedPreKey.keyId);
  pushBytes(out, spkPub);
  pushBytes(out, spkSig);
  pushUint(out, card.kyberPreKey.keyId);
  pushBytes(out, kyberPub);
  pushBytes(out, kyberSig);
  pushText(out, card.displayName);
  if (card.server === undefined) out.push(CBOR_NULL);
  else pushText(out, card.server);
  return Uint8Array.from(out);
}

// Encodes a card into the QR string. Throws on malformed input: the encoder only ever
// runs on the local account's own card, so a failure here is a programming error, not
// untrusted input.
export function encodeContactCardQr(card: ContactCard): string {
  if (!isContactCard(card) || card.v !== CONTACT_CARD_VERSION) {
    throw new Error('not a v4 contact card');
  }
  return CARD_QR_PREFIX + base45Encode(encodeCardBytes(card));
}

// Decodes a scanned QR string. Strict: returns null unless the payload is a canonical
// v4 card (prefix, base45, CBOR layout, exact field lengths and bounds, and a byte
// exact re-encode).
export function decodeContactCardQr(data: string): ContactCard | null {
  if (!data.startsWith(CARD_QR_PREFIX)) return null;
  const bytes = base45Decode(data.slice(CARD_QR_PREFIX.length));
  if (bytes === null) return null;
  let card: ContactCard;
  try {
    const reader = new CborReader(bytes);
    if (reader.arrayHeader() !== CARD_FIELD_COUNT) return null;
    const v = reader.uint(UINT_MAX);
    if (v !== CONTACT_CARD_VERSION) return null;
    const handle = reader.text(CARD_HANDLE_MAX_LEN);
    const identityKey = reader.bytes(IDENTITY_KEY_LEN);
    const registrationId = reader.uint(UINT_MAX);
    const spkId = reader.uint(UINT_MAX);
    const spkPub = reader.bytes(SIGNED_PREKEY_PUB_LEN);
    const spkSig = reader.bytes(PREKEY_SIGNATURE_LEN);
    const kyberId = reader.uint(UINT_MAX);
    const kyberPub = reader.bytes(KYBER_PREKEY_PUB_LEN);
    const kyberSig = reader.bytes(PREKEY_SIGNATURE_LEN);
    const displayName = reader.text(CARD_NAME_MAX_LEN);
    const server = reader.nullOrText(CARD_SERVER_MAX_LEN);
    if (!reader.done()) return null;
    card = {
      v,
      handle,
      identityKey: bytesToBase64(identityKey),
      registrationId,
      signedPreKey: { keyId: spkId, publicKey: bytesToBase64(spkPub), signature: bytesToBase64(spkSig) },
      kyberPreKey: { keyId: kyberId, publicKey: bytesToBase64(kyberPub), signature: bytesToBase64(kyberSig) },
      displayName,
      ...(server !== undefined ? { server } : {}),
    };
  } catch {
    return null;
  }
  if (!isContactCard(card)) return null;
  // Canonicality: the only accepted byte representation of this card is the one our own
  // encoder produces. This also rejects invalid utf8 (the tolerant decoder mangles it,
  // so the re-encode differs).
  const reencoded = encodeCardBytes(card);
  if (reencoded.length !== bytes.length) return null;
  for (let i = 0; i < bytes.length; i++) {
    if (reencoded[i] !== bytes[i]) return null;
  }
  return card;
}
