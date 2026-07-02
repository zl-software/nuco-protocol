// Hand rolled runtime validators for untrusted input. The relay parses every client
// frame through parseClientMessage before acting on it. Kept dependency free and
// explicit so the trust boundary is easy to audit.

import type {
  ClientMessage,
  MessageEnvelope,
  PushRegistration,
  PushKind,
  CipherMessageType,
} from './messages.js';
import type {
  PreKeyUpload,
  SignedPreKeyPublic,
  OneTimePreKeyPublic,
} from './prekeys.js';
import { ErrorCode } from './errors.js';

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function isStr(v: unknown): v is string {
  return typeof v === 'string';
}
function isNonEmptyStr(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}
function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}
function isUint(v: unknown): v is number {
  return isInt(v) && v >= 0;
}

// Caps that bound abuse independently of the relay config.
export const LIMITS = {
  handleMaxLen: 128,
  keyB64MaxLen: 2048,
  signatureB64MaxLen: 2048,
  ciphertextB64MaxLen: 262144, // generous ceiling above the largest padded bucket
  oneTimeBatchMax: 200,
  ridMaxLen: 128,
  idMaxLen: 128,
  apnsTopicMaxLen: 256,
  pushTokenMaxLen: 4096,
} as const;

function isHandle(v: unknown): v is string {
  return isNonEmptyStr(v) && v.length <= LIMITS.handleMaxLen;
}
// Standard base64 with padding, exactly what the client's encoder emits (length a multiple
// of 4, only the base64 alphabet, at most two trailing '='). Rejecting malformed base64 at
// the trust boundary stops garbage key material from being stored and later handed to peers.
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
function isBase64(v: string): boolean {
  return v.length % 4 === 0 && BASE64_RE.test(v);
}
function isKeyB64(v: unknown): v is string {
  return isNonEmptyStr(v) && v.length <= LIMITS.keyB64MaxLen && isBase64(v);
}

function isSignedPreKey(v: unknown): v is SignedPreKeyPublic {
  return (
    isRecord(v) &&
    isUint(v.keyId) &&
    isKeyB64(v.publicKey) &&
    isNonEmptyStr(v.signature) &&
    (v.signature as string).length <= LIMITS.signatureB64MaxLen
  );
}
function isOneTimePreKey(v: unknown): v is OneTimePreKeyPublic {
  return isRecord(v) && isUint(v.keyId) && isKeyB64(v.publicKey);
}
function isPreKeyUpload(v: unknown): v is PreKeyUpload {
  if (!isRecord(v)) return false;
  if (!isSignedPreKey(v.signedPreKey)) return false;
  if (!Array.isArray(v.oneTimePreKeys)) return false;
  if (v.oneTimePreKeys.length > LIMITS.oneTimeBatchMax) return false;
  return v.oneTimePreKeys.every(isOneTimePreKey);
}

const PUSH_KINDS: readonly PushKind[] = ['apns', 'unifiedpush', 'none'];
function isPushRegistration(v: unknown): v is PushRegistration {
  if (!isRecord(v)) return false;
  if (!isStr(v.kind) || !PUSH_KINDS.includes(v.kind as PushKind)) return false;
  if (v.token !== undefined && !(isStr(v.token) && v.token.length <= LIMITS.pushTokenMaxLen)) return false;
  if (v.endpoint !== undefined && !(isStr(v.endpoint) && v.endpoint.length <= LIMITS.pushTokenMaxLen)) return false;
  if (v.apnsTopic !== undefined && !(isStr(v.apnsTopic) && v.apnsTopic.length <= LIMITS.apnsTopicMaxLen)) return false;
  return true;
}

const CIPHER_TYPES: readonly CipherMessageType[] = ['prekey', 'whisper'];
function isEnvelope(v: unknown): v is MessageEnvelope {
  return (
    isRecord(v) &&
    isNonEmptyStr(v.id) &&
    (v.id as string).length <= LIMITS.idMaxLen &&
    isNonEmptyStr(v.ciphertext) &&
    (v.ciphertext as string).length <= LIMITS.ciphertextB64MaxLen &&
    isStr(v.messageType) &&
    CIPHER_TYPES.includes(v.messageType as CipherMessageType) &&
    isInt(v.sentAt)
  );
}

function isRid(v: unknown): v is string {
  return isNonEmptyStr(v) && v.length <= LIMITS.ridMaxLen;
}

export type ParseResult =
  | { ok: true; message: ClientMessage }
  | { ok: false; code: ErrorCode };

const MALFORMED = { ok: false, code: ErrorCode.MalformedMessage } as const;

export function parseClientMessage(raw: string): ParseResult {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return MALFORMED;
  }
  if (!isRecord(v) || !isStr(v.type)) return MALFORMED;

  switch (v.type) {
    case 'connect': {
      if (!isRecord(v.protocolVersion)) return MALFORMED;
      const pv = v.protocolVersion;
      if (!isInt(pv.major) || !isInt(pv.minor)) return MALFORMED;
      if (!isHandle(v.handle)) return MALFORMED;
      return { ok: true, message: { type: 'connect', protocolVersion: { major: pv.major, minor: pv.minor }, handle: v.handle } };
    }
    case 'authenticate': {
      if (!isNonEmptyStr(v.signature) || v.signature.length > LIMITS.signatureB64MaxLen) return MALFORMED;
      return { ok: true, message: { type: 'authenticate', signature: v.signature } };
    }
    case 'register': {
      if (!isRid(v.rid)) return MALFORMED;
      if (!isKeyB64(v.identityKey)) return MALFORMED;
      if (!isKeyB64(v.authKey)) return MALFORMED;
      if (!isUint(v.registrationId)) return MALFORMED;
      if (!isUint(v.deviceId)) return MALFORMED;
      if (!isPushRegistration(v.push)) return MALFORMED;
      return {
        ok: true,
        message: {
          type: 'register',
          rid: v.rid,
          identityKey: v.identityKey,
          authKey: v.authKey,
          registrationId: v.registrationId,
          deviceId: v.deviceId,
          push: v.push,
        },
      };
    }
    case 'publishPreKeys': {
      if (!isRid(v.rid)) return MALFORMED;
      if (!isPreKeyUpload(v.preKeys)) return MALFORMED;
      return { ok: true, message: { type: 'publishPreKeys', rid: v.rid, preKeys: v.preKeys } };
    }
    case 'fetchPreKeyBundle': {
      if (!isRid(v.rid)) return MALFORMED;
      if (!isHandle(v.handle)) return MALFORMED;
      return { ok: true, message: { type: 'fetchPreKeyBundle', rid: v.rid, handle: v.handle } };
    }
    case 'preKeyCount': {
      if (!isRid(v.rid)) return MALFORMED;
      return { ok: true, message: { type: 'preKeyCount', rid: v.rid } };
    }
    case 'send': {
      if (!isRid(v.rid)) return MALFORMED;
      if (!isHandle(v.to)) return MALFORMED;
      if (!isEnvelope(v.envelope)) return MALFORMED;
      return { ok: true, message: { type: 'send', rid: v.rid, to: v.to, envelope: v.envelope } };
    }
    case 'ack': {
      if (!isNonEmptyStr(v.id) || v.id.length > LIMITS.idMaxLen) return MALFORMED;
      return { ok: true, message: { type: 'ack', id: v.id } };
    }
    case 'ping': {
      if (!isInt(v.ts)) return MALFORMED;
      return { ok: true, message: { type: 'ping', ts: v.ts } };
    }
    default:
      return MALFORMED;
  }
}
