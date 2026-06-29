// The typed wire messages exchanged over the WebSocket between a Nuco client and the
// relay. Every payload that carries message content is opaque base64 ciphertext; the
// relay never inspects it. JSON text frames are used so the protocol stays auditable.

import type { ProtocolVersion } from './version.js';
import type { PreKeyUpload, PreKeyBundle } from './prekeys.js';
import type { ErrorCodeValue } from './errors.js';

export type PushKind = 'apns' | 'unifiedpush' | 'none';

// Push routing data. Opaque to the relay beyond knowing how to deliver a wake.
export interface PushRegistration {
  readonly kind: PushKind;
  readonly token?: string; // APNs hex device token
  readonly endpoint?: string; // UnifiedPush endpoint URL
  readonly apnsTopic?: string; // iOS bundle id used as the apns-topic header
}

// The Signal message type carried inside an envelope.
export type CipherMessageType = 'prekey' | 'whisper';

// A sealed, padded message. ciphertext is base64 of the Signal ciphertext computed
// over the padded plaintext. id is client generated and used for dedupe and ack.
export interface MessageEnvelope {
  readonly id: string;
  readonly ciphertext: string;
  readonly messageType: CipherMessageType;
  readonly sentAt: number; // sender clock, informational only
}

// ---------------------------------------------------------------------------
// client -> server
// ---------------------------------------------------------------------------

// First frame on a new socket. The relay validates the major version.
export interface ConnectMsg {
  readonly type: 'connect';
  readonly protocolVersion: ProtocolVersion;
  readonly handle: string;
}

// Response to the connect challenge: a base64 signature over the nonce, proving
// control of the identity private key bound to the handle.
export interface AuthenticateMsg {
  readonly type: 'authenticate';
  readonly signature: string;
}

// Register a new handle or update an existing one (push token, keys). Updating an
// already registered handle requires the socket to be authenticated.
export interface RegisterMsg {
  readonly type: 'register';
  readonly rid: string;
  readonly identityKey: string; // base64 public identity key
  readonly registrationId: number;
  readonly deviceId: number;
  readonly push: PushRegistration;
}

export interface PublishPreKeysMsg {
  readonly type: 'publishPreKeys';
  readonly rid: string;
  readonly preKeys: PreKeyUpload;
}

export interface FetchPreKeyBundleMsg {
  readonly type: 'fetchPreKeyBundle';
  readonly rid: string;
  readonly handle: string;
}

export interface PreKeyCountMsg {
  readonly type: 'preKeyCount';
  readonly rid: string;
}

export interface SendMsg {
  readonly type: 'send';
  readonly rid: string;
  readonly to: string; // recipient handle
  readonly envelope: MessageEnvelope;
}

export interface AckMsg {
  readonly type: 'ack';
  readonly id: string; // envelope id the client has durably stored
}

export interface PingMsg {
  readonly type: 'ping';
  readonly ts: number;
}

export type ClientMessage =
  | ConnectMsg
  | AuthenticateMsg
  | RegisterMsg
  | PublishPreKeysMsg
  | FetchPreKeyBundleMsg
  | PreKeyCountMsg
  | SendMsg
  | AckMsg
  | PingMsg;

export type ClientMessageType = ClientMessage['type'];

// ---------------------------------------------------------------------------
// server -> client
// ---------------------------------------------------------------------------

// Sent after a valid connect. Carries a base64 nonce the client must sign.
export interface ConnectedMsg {
  readonly type: 'connected';
  readonly protocolVersion: ProtocolVersion;
  readonly challenge: string;
}

export interface AuthenticatedMsg {
  readonly type: 'authenticated';
}

// Generic success for a request, correlated by rid. Optional data per operation.
export interface OkMsg {
  readonly type: 'ok';
  readonly rid: string;
  readonly data?: Record<string, unknown>;
}

export interface PreKeyBundleMsg {
  readonly type: 'preKeyBundle';
  readonly rid: string;
  readonly bundle: PreKeyBundle;
}

export interface PreKeyCountResultMsg {
  readonly type: 'preKeyCountResult';
  readonly rid: string;
  readonly hasSignedPreKey: boolean;
  readonly oneTimeCount: number;
}

// A queued or live message pushed to a connected recipient. The client acks by id.
export interface DeliverMsg {
  readonly type: 'deliver';
  readonly from: string;
  readonly envelope: MessageEnvelope;
  readonly seq: number; // server sequence for ordering and resume
}

export interface ErrorMsg {
  readonly type: 'error';
  readonly code: ErrorCodeValue;
  readonly rid?: string;
}

export interface PongMsg {
  readonly type: 'pong';
  readonly ts: number;
}

export type ServerMessage =
  | ConnectedMsg
  | AuthenticatedMsg
  | OkMsg
  | PreKeyBundleMsg
  | PreKeyCountResultMsg
  | DeliverMsg
  | ErrorMsg
  | PongMsg;

export type ServerMessageType = ServerMessage['type'];

// ---------------------------------------------------------------------------
// Runtime type catalogs. The Record types force exhaustiveness at compile time:
// adding a message variant without listing it here is a type error, and the drift
// checker uses these arrays to confirm PROTOCOL.md documents every message.
// ---------------------------------------------------------------------------

const CLIENT_MESSAGE_TYPE_MAP: Record<ClientMessageType, true> = {
  connect: true,
  authenticate: true,
  register: true,
  publishPreKeys: true,
  fetchPreKeyBundle: true,
  preKeyCount: true,
  send: true,
  ack: true,
  ping: true,
};

const SERVER_MESSAGE_TYPE_MAP: Record<ServerMessageType, true> = {
  connected: true,
  authenticated: true,
  ok: true,
  preKeyBundle: true,
  preKeyCountResult: true,
  deliver: true,
  error: true,
  pong: true,
};

export const CLIENT_MESSAGE_TYPES = Object.keys(CLIENT_MESSAGE_TYPE_MAP) as ClientMessageType[];
export const SERVER_MESSAGE_TYPES = Object.keys(SERVER_MESSAGE_TYPE_MAP) as ServerMessageType[];
