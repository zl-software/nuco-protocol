// The typed wire messages exchanged over the WebSocket between a Nuco client and the
// relay. Every payload that carries message content is opaque base64 ciphertext; the
// relay never inspects it. JSON text frames are used so the protocol stays auditable.

import type { ProtocolVersion } from './version.js';
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

// Register a new handle or update an existing one (push token, auth key). Updating an
// already registered handle requires the socket to be authenticated. The relay learns
// nothing about the Signal identity: session establishment is card to card (see qr.ts).
export interface RegisterMsg {
  readonly type: 'register';
  readonly rid: string;
  readonly authKey: string; // base64 Ed25519 public key used to authenticate the socket
  readonly deviceId: number;
  readonly push: PushRegistration;
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

// Delete this account and all of its server side data (device record, queued messages).
// Requires an authenticated socket. Used for in app account deletion.
export interface DeregisterMsg {
  readonly type: 'deregister';
  readonly rid: string;
}

// Request short lived TURN relay credentials for a voice call. Requires an authenticated
// socket. A relay without TURN configured replies with error CALLS_UNAVAILABLE.
export interface TurnCredentialsMsg {
  readonly type: 'turnCredentials';
  readonly rid: string;
}

export type ClientMessage =
  | ConnectMsg
  | AuthenticateMsg
  | RegisterMsg
  | SendMsg
  | AckMsg
  | PingMsg
  | DeregisterMsg
  | TurnCredentialsMsg;

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

// TURN REST API credentials (the scheme coturn implements with use-auth-secret): the
// username embeds a unix expiry, the credential is an HMAC over the username that the TURN
// server verifies against a shared secret. Derived per request, never stored, never logged.
export interface TurnCredentialsResultMsg {
  readonly type: 'turnCredentialsResult';
  readonly rid: string;
  readonly urls: readonly string[]; // e.g. ['turn:turn.example.org:3478?transport=udp']
  readonly username: string; // '<unixExpirySeconds>:<ephemeralId>'
  readonly credential: string; // base64 HMAC-SHA1 over the username
  readonly expiresAt: number; // unix seconds, equals the expiry inside username
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
  | TurnCredentialsResultMsg
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
  send: true,
  ack: true,
  ping: true,
  deregister: true,
  turnCredentials: true,
};

const SERVER_MESSAGE_TYPE_MAP: Record<ServerMessageType, true> = {
  connected: true,
  authenticated: true,
  ok: true,
  turnCredentialsResult: true,
  deliver: true,
  error: true,
  pong: true,
};

export const CLIENT_MESSAGE_TYPES = Object.keys(CLIENT_MESSAGE_TYPE_MAP) as ClientMessageType[];
export const SERVER_MESSAGE_TYPES = Object.keys(SERVER_MESSAGE_TYPE_MAP) as ServerMessageType[];
