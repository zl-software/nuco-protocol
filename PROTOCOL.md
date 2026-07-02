# Nuco wire protocol

This document and the typed sources in `src/` are the single source of truth for how
the Nuco app and the Nuco relay talk. The drift checker (`npm run check`) fails if this
document falls out of sync with the types.

Protocol version: 1.2

The version is `major.minor`. The relay rejects any connection whose MAJOR version does
not match its own. A higher MINOR is backward compatible: unknown optional fields are
ignored. Minor 1 added the message content layer (see "Message content"), which is invisible
to the relay. Minor 2 added the `deregister` client message for account deletion.

## Trust model in one paragraph

The relay is untrusted. It only ever sees ciphertext plus routing metadata (who, when,
and a padded size bucket). It never sees plaintext and never holds a private key. All
content encryption (Signal Protocol: X3DH plus Double Ratchet) happens on the device.
Clients pad every plaintext to a fixed size bucket before sealing it, so the relay learns
only a coarse size. The metadata that remains visible to the relay (handles in contact,
timing, and the size bucket) is documented here and surfaced honestly in the app.

## Transport

A single WebSocket per device carries JSON text frames. Binary values (public keys,
signatures, ciphertext) are base64 strings inside the JSON. Requests that expect a reply
carry a client generated correlation id `rid`; the matching reply echoes it.

## Identity and handles

Each install generates a long term identity key pair, a registration id, a signed prekey,
and a batch of one time prekeys. A routing handle is a public, opaque, app generated id
used only for delivery. The QR contact card encodes public data only: the handle, the
base64 identity public key, a human readable fingerprint, and a display name. It never
encodes a private key.

## Connection handshake

1. Client opens the socket and sends `connect` with its protocol version and handle.
2. Relay validates the major version. On mismatch it replies `error` with
   PROTOCOL_VERSION_MISMATCH and closes. Otherwise it replies `connected` with its own
   version and a random base64 challenge nonce.
3. If the handle is new, the client sends `register` first (see below) so the relay knows
   the transport auth key. The client then signs the nonce with its Ed25519 transport auth
   private key and sends `authenticate` with the base64 signature.
4. Relay verifies the signature against the registered transport auth public key for the
   handle and replies `authenticated`. The socket is now bound to the handle and will
   receive `deliver` frames. A bad signature yields AUTH_FAILED; authenticating an
   unregistered handle yields NOT_REGISTERED.

The transport auth key is a dedicated Ed25519 key pair, separate from the Signal identity
key. It exists only so the relay can bind a socket to its handle (which stops a third party
from draining a handle's queue) using a standard signature the relay can verify without any
Signal specific crypto. The identity key remains the end to end trust anchor that peers
verify in person; the relay never needs to verify anything about the identity key.

Operations below require an authenticated socket, except `register` for a brand new handle
which is allowed before authentication (trust on first use for the random handle
namespace; the identity key, not the handle, is the trust anchor that peers verify in
person).

## Client to server messages

- `connect`: open a session. Fields: protocolVersion, handle.
- `authenticate`: prove control of the identity key. Fields: signature (base64 over the
  challenge nonce).
- `register`: create or update a device record. Fields: rid, identityKey (base64 public),
  authKey (base64 Ed25519 public, used to authenticate the socket), registrationId,
  deviceId, push (kind plus opaque token or endpoint plus apnsTopic). Updating an existing
  handle requires an authenticated socket. Replies `ok`.
- `publishPreKeys`: upload a signed prekey and a batch of one time prekeys. Fields: rid,
  preKeys. Replies `ok` with the remaining one time count in data.
- `fetchPreKeyBundle`: fetch a bundle for a handle. Fields: rid, handle. The relay pops one
  one time prekey per fetch and replies `preKeyBundle`. Unknown handle yields NO_SUCH_HANDLE.
  A bundle may omit the one time prekey when the pool is empty (NO_ONE_TIME_PREKEY is used
  only when a strict caller requires one).
- `preKeyCount`: ask how many keys remain so the client can replenish. Fields: rid. Replies
  `preKeyCountResult`.
- `send`: enqueue a sealed message for a recipient. Fields: rid, to (recipient handle),
  envelope (id, ciphertext, messageType, sentAt). Replies `ok`. Oversized payloads yield
  MESSAGE_TOO_LARGE; a full recipient queue yields QUEUE_FULL.
- `ack`: confirm a delivered message has been durably stored. Fields: id. The relay then
  deletes that queued message.
- `ping`: heartbeat. Fields: ts. Replies `pong`.
- `deregister`: delete this account and all of its server side data (device record, prekey
  bundles, queued messages). Fields: rid. Requires an authenticated socket. Replies `ok`.

## Server to client messages

- `connected`: handshake reply. Fields: protocolVersion, challenge.
- `authenticated`: the socket is now bound to the handle for delivery.
- `ok`: generic success for a request. Fields: rid, optional data.
- `preKeyBundle`: a fetched bundle. Fields: rid, bundle.
- `preKeyCountResult`: remaining keys. Fields: rid, hasSignedPreKey, oneTimeCount.
- `deliver`: a queued or live message for this recipient. Fields: from, envelope, seq.
  Delivery is at least once; clients dedupe by envelope id and ack by id.
- `error`: a stable machine error code. Fields: code, optional rid.
- `pong`: heartbeat reply. Fields: ts.

## Message envelope and padding

An envelope carries an id (client generated, used for dedupe and ack), the base64
ciphertext, the Signal messageType (prekey or whisper), and a sender timestamp. The
plaintext is padded to one of the buckets 256, 1024, 4096, 16384, or 65536 bytes (inputs
above the largest bucket round up to a whole multiple of it) before encryption, using a 4
byte big endian length prefix so the receiver can recover the exact plaintext after
decryption.

## Message content

The plaintext inside an envelope is a typed content object, JSON encoded, so peers can carry
control messages alongside text on the same sealed channel. The relay never sees any of this.
Variants: `text` (a message body), `retention/request` (request a disappearing message timer
of `value` seconds, 0 = off), `retention/accept` (accept a pending request of `value`), and
`retention/cancel` (the requester cancels, or the recipient declines, a pending request).
Decoding is tolerant: bytes that are not a recognized content object are treated as a raw text
body, so an unknown future variant degrades to text rather than being dropped. Adding a variant
is a backward compatible (minor) change.

On decode the receiver bounds two fields so a hostile peer cannot force unbounded storage or
overflow expiry math: a `text` body is capped at 16384 units (longer bodies are truncated),
and a retention `value` above 365 days (31536000 seconds) is not recognized as a control
message.

## Delivery semantics

The relay stores sealed messages per recipient with a queue size cap and a time to live.
When the recipient has a live authenticated socket, queued and live messages are pushed as
`deliver` frames with an increasing seq. The client acks each by id; the relay deletes on
ack and dedupes by id, so delivery is at least once. When the recipient has no live socket,
the relay triggers a content free push wake (APNs or UnifiedPush) instead.

## Error codes

The relay never sends human readable text. It sends one of these stable codes, which the
app maps to a localized string:

- PROTOCOL_VERSION_MISMATCH: the client major version does not match the relay.
- MALFORMED_MESSAGE: the frame failed validation.
- UNAUTHENTICATED: an operation that needs an authenticated socket was attempted first.
- AUTH_FAILED: the challenge signature did not verify.
- NOT_REGISTERED: authentication was attempted for a handle with no identity key on file.
- NO_SUCH_HANDLE: a prekey bundle or send targeted an unknown handle.
- NO_ONE_TIME_PREKEY: a strict prekey fetch found no one time prekey left in the pool.
- RATE_LIMITED: the client exceeded a rate or abuse limit.
- QUEUE_FULL: the recipient queue is at capacity.
- MESSAGE_TOO_LARGE: the envelope exceeded the maximum allowed size.
- INTERNAL: an unexpected relay error.

## What the relay can and cannot see

Cannot see: message content, display names in message bodies, any private key, the result
of any decryption.

Can see: which handles exchange messages, timing, message counts, padded size buckets, and
the opaque push token or endpoint needed to send a wake. Operators should run the relay
with this in mind, and the app states it plainly on the About and Privacy screen.
