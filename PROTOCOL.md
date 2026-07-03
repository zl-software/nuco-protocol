# Nuco wire protocol

This document and the typed sources in `src/` are the single source of truth for how
the Nuco app and the Nuco relay talk. The drift checker (`npm run check`) fails if this
document falls out of sync with the types.

Protocol version: 1.4

The version is `major.minor`. The relay rejects any connection whose MAJOR version does
not match its own. A higher MINOR is backward compatible: unknown optional fields are
ignored, but a relay answers a frame TYPE it does not know with MALFORMED_MESSAGE (and no
rid), so a client MUST NOT send frames newer than the minor the relay advertises in its
`connected` reply; that advertised minor exists exactly for this feature negotiation.
Minor 1 added the message content layer (see "Message content"), which is invisible
to the relay. Minor 2 added the `deregister` client message for account deletion. Minor 3
added voice call signaling content (`call/offer`, `call/answer`, `call/end`), the
`turnCredentials` and `turnCredentialsResult` frames for short lived TURN credentials, the
CALLS_UNAVAILABLE error code, and the structured unknown decode rule (see "Message content").
Clients treat a relay older than minor 3 as calls unavailable. Minor 4 added two transport
conventions for edge hosted relays (see "Transport"): the client repeats its handle in the
WebSocket URL query, and the heartbeat ping carries a constant payload.

## Trust model in one paragraph

The relay is untrusted. It only ever sees ciphertext plus routing metadata (who, when,
and a padded size bucket). It never sees plaintext and never holds a private key. All
content encryption (Signal Protocol: X3DH plus Double Ratchet) happens on the device.
Clients pad every plaintext to a fixed size bucket before sealing it, so the relay learns
only a coarse size. The metadata that remains visible to the relay (handles in contact,
timing, and the size bucket) is documented here and surfaced honestly in the app. The
reference relay runs on Cloudflare Workers, so that metadata (plus client IPs and, for
calls, TURN allocation timing and volume) is visible to Cloudflare as the infrastructure
operator; the sealed content and the DTLS-SRTP call media remain unreadable to it. Self
hosting means deploying the relay on your own Cloudflare account.

## Transport

A single WebSocket per device carries JSON text frames. Binary values (public keys,
signatures, ciphertext) are base64 strings inside the JSON. Requests that expect a reply
carry a client generated correlation id `rid`; the matching reply echoes it.

Since minor 4 the client also repeats its handle in the WebSocket URL query
(`?handle=<handle>`), so an edge hosted relay can route the socket to the handle's mailbox
before the first frame arrives. The `connect` frame is unchanged and remains authoritative;
the relay rejects a socket whose frame handle does not match the URL handle. The heartbeat
`ping` SHOULD carry the constant payload `ts: 0` (identical bytes every time) so a relay
can answer it without waking a hibernated mailbox; the `pong` echoes it. Relays accept any
integer `ts` for compatibility.

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
- `turnCredentials`: request short lived TURN relay credentials for a voice call. Fields:
  rid. Requires an authenticated socket. Replies `turnCredentialsResult`; a relay without
  TURN configured replies error CALLS_UNAVAILABLE.

## Server to client messages

- `connected`: handshake reply. Fields: protocolVersion, challenge.
- `authenticated`: the socket is now bound to the handle for delivery.
- `ok`: generic success for a request. Fields: rid, optional data.
- `preKeyBundle`: a fetched bundle. Fields: rid, bundle.
- `preKeyCountResult`: remaining keys. Fields: rid, hasSignedPreKey, oneTimeCount.
- `turnCredentialsResult`: short lived TURN credentials (TURN REST scheme). Fields: rid,
  urls, username (embeds a unix expiry), credential (base64 HMAC over the username),
  expiresAt (unix seconds). Derived per request, never stored server side.
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
of `value` seconds, 0 = off), `retention/accept` (accept a pending request of `value`),
`retention/cancel` (the requester cancels, or the recipient declines, a pending request),
`call/offer` (start a voice call: callId plus a complete SDP offer), `call/answer` (accept a
pending offer: the same callId plus a complete SDP answer), and `call/end` (end, decline, or
abort the call with that callId, with a short `reason` string).

Decoding is tolerant: unstructured bytes (plain text, malformed JSON) are treated as a raw
text body, so a nonconforming but honest peer still renders as a message. A structured
object whose `t` is not recognized decodes as a local `unknown` sentinel instead, and the
receiver drops it silently; this keeps control payloads from a newer minor from rendering
as raw JSON text. (Clients on minor 2 or older predate this rule and render unknown
structured content as text; there is no peer capability discovery, so callers should expect
that limitation against old clients.) Adding a variant is a backward compatible (minor)
change.

On decode the receiver bounds every field so a hostile peer cannot force unbounded storage
or overflow expiry math: a `text` body is capped at 16384 units (longer bodies are
truncated), a retention `value` above 365 days (31536000 seconds) is not recognized, a call
id is capped at 64 units, an SDP payload at 8192 units, and a call end reason at 32 units.

### Call signaling semantics

Call setup is plain content on the sealed channel; the relay cannot distinguish it from
ordinary messages beyond the usual padded size bucket (an audio only offer or answer lands
in the 4096 bucket).

- No trickle ICE. With relay only ICE (see "Voice calls"), candidate gathering is a single
  TURN allocation round trip, so each side sends one complete SDP after gathering finishes.
  Trickled candidates over an at least once, store and forward channel would add ordering
  and staleness complexity for no practical gain. A `call/ice` variant can be added in a
  future minor if ever needed.
- Ring timeout. Both sides ring for at most CALL_RING_TIMEOUT_SECONDS (45). When the caller
  gives up, it MUST send `call/end` with reason `timeout`: that queued end marker is what
  converts an undelivered offer into a missed call for an offline recipient.
- Staleness. Offers are queued and redelivered at least once, so a receiver rings only if
  localReceiveTime - envelope.sentAt < CALL_OFFER_STALE_SECONDS (120) * 1000. The local
  receive time is the trust anchor; `sentAt` is the sender's clock and only ages the offer.
  A stale offer becomes a missed call: no ring, no reply, and the envelope is still acked.
  The window is deliberately much wider than the ring timeout: it tolerates sender clocks
  up to (window - ring timeout - delivery delay) behind, roughly 75 seconds at these
  values, before that sender's calls stop ringing on the receiver (they surface as missed
  calls instead). A wider window is cheap because late ghost rings are already bounded by
  the caller's trailing `call/end` marker (delivered in order right behind the offer) and
  by the callee's own local ring timer. A lying clock can at worst make the phone ring,
  which any caller can do anyway.
- End reasons: `hangup` (normal end, also caller cancel before answer), `decline` (callee
  rejected), `busy` (callee already in a call), `timeout` (caller gave up unanswered),
  `error` (setup or media failure). Receivers treat an unrecognized reason like a generic
  end so future reasons still stop the ring.
- Glare. When both peers send each other offers concurrently, the offer with the smaller
  callId (plain code unit comparison, see `callOfferWins`) wins on both sides; the loser
  silently abandons its own offer and answers the winner. No extra round trip, no signal
  for the abandoned offer.
- A `call/answer` for a callId the caller no longer has active is ignored (the caller's
  earlier queued `call/end` already tells the callee why).

## Voice calls

Call media is WebRTC audio between exactly two devices, encrypted with DTLS-SRTP. The
signaling (offer, answer, end) rides the sealed Signal channel as ordinary message content,
so the DTLS certificate fingerprints (`a=fingerprint` in the SDP) are exchanged end to end
encrypted and authenticated by the Signal session. A relay or TURN operator cannot man in
the middle the media without first breaking the Signal channel, so call authenticity
inherits the messaging trust anchor (the identity key, verifiable in person via the safety
number); no separate in call verification string is needed. The self signed DTLS
certificates visible to a wire observer carry no identity beyond a fresh random key.

Media is always routed through the operator's TURN server: clients force relay only ICE
candidates, so neither peer learns the other's IP address. The client fetches short lived
TURN credentials from the relay with `turnCredentials` (TURN REST scheme: the username
embeds a unix expiry, the password is an HMAC the TURN server verifies against a shared
secret; nothing is stored server side, and the credential TTL caps how long an established
call can refresh its allocation). A relay without TURN configured answers
CALLS_UNAVAILABLE and the app disables calling.

What the operators see: the TURN server sees both endpoints' IP addresses (by design,
instead of the peers seeing each other's), allocation times, duration, and byte counts; the
payload it forwards is SRTP ciphertext. The relay can infer that a call attempt happened
(a characteristic burst of sealed messages correlated in time with TURN allocations). This
is the same class of exposure as the existing messaging metadata (who talks to whom, and
when), extended by call duration.

An offline callee gets the normal content free push wake; the queued offer converts into a
missed call after the ring timeout (see "Call signaling semantics"), never a late ring.
While the app is locked, envelopes stay queued unacked, so a call placed during lock
surfaces as a missed call after unlock.

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
- CALLS_UNAVAILABLE: the relay has no TURN server configured, so voice calls cannot connect.
- INTERNAL: an unexpected relay error.

## What the relay can and cannot see

Cannot see: message content, display names in message bodies, any private key, the result
of any decryption.

Can see: which handles exchange messages, timing, message counts, padded size buckets, and
the opaque push token or endpoint needed to send a wake. Operators should run the relay
with this in mind, and the app states it plainly on the About and Privacy screen.
