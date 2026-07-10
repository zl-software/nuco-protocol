# Nuco wire protocol

This document and the typed sources in `src/` are the single source of truth for how
the Nuco app and the Nuco relay talk. The drift checker (`npm run check`) fails if this
document falls out of sync with the types.

Protocol version: 3.1

The version is `major.minor`. The relay rejects any connection whose MAJOR version does
not match its own. A higher MINOR is backward compatible: unknown optional fields are
ignored, but a relay answers a frame TYPE it does not know with MALFORMED_MESSAGE (and no
rid), so a client MUST NOT send frames newer than the minor the relay advertises in its
`connected` reply; that advertised minor exists exactly for this feature negotiation.

Major 3 makes the initial key agreement post quantum. Sessions establish with PQXDH
(libsignal: X25519 agreement plus an ML-KEM-1024 encapsulation) instead of X3DH, so a
recording of today's traffic cannot be decrypted later by a quantum computer. Each
install now also generates ONE signed Kyber prekey next to the elliptic curve signed
prekey, and the QR contact card (v4) carries it; because the Kyber public key is 1569
raw bytes, the card moved from JSON to a binary CBOR payload in base45 with the `NC4:`
prefix (see "Identity and handles"), and the derivable `fingerprint` field was dropped.
The verification `cardHash` now also commits to the Kyber prekey. No transport frames
changed; the relay still never sees any Signal key material. Minor 1 added the optional
`wake` hint on `send` and the optional `voipToken` on the push registration (see
"Delivery semantics"): the sender classifies how an offline recipient is woken, because
the sealed envelope gives the relay nothing to classify. `alert` (the default and the
pre 3.1 behavior) is the visible content free banner, `voip` is an incoming call wake
(iOS PushKit; the app reports it as an incoming call, falls back to `alert` when no
voipToken is registered), and `none` is invisible control traffic (verification
confirms, call teardown, profile syncs) that queues silently for the next connect. The
hint leaks one coarse traffic class bit to the relay; a relay already infers calls from
TURN credential mints, and misuse degrades only the sender's own notifications.

Major 2 is a breaking cut. The relay stores and serves no prekeys: the `publishPreKeys`,
`fetchPreKeyBundle`, and `preKeyCount` client frames and the `preKeyBundle` and
`preKeyCountResult` server frames are gone, along with the NO_ONE_TIME_PREKEY error code.
The signed prekey now travels only inside the QR contact card (v2, see "Identity and
handles"), so sessions are established fully offline at the scan. `register` no longer
carries the Signal identity key or registration id; the relay learns nothing about the
end to end identity. The content layer gained `verify/confirm` and the mutual verification
rules (see "Mutual verification semantics"): a conversation is usable only after both
peers scanned each other and confirmed the emoji SAS. Minor 1 of major 2 added the per
chat screenshot protection trio (`screenshot/request`, `screenshot/accept`,
`screenshot/cancel`) to the content layer. Minor 2 added the optional `server` field to
the QR contact card (card v3): the card owner's resolved relay URL, so the scanner can
warn at scan time when the two people are not on the same relay. The field never
participates in the `cardHash` and the relay never sees the card. Minor 3 added the
optional `replyTo` field on `text` (quote an earlier message by its envelope id) and the
`message/delete` content (ask the peer to remove a text its sender authored). Minor 4
added the optional `attestation` field on `register` plus the ATTESTATION_REQUIRED and
ATTESTATION_FAILED error codes (registration gating, see "App attestation"). Minor 5
added the `call/accept` content (the callee's immediate accepted marker, sent before the
answer sdp is ready). Minor 6 added the `profile/name` content (a renamed sender announces
its new display name to each mutually verified contact). The 1.x line for history: minor 1
added the content layer, minor 2 `deregister`, minor 3 call signaling plus TURN
credentials plus the structured unknown decode rule, minor 4 the URL handle and constant
ping transport conventions (both kept in 2.0).

## Trust model in one paragraph

The relay is untrusted. It only ever sees ciphertext plus routing metadata (who, when,
and a padded size bucket). It never sees plaintext and never holds a private key. All
content encryption (Signal Protocol: PQXDH plus Double Ratchet) happens on the device.
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

Each install generates a long term identity key pair, a registration id, one signed
elliptic curve prekey, and one signed Kyber (ML-KEM-1024) prekey. A routing handle is a
public, opaque, app generated id used only for delivery. The QR contact card (v4) encodes
public data only: the handle, the identity public key, the registration id, the signed
prekey and the signed Kyber prekey (each: key id, public key, and its signature by the
identity key), a display name, and optionally the owner's resolved relay ws(s) URL
(`server`, since card v3). It never encodes a private key.

On the wire the v4 card is a fixed position CBOR array (definite lengths, canonical
minimal integer encodings), base45 encoded (RFC 9285) and prefixed with `NC4:`, so the
whole card rides a single QR code in alphanumeric mode. The array layout, the exact
field lengths (identity and curve prekeys 33 bytes, Kyber prekey 1569 bytes, signatures
64 bytes), and the strict decode rules live in `src/card-codec.ts`; a decoder rejects
anything that does not re-encode byte identically. v1 to v3 cards were JSON; a v4
scanner rejects them as incompatible (the peer must update), which is acceptable because
major 3 is a breaking cut.

Handles are namespaced per relay, so two people on different relays cannot message each
other. The `server` field exists so the scanning app can detect that at scan time and
warn instead of failing later. It is optional and best effort: v1/v2 cards lack it, a
scanner treats a malformed value as absent, and the field never participates in the
`cardHash` (display name aside, only immutable identity fields do).

The card is the ONLY channel that distributes the signed prekeys; the relay never stores
or serves key material beyond the transport auth key. Scanning a card therefore lets the
scanner run PQXDH entirely offline, and possessing a peer's signed prekeys proves their
card was scanned (an initiator's own prekeys never appear in the PQXDH handshake). To
avoid establishing two racing sessions when both people scan each other, exactly one side
initiates: the peer whose raw identity key compares byte wise smaller runs PQXDH from the
scanned card; the other side never initiates and becomes the responder when the
initiator's first sealed message (a `prekey` envelope) arrives.

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

## App attestation (registration gating)

A relay MAY gate the creation of NEW handles on proof that the registering client is a
genuine build of an official app. This is relay policy, not a protocol requirement: the
protocol only defines the carrier field and the error codes. Enforcement is off by
default; the reference relay enforces it. Register updates for an existing handle are
already authenticated by the transport auth key and are never gated.

The flow is reactive. A client first sends a plain `register`. A relay that enforces
gating replies `error` ATTESTATION_REQUIRED (with the request's rid). The client then
produces an attestation bound to this socket's `connected` challenge and retries
`register` once with the optional `attestation` field attached:

- kind: the attestation scheme. `apple-app-attest` is the only kind defined today; a
  relay answers a kind it does not accept with ATTESTATION_REQUIRED.
- keyId: base64 App Attest key id (the SHA-256 of the attested public key).
- data: base64 CBOR attestation object from Apple's DCAppAttestService.

Challenge binding, spelled out because two hashing conventions meet here: for
`apple-app-attest` the client passes the challenge STRING exactly as it appeared in the
`connected` frame (the base64 text itself) to DCAppAttestService, so the attestation's
client data hash is the SHA-256 over the UTF-8 bytes of that base64 string. This differs
from `authenticate`, whose Ed25519 signature is computed over the base64 DECODED nonce
bytes. The challenge is per socket, random, and single purpose; a failed or missing
attestation never consumes it, so the subsequent `authenticate` on the same socket still
works.

The relay verifies the attestation following Apple's published steps (certificate chain
to the pinned Apple App Attestation Root CA, nonce binding to the challenge, key id, app
id, sign counter, environment) and then DISCARDS it. Nothing new is stored on the device
record: no key id, no receipt. A failed verification yields ATTESTATION_FAILED. What the
relay learns is only that the registering client is a genuine build of the app id it
requires; what Apple learns is only that the app requested an attestation, never the
handle or relay involved.

## Client to server messages

- `connect`: open a session. Fields: protocolVersion, handle.
- `authenticate`: prove control of the identity key. Fields: signature (base64 over the
  challenge nonce).
- `register`: create or update a device record. Fields: rid, authKey (base64 Ed25519
  public, used to authenticate the socket), deviceId, push (kind plus opaque token or
  endpoint plus apnsTopic plus, since 3.1, an optional voipToken for iOS call wakes),
  and optionally attestation (kind, keyId, data; see "App attestation"). Updating an
  existing handle requires an authenticated socket. Replies `ok`.
- `send`: enqueue a sealed message for a recipient. Fields: rid, to (recipient handle),
  envelope (id, ciphertext, messageType, sentAt), and since 3.1 an optional wake hint
  (`alert` | `voip` | `none`, default `alert`; see "Delivery semantics"). Replies `ok`.
  Oversized payloads yield MESSAGE_TOO_LARGE; a full recipient queue yields QUEUE_FULL.
- `ack`: confirm a delivered message has been durably stored. Fields: id. The relay then
  deletes that queued message.
- `ping`: heartbeat. Fields: ts. Replies `pong`.
- `deregister`: delete this account and all of its server side data (device record, queued
  messages). Fields: rid. Requires an authenticated socket. Replies `ok`.
- `turnCredentials`: request short lived TURN relay credentials for a voice call. Fields:
  rid. Requires an authenticated socket. Replies `turnCredentialsResult`; a relay without
  TURN configured replies error CALLS_UNAVAILABLE.

## Server to client messages

- `connected`: handshake reply. Fields: protocolVersion, challenge.
- `authenticated`: the socket is now bound to the handle for delivery.
- `ok`: generic success for a request. Fields: rid, optional data.
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
Variants: `text` (a message body, with an optional `replyTo` reference quoting an earlier
message by its envelope id), `retention/request` (request a disappearing message timer
of `value` seconds, 0 = off), `retention/accept` (accept a pending request of `value`),
`retention/cancel` (the requester cancels, or the recipient declines, a pending request),
`screenshot/request` (request per chat screenshot protection `on` or off), `screenshot/accept`
(accept a pending request of `on`), `screenshot/cancel` (the requester cancels, or the
recipient declines, a pending request), `call/offer` (start a voice call: callId plus a
complete SDP offer), `call/accept` (the callee pressed answer; the answer sdp is being
produced), `call/answer` (accept a pending offer: the same callId plus a complete
SDP answer), `call/end` (end, decline, or abort the call with that callId, with a short
`reason` string), `verify/confirm` (the mutual verification proof, see "Mutual
verification semantics"), `message/delete` (ask the peer to remove the text with that
envelope id from its device), and `profile/name` (the sender's new display name after a
rename; the receiver updates its stored contact name).

A text's envelope id doubles as its cross peer identity: the sender uses the same id as
its local record key and as the envelope id, and the receiver stores the message under
that envelope id. `replyTo` and `message/delete.id` both name a message this way. Deletion
is cooperative client behavior, like screenshot protection: the receiver removes the
message only if the requesting peer authored it (and resolves a reference it cannot find
to nothing), and an older peer drops the request as unknown content and keeps its copy.

A rename is announced, not negotiated: after changing their display name, a client sends
`profile/name` once to each mutually verified contact (resending on reconnect until the
relay accepts it; receivers treat a repeated unchanged name as a no-op). Applying it is
cooperative client behavior, like deletion. The display name never participates in the
verification `cardHash`, so a rename cannot break or fake verification; a pre 2.6 peer
drops the content as unknown and keeps the name from the last scan.

Screenshot protection follows the retention negotiation shape: a change is a request the
other side accepts before it applies on either device. Once agreed, each client instructs
its OS to block screenshots and screen recording while that conversation is on screen.
Enforcement is cooperative client behavior, not a cryptographic guarantee: a modified
client, an older client that drops the trio as unknown content, or a second camera pointed
at the screen is not stopped by it.

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
id is capped at 64 units, an SDP payload at 8192 units, a call end reason at 32 units, a
message id (`message/delete.id` or a `replyTo` reference) at 64 units, a `profile/name`
name at 64 units (and it must be non empty), and a `cardHash` must be exactly 44
characters (base64 of a 32 byte sha256 digest).

### Mutual verification semantics

A conversation is usable only after MUTUAL verification: each person scanned the other's
QR card in person and each pressed "the emojis match" on the SAS screen. Both facts are
peer to peer contract; the relay sees none of it.

- `verify/confirm` carries `cardHash`, computed over the RECEIVER's card:
  base64(sha256(utf8(handle) || 0x00 || identityKeyBytes || 0x00 ||
  signedPreKeyPublicBytes || 0x00 || kyberPreKeyPublicBytes)). Only immutable card
  fields participate (displayName may change). Since 3.0 the hash also commits to the
  Kyber prekey; the pre 3.0 hash omitted the last term. Because the signed prekeys
  distribute only via the QR card, a correct hash proves the sender held the receiver's
  card. The receiver recomputes the hash over its own card and silently ignores the
  message on mismatch.
- Sending rules, all idempotent: a client sends its confirm when its user confirms the SAS
  (deferred until a session exists for a responder), replies with its own confirm when an
  incoming confirm first flips the peer to confirmed, and resends on reconnect while its
  own confirm is unanswered. Receivers ignore duplicate confirms.
- Receive gate: until both sides' confirms are exchanged, a receiver processes only
  `verify/confirm` from that peer. Every other content type is decrypted (to keep the
  ratchet healthy), acked, and silently discarded: never stored, never displayed, never
  rung. A conforming client never sends gated content before mutual verification.
- Unknown senders: an envelope from a handle the receiver has no contact for is handled by
  messageType. A `prekey` envelope is left unacked (it can only be the confirm of someone
  whose scan the receiver has not yet reciprocated; it stays queued at the relay until the
  receiver scans back and reconnects, or the queue TTL expires it). A `whisper` envelope
  can never become decryptable and is acked and dropped.

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
- Accepted marker. Producing the `call/answer` takes real time on the callee (a TURN
  credential fetch, microphone acquisition, and the full relay only ICE gathering), so
  since minor 5 the callee sends `call/accept` (callId only) the moment answer is pressed,
  before that work starts. The caller leaves its ringing state on `call/accept` instead of
  seconds later on the answer. Purely informational and best effort: `call/answer` remains
  the authoritative transition (a caller that never got the accept behaves exactly as
  before), and a pre 2.5 peer drops `call/accept` as unknown content.
- Glare. When both peers send each other offers concurrently, the offer with the smaller
  callId (plain code unit comparison, see `callOfferWins`) wins on both sides; the loser
  silently abandons its own offer and answers the winner. No extra round trip, no signal
  for the abandoned offer.
- A `call/accept` or `call/answer` for a callId the caller no longer has active is ignored
  (the caller's earlier queued `call/end` already tells the callee why).

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
the sender's wake hint decides what happens (since 3.1): `alert` (the default) triggers a
content free push (APNs or UnifiedPush), `voip` triggers an iOS PushKit VoIP push against
the registered voipToken with a short expiry matched to the ring window (falling back to
`alert` when no voipToken is registered; on UnifiedPush it degrades to the ordinary wake),
and `none` queues the envelope silently until the next connect. No push ever carries
message content or sender identity: on APNs the alert wake is a visible generic
notification whose text is a fixed localization key resolved on the device, the voip wake
is an empty payload the app must present as a generic incoming call, and on UnifiedPush it
is an opaque wake body.

## Error codes

The relay never sends human readable text. It sends one of these stable codes, which the
app maps to a localized string:

- PROTOCOL_VERSION_MISMATCH: the client major version does not match the relay.
- MALFORMED_MESSAGE: the frame failed validation.
- UNAUTHENTICATED: an operation that needs an authenticated socket was attempted first.
- AUTH_FAILED: the challenge signature did not verify.
- NOT_REGISTERED: authentication was attempted for a handle with no device record on file.
- NO_SUCH_HANDLE: a send targeted an unknown handle.
- RATE_LIMITED: the client exceeded a rate or abuse limit.
- ATTESTATION_REQUIRED: this relay only creates new handles for attested registrations;
  retry `register` with the attestation field (see "App attestation").
- ATTESTATION_FAILED: the supplied attestation did not verify.
- QUEUE_FULL: the recipient queue is at capacity.
- MESSAGE_TOO_LARGE: the envelope exceeded the maximum allowed size.
- CALLS_UNAVAILABLE: the relay has no TURN server configured, so voice calls cannot connect.
- INTERNAL: an unexpected relay error.

## What the relay can and cannot see

Cannot see: message content, display names in message bodies, any private key, any Signal
identity key or prekey (since 2.0 the relay holds no end to end key material at all, only
the transport auth public key), the result of any decryption.

Can see: which handles exchange messages, timing, message counts, padded size buckets, and
the opaque push token or endpoint needed to send a wake. Operators should run the relay
with this in mind, and the app states it plainly on the About and Privacy screen.
