// The decrypted plaintext payload carried inside a sealed MessageEnvelope. The relay never
// sees this: it is end to end encrypted, padded, then sealed. Wrapping every message in a
// typed content envelope lets peers carry control messages (disappearing message requests)
// on the same channel as ordinary text, without the relay learning anything new.
//
// This is part of the wire contract between two peers (not between client and relay), so it
// lives here in @nuco/protocol. Adding a content variant is a backward compatible (minor)
// change: a peer that does not understand a variant decodes it as `unknown` (structured
// content it can drop silently) or as text (anything unstructured), never as a crash.

// TextEncoder/TextDecoder are standard globals on both runtimes we target (Node and Hermes),
// but the package lib is pure ES2022 (no DOM, no Node) to stay dependency free, so declare the
// minimal surface we use. The real global is used at runtime.
interface TextEncoderLike {
  encode(input: string): Uint8Array;
}
interface TextDecoderLike {
  decode(input?: Uint8Array): string;
}
declare const TextEncoder: { new (): TextEncoderLike };
declare const TextDecoder: { new (label?: string): TextDecoderLike };

const encoder = new TextEncoder();
const decoder = new TextDecoder(); // utf-8

export type MessageContent =
  | { readonly t: 'text'; readonly body: string; readonly replyTo?: string } // replyTo: envelope id of the quoted text
  | { readonly t: 'retention/request'; readonly value: number } // requested retention, seconds (0 = off)
  | { readonly t: 'retention/accept'; readonly value: number } // accept a pending request of `value`
  | { readonly t: 'retention/cancel' } // requester cancels, or recipient declines, a pending request
  | { readonly t: 'screenshot/request'; readonly on: boolean } // request per chat screenshot protection on or off
  | { readonly t: 'screenshot/accept'; readonly on: boolean } // accept a pending request of `on`
  | { readonly t: 'screenshot/cancel' } // requester cancels, or recipient declines, a pending request
  | { readonly t: 'call/offer'; readonly callId: string; readonly sdp: string } // start a voice call
  | { readonly t: 'call/accept'; readonly callId: string } // callee accepted; the answer sdp follows (see below)
  | { readonly t: 'call/answer'; readonly callId: string; readonly sdp: string } // accept a pending offer
  | { readonly t: 'call/end'; readonly callId: string; readonly reason: CallEndReason | (string & {}) }
  | { readonly t: 'verify/confirm'; readonly cardHash: string } // mutual verification proof, see below
  | { readonly t: 'message/delete'; readonly id: string } // retract a text the sender authored, see below
  | { readonly t: 'profile/name'; readonly name: string } // the sender's new display name, see below
  | {
      // Announces an image (since 3.3), see the image block below. This content's envelope
      // id doubles as the image's message id on both peers, exactly like a text's id.
      readonly t: 'image';
      readonly mime: string; // strictly image/jpeg for now
      readonly width: number; // pixel dimensions of the encoded image
      readonly height: number;
      readonly bytes: number; // total raw (pre base64) image size
      readonly sha256: string; // base64 sha256 digest of the raw image bytes
      readonly chunks: number; // count of image/chunk parts that follow
    }
  | { readonly t: 'image/chunk'; readonly ref: string; readonly seq: number; readonly data: string }; // one base64 slice of the image named by ref

export type MessageContentType = MessageContent['t'];

// Bounds enforced on decode so a malicious or buggy peer cannot make the receiver store or
// render an unbounded body, nor set a retention so large that expiry arithmetic overflows.
// A text body of up to 16384 UTF-16 units always fits within the largest padding bucket
// (65536 bytes) even at the 4 byte per unit worst case. The retention ceiling (365 days)
// covers every offered option while keeping now + value*1000 far below MAX_SAFE_INTEGER.
export const MESSAGE_BODY_MAX_LEN = 16384;
export const RETENTION_MAX_SECONDS = 365 * 24 * 60 * 60;

// Message references. A text's envelope id doubles as its cross peer identity: the sender
// uses one id as its local row key and as the envelope id, and the receiver stores the row
// under that same envelope id. So `text.replyTo` (quote a message) and `message/delete.id`
// (ask the peer to remove a text its sender authored) both name a message either side can
// resolve with a plain key lookup. Ids are client generated UUIDs today; 64 leaves headroom
// and matches CALL_ID_MAX_LEN. Deletion is cooperative client behavior, like screenshot
// protection: the receiver removes the row only if the requesting peer authored it, and a
// pre 2.3 peer drops the request as unknown content and keeps its copy.
export const MESSAGE_ID_MAX_LEN = 64;

// Images (since 3.3). An image travels as one `image` announcement followed by `chunks`
// `image/chunk` parts, all ordinary sealed envelopes, so the relay learns nothing new and
// no transport frame changes. The announcement's envelope id doubles as the image's
// message id on both peers (see the message reference block above); each chunk names it
// via `ref`. Chunk geometry is fixed: IMAGE_CHUNK_RAW_BYTES is divisible by 3, so every
// chunk except the last carries exactly IMAGE_CHUNK_DATA_B64_MAX base64 characters with
// no '=' padding. A sender may slice a base64 body directly, a receiver reassembles by
// plain concatenation, and every slice decodes on its own for incremental hashing. The
// cap keeps a maximal chunk's JSON encoding (worst case field overhead is about 110
// bytes) inside the 65536 padding bucket after the 4 byte length prefix, whose sealed
// ciphertext stays under the relay's default MAX_MESSAGE_BYTES (the drift check asserts
// the budget). The receiver persists each chunk before acking its envelope, assembles
// once all chunks arrived, verifies `sha256` over the raw image bytes, and discards the
// whole transfer on any mismatch. `chunks` must equal ceil(bytes / IMAGE_CHUNK_RAW_BYTES),
// which also bounds it to IMAGE_MAX_CHUNKS. `mime` is strictly image/jpeg for now; a
// future format is a later minor and decodes as unknown on a 3.3 peer. A pre 3.3 peer
// drops both variants as unknown content and the sender cannot detect that (there is no
// capability discovery), the standard limitation of every content addition.
export const IMAGE_CHUNK_RAW_BYTES = 48000;
export const IMAGE_CHUNK_DATA_B64_MAX = 64000; // IMAGE_CHUNK_RAW_BYTES / 3 * 4
export const IMAGE_MAX_CHUNKS = 64; // keeps seq at two digits, see the check.ts budget
export const IMAGE_MAX_BYTES = IMAGE_MAX_CHUNKS * IMAGE_CHUNK_RAW_BYTES; // 3072000
export const IMAGE_SHA256_B64_LEN = 44; // a sha256 digest in base64, like CARD_HASH_LEN
export const IMAGE_MAX_DIM = 8192;
export const IMAGE_MIME_JPEG = 'image/jpeg';

// Voice call signaling bounds and shared timing. The sdp cap is a safety ceiling well above
// an audio only, relay only offer or answer (roughly 1 to 3 KB, which pads into the 4096
// bucket). Both sides time the ring against CALL_RING_TIMEOUT_SECONDS; the caller MUST send
// `call/end` with reason `timeout` when it fires, so a queued offer is always followed by an
// authoritative end marker. A receiver rings only if localReceiveTime - envelope.sentAt <
// CALL_OFFER_STALE_SECONDS * 1000 and treats an older offer as a missed call (no ring, no
// reply). The window tolerates sender clocks up to (window - ring timeout - delivery delay)
// behind before rings start being suppressed (75s of skew at these values); a wider window
// costs little because late ghost rings are already bounded by the caller's trailing end
// marker (delivered in order right behind the offer) and the callee's own local ring timer.
export const CALL_ID_MAX_LEN = 64;
export const CALL_SDP_MAX_LEN = 8192;
export const CALL_END_REASON_MAX_LEN = 32;
export const CALL_RING_TIMEOUT_SECONDS = 45;
export const CALL_OFFER_STALE_SECONDS = 120;

// `call/accept` (since 2.5) is the callee's immediate "I pressed answer": it is sent
// before the TURN fetch, microphone acquisition, and relay-only ICE gathering that
// producing the `call/answer` sdp requires, so the caller can leave its ringing state in
// step with the callee instead of seconds later. Purely informational: the `call/answer`
// remains the authoritative transition into media setup, and a peer that does not know
// `call/accept` (pre 2.5) drops it as unknown content and keeps today's behavior.

// Mutual verification. `verify/confirm` says: this sender scanned the receiver's contact
// card AND confirmed the emoji SAS in person. cardHash proves the scan: it is
// base64(sha256(utf8(handle) || 0x00 || identityKeyBytes || 0x00 || signedPreKeyPublicBytes))
// over the RECEIVER's card (immutable fields only; displayName may change). Since the
// signed prekey distributes only via the QR card and an initiator's own signed prekey never
// appears in the X3DH handshake, only someone who held the card can compute the hash. The
// receiver recomputes it over its own card and ignores the message on mismatch. A sha256
// digest is 32 bytes, so the base64 form is always exactly 44 characters.
export const CARD_HASH_LEN = 44;

// Display name propagation (since 2.6). `profile/name` announces the sender's new display
// name after a rename, sent once per mutually verified contact. The receiver updates its
// stored contact name and may show a local note; applying it is cooperative client
// behavior, and a pre 2.6 peer drops it as unknown content. The display name never
// participates in the verification cardHash (see above), so a rename cannot break or fake
// verification. The cap bounds hostile input; clients keep their own tighter entry limits.
export const NAME_MAX_LEN = 64;

// Known call end reasons. The wire field stays an open short string so a reason added in a
// future minor still ends the call on an older peer instead of ringing through the timeout.
export const CALL_END_REASONS = ['hangup', 'decline', 'busy', 'timeout', 'error'] as const;
export type CallEndReason = (typeof CALL_END_REASONS)[number];

// Force exhaustiveness: adding a variant without listing it here is a type error.
const MESSAGE_CONTENT_TYPE_MAP: Record<MessageContentType, true> = {
  text: true,
  'retention/request': true,
  'retention/accept': true,
  'retention/cancel': true,
  'screenshot/request': true,
  'screenshot/accept': true,
  'screenshot/cancel': true,
  'call/offer': true,
  'call/accept': true,
  'call/answer': true,
  'call/end': true,
  'verify/confirm': true,
  'message/delete': true,
  'profile/name': true,
  image: true,
  'image/chunk': true,
};

export const MESSAGE_CONTENT_TYPES = Object.keys(MESSAGE_CONTENT_TYPE_MAP) as MessageContentType[];

export function encodeContent(content: MessageContent): Uint8Array {
  return encoder.encode(JSON.stringify(content));
}

// A decode sentinel for structured content this peer does not recognize (a variant from a
// newer minor, or an invalid shape). Local only: it is never encoded onto the wire and is
// deliberately not part of MessageContent or its type map.
export interface UnknownContent {
  readonly t: 'unknown';
  readonly originalType: string;
}

export type DecodedContent = MessageContent | UnknownContent;

// Decode bytes into a typed content. Tolerant by design: unstructured bytes (plain text,
// malformed JSON) degrade to a text body so a nonconforming but honest peer still renders
// as a message. Structured content with an unrecognized `t` decodes as `unknown` instead,
// so control payloads from a newer peer are dropped silently rather than rendered as raw
// JSON text. Every conforming sender wraps user text as { t: 'text' }, so hand typed JSON
// in a message body never reaches the unknown branch.
export function decodeContent(bytes: Uint8Array): DecodedContent {
  const text = decoder.decode(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { t: 'text', body: text };
  }
  if (isMessageContent(parsed)) return parsed;
  if (typeof parsed === 'object' && parsed !== null) {
    const o = parsed as Record<string, unknown>;
    if (typeof o.t === 'string') {
      // An oversized text body is truncated rather than dropped, preserving the documented
      // cap for nonconforming senders.
      if (o.t === 'text' && typeof o.body === 'string') {
        return { t: 'text', body: o.body.slice(0, MESSAGE_BODY_MAX_LEN) };
      }
      return { t: 'unknown', originalType: o.t.slice(0, 64) };
    }
  }
  return { t: 'text', body: text.slice(0, MESSAGE_BODY_MAX_LEN) };
}

function isMessageContent(v: unknown): v is MessageContent {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  switch (o.t) {
    case 'text':
      return (
        typeof o.body === 'string' &&
        o.body.length <= MESSAGE_BODY_MAX_LEN &&
        (o.replyTo === undefined || isMessageId(o.replyTo))
      );
    case 'retention/request':
    case 'retention/accept':
      return (
        typeof o.value === 'number' &&
        Number.isFinite(o.value) &&
        o.value >= 0 &&
        o.value <= RETENTION_MAX_SECONDS
      );
    case 'retention/cancel':
      return true;
    case 'screenshot/request':
    case 'screenshot/accept':
      return typeof o.on === 'boolean';
    case 'screenshot/cancel':
      return true;
    case 'call/offer':
    case 'call/answer':
      return (
        typeof o.callId === 'string' &&
        o.callId.length > 0 &&
        o.callId.length <= CALL_ID_MAX_LEN &&
        typeof o.sdp === 'string' &&
        o.sdp.length > 0 &&
        o.sdp.length <= CALL_SDP_MAX_LEN
      );
    case 'call/accept':
      return typeof o.callId === 'string' && o.callId.length > 0 && o.callId.length <= CALL_ID_MAX_LEN;
    case 'call/end':
      return (
        typeof o.callId === 'string' &&
        o.callId.length > 0 &&
        o.callId.length <= CALL_ID_MAX_LEN &&
        typeof o.reason === 'string' &&
        o.reason.length > 0 &&
        o.reason.length <= CALL_END_REASON_MAX_LEN
      );
    case 'verify/confirm':
      return typeof o.cardHash === 'string' && o.cardHash.length === CARD_HASH_LEN;
    case 'message/delete':
      return isMessageId(o.id);
    case 'profile/name':
      return typeof o.name === 'string' && o.name.length > 0 && o.name.length <= NAME_MAX_LEN;
    case 'image':
      // The chunks consistency rule also bounds chunks to 1..IMAGE_MAX_CHUNKS via bytes.
      return (
        o.mime === IMAGE_MIME_JPEG &&
        isPixelDim(o.width) &&
        isPixelDim(o.height) &&
        typeof o.bytes === 'number' &&
        Number.isInteger(o.bytes) &&
        o.bytes >= 1 &&
        o.bytes <= IMAGE_MAX_BYTES &&
        typeof o.sha256 === 'string' &&
        o.sha256.length === IMAGE_SHA256_B64_LEN &&
        o.chunks === Math.ceil(o.bytes / IMAGE_CHUNK_RAW_BYTES)
      );
    case 'image/chunk':
      return (
        isMessageId(o.ref) &&
        typeof o.seq === 'number' &&
        Number.isInteger(o.seq) &&
        o.seq >= 0 &&
        o.seq < IMAGE_MAX_CHUNKS &&
        typeof o.data === 'string' &&
        o.data.length > 0 &&
        o.data.length <= IMAGE_CHUNK_DATA_B64_MAX &&
        o.data.length % 4 === 0 &&
        CONTENT_BASE64_RE.test(o.data)
      );
    default:
      return false;
  }
}

// Standard base64 with padding, matching the transport validator's rule: length a multiple
// of 4 (checked by the caller), only the base64 alphabet, at most two trailing '='.
const CONTENT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function isPixelDim(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= IMAGE_MAX_DIM;
}

function isMessageId(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && v.length <= MESSAGE_ID_MAX_LEN;
}

// Glare: both peers place a call to each other at the same time. Both sides resolve it
// without an extra round trip by comparing the two call ids with plain code unit order:
// the smaller call id wins and its offer proceeds; the losing side silently abandons its
// own offer (no `call/end` needed, both peers derive the same result) and answers the
// winning offer.
export function callOfferWins(localCallId: string, remoteCallId: string): boolean {
  return localCallId < remoteCallId;
}
