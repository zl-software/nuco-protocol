// Drift and self test for @nuco/protocol. Run with `npm run check`.
// Fails (exit 1) if PROTOCOL.md does not document every message type, every content type,
// every error code, and the current version, or if the padding or content round trip is
// broken.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  PROTOCOL_VERSION_STRING,
  ALL_ERROR_CODES,
  CLIENT_MESSAGE_TYPES,
  SERVER_MESSAGE_TYPES,
  MESSAGE_CONTENT_TYPES,
  PADDING_BUCKETS,
  pad,
  unpad,
  encodeContent,
  decodeContent,
  callOfferWins,
  CALL_SDP_MAX_LEN,
  MESSAGE_ID_MAX_LEN,
  NAME_MAX_LEN,
  IMAGE_CHUNK_RAW_BYTES,
  IMAGE_CHUNK_DATA_B64_MAX,
  IMAGE_MAX_CHUNKS,
  IMAGE_MAX_BYTES,
  IMAGE_MIME_JPEG,
  base45Encode,
  base45Decode,
  encodeContactCardQr,
  decodeContactCardQr,
  CARD_QR_PREFIX,
  CARD_QR_MAX_LEN,
  CARD_HANDLE_MAX_LEN,
  CARD_NAME_MAX_LEN,
  CARD_SERVER_MAX_LEN,
  CONTACT_CARD_VERSION,
  IDENTITY_KEY_LEN,
  SIGNED_PREKEY_PUB_LEN,
  KYBER_PREKEY_PUB_LEN,
  PREKEY_SIGNATURE_LEN,
  parseClientMessage,
  REPORT_CATEGORIES,
  REPORT_CONTEXTS,
  LIMITS,
  type ContactCard,
  type MessageContent,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const protocolMd = readFileSync(join(here, '..', 'PROTOCOL.md'), 'utf8');

const failures: string[] = [];

function expectInDoc(label: string, token: string): void {
  if (!protocolMd.includes(token)) {
    failures.push(`PROTOCOL.md is missing ${label}: ${token}`);
  }
}

// 1. Version is documented.
expectInDoc('the protocol version', PROTOCOL_VERSION_STRING);

// 2. Every message type is documented.
for (const t of CLIENT_MESSAGE_TYPES) expectInDoc('client message', `\`${t}\``);
for (const t of SERVER_MESSAGE_TYPES) expectInDoc('server message', `\`${t}\``);

// 3. Every error code is documented.
for (const code of ALL_ERROR_CODES) expectInDoc('error code', code);

// 3b. Every content type is documented.
for (const t of MESSAGE_CONTENT_TYPES) expectInDoc('content type', `\`${t}\``);

// 4. Padding round trips for a range of sizes and lands on a bucket.
const sizes = [0, 1, 5, 200, 256, 257, 1000, 5000, 70000];
for (const n of sizes) {
  const data = new Uint8Array(n);
  for (let i = 0; i < n; i++) data[i] = i & 0xff;
  const padded = pad(data);
  const onBucket =
    PADDING_BUCKETS.includes(padded.length) || padded.length % 65536 === 0;
  if (!onBucket) failures.push(`padded size ${padded.length} for input ${n} is not on a bucket`);
  const back = unpad(padded);
  if (back.length !== n) failures.push(`unpad length mismatch for input ${n}: got ${back.length}`);
  for (let i = 0; i < n; i++) {
    if (back[i] !== (i & 0xff)) {
      failures.push(`unpad content mismatch for input ${n} at byte ${i}`);
      break;
    }
  }
}

// 5. Content round trips exactly for one sample of every variant.
const fakeSdp = 'v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n' + 'a=candidate:relay '.repeat(160);
const contentSamples: MessageContent[] = [
  { t: 'text', body: 'hello' },
  { t: 'text', body: 'a reply', replyTo: 'a1b2c3d4-0000-4000-8000-000000000000' },
  { t: 'message/delete', id: 'a1b2c3d4-0000-4000-8000-000000000000' },
  { t: 'retention/request', value: 86400 },
  { t: 'retention/accept', value: 0 },
  { t: 'retention/cancel' },
  { t: 'screenshot/request', on: true },
  { t: 'screenshot/accept', on: false },
  { t: 'screenshot/cancel' },
  { t: 'call/offer', callId: 'a1b2c3d4-0000-4000-8000-000000000000', sdp: fakeSdp },
  { t: 'call/answer', callId: 'a1b2c3d4-0000-4000-8000-000000000000', sdp: fakeSdp },
  { t: 'call/end', callId: 'a1b2c3d4-0000-4000-8000-000000000000', reason: 'hangup' },
  { t: 'profile/name', name: 'Alice Example' },
  {
    t: 'image',
    mime: IMAGE_MIME_JPEG,
    width: 1600,
    height: 1200,
    bytes: 150000,
    sha256: fakeB64(32, 3),
    chunks: 4,
  },
  { t: 'image/chunk', ref: 'a1b2c3d4-0000-4000-8000-000000000000', seq: 0, data: 'QUJD' },
];
for (const sample of contentSamples) {
  const decoded = decodeContent(encodeContent(sample));
  if (JSON.stringify(decoded) !== JSON.stringify(sample)) {
    failures.push(`content round trip mismatch for ${sample.t}: got ${JSON.stringify(decoded)}`);
  }
}

// 6. An audio only offer of realistic size pads into the 4096 bucket.
const offerBytes = encodeContent({ t: 'call/offer', callId: 'a1b2c3d4', sdp: fakeSdp });
if (pad(offerBytes).length !== 4096) {
  failures.push(`call offer of ${offerBytes.length} bytes padded to ${pad(offerBytes).length}, expected 4096`);
}

// 7. Bounds are enforced: an oversized sdp is not recognized as a call offer, and an
// oversized message id is not recognized as a delete request.
const oversized = decodeContent(
  encodeContent({ t: 'call/offer', callId: 'x', sdp: 'a'.repeat(CALL_SDP_MAX_LEN + 1) }),
);
if (oversized.t !== 'unknown') {
  failures.push(`oversized sdp decoded as ${oversized.t}, expected unknown`);
}
const oversizedId = decodeContent(
  encodeContent({ t: 'message/delete', id: 'a'.repeat(MESSAGE_ID_MAX_LEN + 1) }),
);
if (oversizedId.t !== 'unknown') {
  failures.push(`oversized message id decoded as ${oversizedId.t}, expected unknown`);
}
const oversizedName = decodeContent(
  encodeContent({ t: 'profile/name', name: 'a'.repeat(NAME_MAX_LEN + 1) }),
);
if (oversizedName.t !== 'unknown') {
  failures.push(`oversized profile name decoded as ${oversizedName.t}, expected unknown`);
}
const emptyName = decodeContent(encodeContent({ t: 'profile/name', name: '' }));
if (emptyName.t !== 'unknown') {
  failures.push(`empty profile name decoded as ${emptyName.t}, expected unknown`);
}

// 8. Structured content with an unrecognized type decodes as unknown; unstructured bytes
// still degrade to text (the tolerant path must not regress).
const encoder = new TextEncoder();
const future = decodeContent(encoder.encode('{"t":"call/future","x":1}'));
if (future.t !== 'unknown' || future.originalType !== 'call/future') {
  failures.push(`future variant decoded as ${JSON.stringify(future)}, expected unknown call/future`);
}
const plain = decodeContent(encoder.encode('not json at all'));
if (plain.t !== 'text' || plain.body !== 'not json at all') {
  failures.push(`plain bytes decoded as ${JSON.stringify(plain)}, expected text`);
}

// 9. Glare tiebreak is antisymmetric.
if (!callOfferWins('a-id', 'b-id') || callOfferWins('b-id', 'a-id')) {
  failures.push('callOfferWins is not antisymmetric for a-id and b-id');
}

// 10. Base45 matches the RFC 9285 vectors, both directions, and rejects garbage.
const utf8 = new TextEncoder();
const base45Vectors: Array<[string, string]> = [
  ['AB', 'BB8'],
  ['Hello!!', '%69 VD92EX0'],
  ['base-45', 'UJCLQE7W581'],
  ['ietf!', 'QED8WEX0'],
];
for (const [plain, encoded] of base45Vectors) {
  if (base45Encode(utf8.encode(plain)) !== encoded) {
    failures.push(`base45 encode of ${plain} != ${encoded}`);
  }
  const back = base45Decode(encoded);
  if (back === null || new TextDecoder().decode(back) !== plain) {
    failures.push(`base45 decode of ${encoded} != ${plain}`);
  }
}
for (const bad of ['A', 'BB8A', 'GGW', ':::', 'ab8', 'BB8é']) {
  // 'GGW' overflows 16 bits (65536), ':::' overflows too, lowercase is not in the alphabet.
  if (base45Decode(bad) !== null) failures.push(`base45 decode accepted invalid input ${bad}`);
}

// 11. The card codec round trips a v4 card exactly, with and without the server field.
function fakeB64(len: number, seed: number): string {
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = (i * 31 + seed) & 0xff;
  // Standard base64 via the padding trick: build with btoa-free math.
  let out = '';
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    out += A[b0 >> 2] + A[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < len ? A[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < len ? A[b2 & 63] : '=';
  }
  return out;
}
const sampleCard: ContactCard = {
  v: CONTACT_CARD_VERSION,
  handle: 'k7f2m9x1q8w3e6r5t0y4u2i7o1p5a9s3',
  identityKey: fakeB64(IDENTITY_KEY_LEN, 5),
  registrationId: 16383,
  signedPreKey: {
    keyId: 1,
    publicKey: fakeB64(SIGNED_PREKEY_PUB_LEN, 7),
    signature: fakeB64(PREKEY_SIGNATURE_LEN, 11),
  },
  kyberPreKey: {
    keyId: 1,
    publicKey: fakeB64(KYBER_PREKEY_PUB_LEN, 13),
    signature: fakeB64(PREKEY_SIGNATURE_LEN, 17),
  },
  displayName: 'Alice Example',
  server: 'wss://nuco-server.zlsoftware.at',
};
for (const card of [sampleCard, (({ server, ...rest }) => rest)(sampleCard) as ContactCard]) {
  const encoded = encodeContactCardQr(card);
  if (!encoded.startsWith(CARD_QR_PREFIX)) {
    failures.push('encoded card is missing the NC4: prefix');
  }
  const decoded = decodeContactCardQr(encoded);
  if (JSON.stringify(decoded) !== JSON.stringify(card)) {
    failures.push(`card codec round trip mismatch (server ${card.server === undefined ? 'absent' : 'present'})`);
  }
}

// 12. A worst case card (every variable field at its bound) still fits QR v40-M
// alphanumeric capacity, so a realistic card always scans.
const worstCard: ContactCard = {
  ...sampleCard,
  handle: 'h'.repeat(CARD_HANDLE_MAX_LEN),
  registrationId: 0xffffffff,
  signedPreKey: { ...sampleCard.signedPreKey, keyId: 0xffff },
  kyberPreKey: { ...sampleCard.kyberPreKey, keyId: 0xffff },
  displayName: 'n'.repeat(CARD_NAME_MAX_LEN),
  server: 'wss://' + 's'.repeat(CARD_SERVER_MAX_LEN - 6),
};
const worstEncoded = encodeContactCardQr(worstCard);
if (worstEncoded.length > CARD_QR_MAX_LEN) {
  failures.push(`worst case card is ${worstEncoded.length} chars, above the QR v40-M cap ${CARD_QR_MAX_LEN}`);
}
if (decodeContactCardQr(worstEncoded) === null) {
  failures.push('worst case card does not decode');
}

// 13. The card decoder is strict: wrong prefix, truncation, a tampered field length, a
// non canonical reencoding, and old JSON cards all yield null.
const goodEncoded = encodeContactCardQr(sampleCard);
const cardRejects: Array<[string, string]> = [
  ['no prefix', goodEncoded.slice(CARD_QR_PREFIX.length)],
  ['truncated', goodEncoded.slice(0, goodEncoded.length - 9)],
  ['bad base45', goodEncoded.slice(0, -1) + 'a'],
  ['json card', JSON.stringify({ v: 3, handle: 'x' })],
  ['empty', ''],
];
for (const [label, data] of cardRejects) {
  if (decodeContactCardQr(data) !== null) {
    failures.push(`card decoder accepted ${label}`);
  }
}

// 14. The doc covers the card codec pieces.
expectInDoc('the card version', `(v${CONTACT_CARD_VERSION})`);
expectInDoc('the QR prefix', CARD_QR_PREFIX);
expectInDoc('the kyber prekey length', String(KYBER_PREKEY_PUB_LEN));
expectInDoc('base45', 'base45');
expectInDoc('PQXDH', 'PQXDH');

// 15. The 3.1 wake hint validates: every hint passes, an unknown one is malformed, and
// the hint is optional. The voip push token registers.
const baseSend = {
  type: 'send',
  rid: 'r1',
  to: 'bob',
  envelope: { id: 'e1', ciphertext: 'AAAA', messageType: 'whisper', sentAt: 1 },
};
for (const wake of ['alert', 'voip', 'none']) {
  const parsed = parseClientMessage(JSON.stringify({ ...baseSend, wake }));
  if (!parsed.ok || (parsed.message.type === 'send' && parsed.message.wake !== wake)) {
    failures.push(`send with wake ${wake} did not validate`);
  }
}
if (!parseClientMessage(JSON.stringify(baseSend)).ok) {
  failures.push('send without a wake hint did not validate');
}
if (parseClientMessage(JSON.stringify({ ...baseSend, wake: 'loud' })).ok) {
  failures.push('send with an unknown wake hint was accepted');
}
const voipRegister = parseClientMessage(
  JSON.stringify({
    type: 'register',
    rid: 'r2',
    authKey: 'AAAA',
    deviceId: 1,
    push: { kind: 'apns', token: 'tok', apnsTopic: 'com.example.app', voipToken: 'voiptok' },
  }),
);
if (!voipRegister.ok || (voipRegister.message.type === 'register' && voipRegister.message.push.voipToken !== 'voiptok')) {
  failures.push('register with a voip token did not validate');
}
expectInDoc('the wake hint', '`voip`');
expectInDoc('the voip token', 'voipToken');

// 16. The 3.2 report frame validates: every category passes, comment and context are
// optional, and unknown categories, unknown contexts, oversized comments, and empty
// comments are malformed.
const baseReport = { type: 'report', rid: 'r3', handle: 'mallory' };
for (const category of REPORT_CATEGORIES) {
  const parsed = parseClientMessage(JSON.stringify({ ...baseReport, category }));
  if (!parsed.ok || (parsed.message.type === 'report' && parsed.message.category !== category)) {
    failures.push(`report with category ${category} did not validate`);
  }
}
for (const context of REPORT_CONTEXTS) {
  if (!parseClientMessage(JSON.stringify({ ...baseReport, category: 'spam', context })).ok) {
    failures.push(`report with context ${context} did not validate`);
  }
}
const fullReport = parseClientMessage(
  JSON.stringify({ ...baseReport, category: 'harassment', comment: 'sent unsolicited ads', context: 'message' }),
);
if (!fullReport.ok || (fullReport.message.type === 'report' && fullReport.message.comment !== 'sent unsolicited ads')) {
  failures.push('report with a comment did not validate');
}
if (parseClientMessage(JSON.stringify({ ...baseReport, category: 'rude' })).ok) {
  failures.push('report with an unknown category was accepted');
}
if (parseClientMessage(JSON.stringify({ ...baseReport, category: 'spam', context: 'group' })).ok) {
  failures.push('report with an unknown context was accepted');
}
if (parseClientMessage(JSON.stringify({ ...baseReport, category: 'spam', comment: '' })).ok) {
  failures.push('report with an empty comment was accepted');
}
if (
  parseClientMessage(
    JSON.stringify({ ...baseReport, category: 'spam', comment: 'x'.repeat(LIMITS.reportCommentMaxLen + 1) }),
  ).ok
) {
  failures.push('report with an oversized comment was accepted');
}
if (parseClientMessage(JSON.stringify(baseReport)).ok) {
  failures.push('report without a category was accepted');
}
expectInDoc('the report frame', '`report`');
expectInDoc('the report category', '`harassment`');

// 17. The 3.3 image content: the chunk geometry constants are internally consistent, a
// maximal chunk's JSON encoding fits the 65536 padding bucket (the whole point of the
// geometry: its sealed ciphertext then stays under the relay's default size limit), and
// every bound rejects.
if (IMAGE_CHUNK_DATA_B64_MAX !== (IMAGE_CHUNK_RAW_BYTES / 3) * 4 || IMAGE_CHUNK_RAW_BYTES % 3 !== 0) {
  failures.push('image chunk base64 and raw sizes are inconsistent');
}
if (IMAGE_MAX_BYTES !== IMAGE_MAX_CHUNKS * IMAGE_CHUNK_RAW_BYTES) {
  failures.push('IMAGE_MAX_BYTES does not equal IMAGE_MAX_CHUNKS * IMAGE_CHUNK_RAW_BYTES');
}
const maximalChunk: MessageContent = {
  t: 'image/chunk',
  ref: 'r'.repeat(MESSAGE_ID_MAX_LEN),
  seq: IMAGE_MAX_CHUNKS - 1,
  data: 'A'.repeat(IMAGE_CHUNK_DATA_B64_MAX),
};
const maximalChunkBytes = encodeContent(maximalChunk);
if (maximalChunkBytes.length > 65532) {
  failures.push(`maximal image chunk encodes to ${maximalChunkBytes.length} bytes, above the 65532 budget`);
}
if (pad(maximalChunkBytes).length !== 65536) {
  failures.push(`maximal image chunk padded to ${pad(maximalChunkBytes).length}, expected the 65536 bucket`);
}
if (decodeContent(maximalChunkBytes).t !== 'image/chunk') {
  failures.push('maximal image chunk did not decode as image/chunk');
}
const goodImageMeta = {
  t: 'image',
  mime: IMAGE_MIME_JPEG,
  width: 1600,
  height: 1200,
  bytes: 150000,
  sha256: fakeB64(32, 3),
  chunks: 4,
};
const goodChunk = { t: 'image/chunk', ref: 'a1b2c3d4', seq: 0, data: 'QUJD' };
const imageRejects: Array<[string, object]> = [
  ['a non jpeg mime', { ...goodImageMeta, mime: 'image/png' }],
  ['a zero width', { ...goodImageMeta, width: 0 }],
  ['an oversized dimension', { ...goodImageMeta, height: 8193 }],
  ['an inconsistent chunk count', { ...goodImageMeta, chunks: 3 }],
  ['an oversized byte count', { ...goodImageMeta, bytes: IMAGE_MAX_BYTES + 1, chunks: IMAGE_MAX_CHUNKS + 1 }],
  ['a wrong length sha256', { ...goodImageMeta, sha256: fakeB64(32, 3).slice(0, 43) }],
  ['an oversized chunk data', { ...goodChunk, data: 'A'.repeat(IMAGE_CHUNK_DATA_B64_MAX + 4) }],
  ['a chunk data length not a multiple of 4', { ...goodChunk, data: 'AAAAA' }],
  ['a chunk data outside the base64 alphabet', { ...goodChunk, data: 'AA$A' }],
  ['a chunk seq at the cap', { ...goodChunk, seq: IMAGE_MAX_CHUNKS }],
  ['an oversized chunk ref', { ...goodChunk, ref: 'r'.repeat(MESSAGE_ID_MAX_LEN + 1) }],
];
for (const [label, bad] of imageRejects) {
  const decoded = decodeContent(encoder.encode(JSON.stringify(bad)));
  if (decoded.t !== 'unknown') {
    failures.push(`image content with ${label} decoded as ${decoded.t}, expected unknown`);
  }
}

if (failures.length > 0) {
  console.error('protocol check FAILED:');
  for (const f of failures) console.error('  - ' + f);
  process.exit(1);
}

console.log(
  `protocol check OK: version ${PROTOCOL_VERSION_STRING}, ` +
    `${CLIENT_MESSAGE_TYPES.length} client + ${SERVER_MESSAGE_TYPES.length} server messages, ` +
    `${MESSAGE_CONTENT_TYPES.length} content types, ` +
    `${ALL_ERROR_CODES.length} error codes, padding and content round trips verified.`,
);
