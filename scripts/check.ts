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
  { t: 'retention/request', value: 86400 },
  { t: 'retention/accept', value: 0 },
  { t: 'retention/cancel' },
  { t: 'screenshot/request', on: true },
  { t: 'screenshot/accept', on: false },
  { t: 'screenshot/cancel' },
  { t: 'call/offer', callId: 'a1b2c3d4-0000-4000-8000-000000000000', sdp: fakeSdp },
  { t: 'call/answer', callId: 'a1b2c3d4-0000-4000-8000-000000000000', sdp: fakeSdp },
  { t: 'call/end', callId: 'a1b2c3d4-0000-4000-8000-000000000000', reason: 'hangup' },
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

// 7. Bounds are enforced: an oversized sdp is not recognized as a call offer.
const oversized = decodeContent(
  encodeContent({ t: 'call/offer', callId: 'x', sdp: 'a'.repeat(CALL_SDP_MAX_LEN + 1) }),
);
if (oversized.t !== 'unknown') {
  failures.push(`oversized sdp decoded as ${oversized.t}, expected unknown`);
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
