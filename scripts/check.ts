// Drift and self test for @nuco/protocol. Run with `npm run check`.
// Fails (exit 1) if PROTOCOL.md does not document every message type, every error
// code, and the current version, or if the padding round trip is broken.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  PROTOCOL_VERSION_STRING,
  ALL_ERROR_CODES,
  CLIENT_MESSAGE_TYPES,
  SERVER_MESSAGE_TYPES,
  PADDING_BUCKETS,
  pad,
  unpad,
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

if (failures.length > 0) {
  console.error('protocol check FAILED:');
  for (const f of failures) console.error('  - ' + f);
  process.exit(1);
}

console.log(
  `protocol check OK: version ${PROTOCOL_VERSION_STRING}, ` +
    `${CLIENT_MESSAGE_TYPES.length} client + ${SERVER_MESSAGE_TYPES.length} server messages, ` +
    `${ALL_ERROR_CODES.length} error codes, padding round trip verified.`,
);
