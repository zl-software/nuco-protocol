// Fixed size message padding applied to the PLAINTEXT before Signal encryption, so
// the relay observes only bucketed ciphertext sizes rather than exact lengths. The
// scheme is part of the wire contract: both peers must pad and unpad identically.
//
// Layout: a 4 byte big endian original length, then the plaintext, then zero bytes
// up to the smallest bucket that fits. Inputs larger than the largest bucket are
// rounded up to a whole multiple of it.

export const PADDING_BUCKETS: readonly number[] = [256, 1024, 4096, 16384, 65536];

const LENGTH_PREFIX = 4;

function targetSize(total: number): number {
  for (const bucket of PADDING_BUCKETS) {
    if (total <= bucket) return bucket;
  }
  const largest = PADDING_BUCKETS[PADDING_BUCKETS.length - 1] as number;
  return Math.ceil(total / largest) * largest;
}

export function pad(data: Uint8Array): Uint8Array {
  const total = LENGTH_PREFIX + data.length;
  const out = new Uint8Array(targetSize(total));
  new DataView(out.buffer).setUint32(0, data.length, false);
  out.set(data, LENGTH_PREFIX);
  return out;
}

export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < LENGTH_PREFIX) {
    throw new Error('padded buffer is shorter than the length prefix');
  }
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const len = view.getUint32(0, false);
  if (LENGTH_PREFIX + len > padded.length) {
    throw new Error('padding length prefix exceeds the buffer');
  }
  return padded.slice(LENGTH_PREFIX, LENGTH_PREFIX + len);
}
