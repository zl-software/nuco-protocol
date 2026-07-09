// Base45 (RFC 9285): binary to text encoding whose alphabet is exactly the QR code
// alphanumeric character set, so a base45 payload rides QR alphanumeric mode, which
// packs 5.5 bits per character instead of 8 bits per byte in byte mode. Used for the
// contact card (see card-codec.ts). Encoding only, no crypto.

const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

const REVERSE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
  return table;
})();

export function base45Encode(data: Uint8Array): string {
  const out: string[] = [];
  const full = data.length - (data.length % 2);
  for (let i = 0; i < full; i += 2) {
    let n = (data[i] as number) * 256 + (data[i + 1] as number);
    const c = n % 45;
    n = (n - c) / 45;
    const d = n % 45;
    const e = (n - d) / 45;
    out.push(ALPHABET.charAt(c), ALPHABET.charAt(d), ALPHABET.charAt(e));
  }
  if (data.length % 2 === 1) {
    const n = data[data.length - 1] as number;
    out.push(ALPHABET.charAt(n % 45), ALPHABET.charAt((n - (n % 45)) / 45));
  }
  return out.join('');
}

// Strict decode: any character outside the alphabet, a dangling single character, or a
// group whose value overflows its byte range returns null.
export function base45Decode(text: string): Uint8Array | null {
  const rem = text.length % 3;
  if (rem === 1) return null;
  const out = new Uint8Array(((text.length - rem) / 3) * 2 + (rem === 2 ? 1 : 0));
  let pos = 0;
  const digit = (i: number): number => {
    const code = text.charCodeAt(i);
    return code < 128 ? (REVERSE[code] as number) : -1;
  };
  const full = text.length - rem;
  for (let i = 0; i < full; i += 3) {
    const c = digit(i);
    const d = digit(i + 1);
    const e = digit(i + 2);
    if (c < 0 || d < 0 || e < 0) return null;
    const n = c + d * 45 + e * 2025;
    if (n > 65535) return null;
    out[pos++] = (n / 256) | 0;
    out[pos++] = n % 256;
  }
  if (rem === 2) {
    const c = digit(text.length - 2);
    const d = digit(text.length - 1);
    if (c < 0 || d < 0) return null;
    const n = c + d * 45;
    if (n > 255) return null;
    out[pos] = n;
  }
  return out;
}
