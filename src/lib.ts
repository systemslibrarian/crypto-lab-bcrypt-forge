/**
 * lib.ts — Pure, DOM-free helpers shared by the UI, the crypto Web Worker,
 * and the unit tests. Nothing here touches `window` or `document`, so every
 * function is deterministic and testable under Node/Vitest.
 */

// ─── bcrypt hash anatomy ──────────────────────────────────────────

export interface BcryptParts {
  version: string; // e.g. "$2b$"
  cost: string;    // e.g. "12$"
  salt: string;    // 22 chars
  hash: string;    // 31 chars
}

/**
 * Split a bcrypt modular-crypt string into its four labelled segments.
 * Returns null if the string is not a well-formed bcrypt hash.
 */
export function parseBcryptHash(hash: string): BcryptParts | null {
  const match = hash.match(/^(\$2[aby]?\$)(\d{2}\$)(.{22})(.{31})$/);
  if (!match) return null;
  return { version: match[1], cost: match[2], salt: match[3], hash: match[4] };
}

/** True when `hash` is a structurally valid bcrypt modular-crypt string. */
export function isBcryptHash(hash: string): boolean {
  return /^\$2[aby]?\$\d{2}\$.{53}$/.test(hash);
}

// ─── Duration formatting ──────────────────────────────────────────

/**
 * Human-readable duration from a count of seconds, auto-selecting the
 * largest sensible unit (seconds → minutes → hours → days → years).
 */
export function formatDuration(seconds: number): string {
  if (!isFinite(seconds)) return '∞';
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : seconds.toFixed(0)} seconds`;
  if (seconds < 3_600) return `${(seconds / 60).toFixed(1)} minutes`;
  if (seconds < 86_400) return `${(seconds / 3_600).toFixed(1)} hours`;
  if (seconds < 31_536_000) return `${(seconds / 86_400).toFixed(1)} days`;
  return `${(seconds / 31_536_000).toFixed(1)} years`;
}

// ─── Statistics ───────────────────────────────────────────────────

/** Population variance of a numeric array (0 for empty/singleton arrays). */
export function variance(arr: number[]): number {
  if (arr.length === 0) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((sum, v) => sum + (v - mean) ** 2, 0) / arr.length;
}

// ─── MD5 (educational use only — Exhibit 6) ───────────────────────

/**
 * A from-scratch MD5 implementation, used only to demonstrate why fast,
 * unsalted hashes are catastrophic for password storage. Never use MD5
 * for anything security-sensitive.
 */
export function md5(message: string): string {
  function rotateLeft(x: number, c: number): number {
    return (x << c) | (x >>> (32 - c));
  }
  function addUnsigned(a: number, b: number): number {
    return (a + b) >>> 0;
  }
  const F = (x: number, y: number, z: number): number => (x & y) | (~x & z);
  const G = (x: number, y: number, z: number): number => (x & z) | (y & ~z);
  const H = (x: number, y: number, z: number): number => x ^ y ^ z;
  const I = (x: number, y: number, z: number): number => y ^ (x | ~z);

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  const K = new Array<number>(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }

  const encoder = new TextEncoder();
  const input = encoder.encode(message);
  const bitLen = input.length * 8;

  const paddedLen = (((input.length + 8) >>> 6) + 1) * 64;
  const data = new Uint8Array(paddedLen);
  data.set(input);
  data[input.length] = 0x80;

  const view = new DataView(data.buffer);
  view.setUint32(paddedLen - 8, bitLen >>> 0, true);
  view.setUint32(paddedLen - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < paddedLen; offset += 64) {
    const M = new Array<number>(16);
    for (let i = 0; i < 16; i++) {
      M[i] = view.getUint32(offset + i * 4, true);
    }

    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let f = 0;
      let g = 0;

      if (i < 16) {
        f = F(B, C, D);
        g = i;
      } else if (i < 32) {
        f = G(B, C, D);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = H(B, C, D);
        g = (3 * i + 5) % 16;
      } else {
        f = I(B, C, D);
        g = (7 * i) % 16;
      }

      const tmp = D;
      D = C;
      C = B;
      B = addUnsigned(B, rotateLeft(addUnsigned(addUnsigned(A, f), addUnsigned(K[i], M[g])), S[i]));
      A = tmp;
    }

    a0 = addUnsigned(a0, A);
    b0 = addUnsigned(b0, B);
    c0 = addUnsigned(c0, C);
    d0 = addUnsigned(d0, D);
  }

  const toHexLE = (n: number): string =>
    [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]
      .map(v => v.toString(16).padStart(2, '0'))
      .join('');

  return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
}
