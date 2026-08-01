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

// ─── Attacker dictionary (Exhibit 6) ──────────────────────────────

/**
 * A real common-password list, ordered roughly by published real-world
 * frequency (the familiar top-of-the-leak ordering: `123456`, `password`,
 * `qwerty`, …). Slurs and sexually explicit entries that appear in the raw
 * published lists have been removed, so positions are approximate rather than
 * exact leak ranks.
 *
 * This is the ACTUAL list both attacks in Exhibit 6 run against:
 *  - Scenario B precomputes the MD5 of every entry — that is the rainbow table.
 *  - Scenario C feeds every entry to bcrypt.compare against the stored hashes.
 *
 * It is deliberately small enough to finish in a browser tab. The UI reports
 * the true entry count and the measured hash rate, and extrapolates to a
 * realistic 100,000-word list from the *measured* rate rather than a constant.
 */
export const COMMON_PASSWORDS: readonly string[] = [
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
  '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football',
  'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
  '123321', 'mustang', '1234567890', 'michael', '654321', 'superman',
  '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer',
  'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
  'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
  '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel',
  'starwars', 'klaster', '112233', 'george', 'computer', 'michelle',
  'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313',
  'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger',
  'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley',
  '6969', 'nicole', 'chelsea', 'matthew', 'access', 'yankees', '987654321',
  'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'william', 'corvette',
  'hello', 'martin', 'heather', 'secret', 'merlin', 'diamond', '1234qwer',
  'hammer', 'silver', '222222', '88888888', 'anthony', 'justin', 'test',
  'bailey', 'q1w2e3r4t5', 'patrick', 'internet', 'scooter', 'orange',
  '11111', 'golfer', 'cookie', 'richard', 'samantha', 'bigdog', 'guitar',
  'jackson', 'whatever', 'mickey', 'chicken', 'sparky', 'snoopy',
  'maverick', 'phoenix', 'camaro', 'peanut', 'morgan', 'welcome', 'falcon',
  'cowboy', 'ferrari', 'samsung', 'andrea', 'smokey', 'steelers', 'joseph',
  'mercedes', 'dakota', 'arsenal', 'eagles', 'melissa', 'boomer', 'booboo',
  'spider', 'password123', 'nascar', 'monster', 'tigers', 'yellow',
  '123123123', 'gateway', 'marina', 'diablo', 'bulldog', 'qwer1234',
  'compaq', 'purple', 'banana', 'junior', 'hannah', '123654', 'porsche',
  'lakers', 'iceman', 'money', 'cowboys', '987654', 'london', 'tennis',
  '999999', 'ncc1701', 'coffee', 'scooby', '0000', 'miller', 'boston',
  'q1w2e3r4', 'brandon', 'yamaha', 'chester', 'mother', 'forever', 'johnny',
  'edward', '333333', 'oliver', 'redsox', 'player', 'nikita', 'knight',
  'fender', 'barney', 'midnight', 'please', 'brandy', 'chicago', 'jasper',
  'enter', 'rachel', 'chris', 'steven', 'winner', 'adidas', 'victoria',
  'natasha', '1q2w3e4r', 'jasmine', 'winter', 'prince', 'marine', 'fishing',
  'cocacola', 'casper', 'james', '232323', 'raiders', 'passw0rd',
  'letmein123', 'admin', 'root', 'welcome1', 'password1', 'qwerty123',
];

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
