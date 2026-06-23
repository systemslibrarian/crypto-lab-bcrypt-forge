import { describe, it, expect } from 'vitest';
import { md5, parseBcryptHash, isBcryptHash, formatDuration, variance } from './lib.ts';

describe('md5', () => {
  // Canonical RFC 1321 / well-known test vectors.
  it.each([
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['a', '0cc175b9c0f1b6a831c399e269772661'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    ['The quick brown fox jumps over the lazy dog', '9e107d9d372bb6826bd81d3542a419d6'],
    ['password123', '482c811da5d5b4bc6d497ffa98491e38'],
  ])('md5(%j) = %s', (input, expected) => {
    expect(md5(input)).toBe(expected);
  });

  it('handles multi-byte UTF-8 input', () => {
    // MD5 operates on the UTF-8 bytes of the string.
    expect(md5('héllo')).toBe('be50e8478cf24ff3595bc7307fb91b50');
  });

  it('is deterministic and produces 32 hex chars', () => {
    const out = md5('anything');
    expect(out).toMatch(/^[0-9a-f]{32}$/);
    expect(out).toBe(md5('anything'));
  });
});

describe('parseBcryptHash', () => {
  const sample = '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW';

  it('splits a valid hash into version, cost, salt, and hash', () => {
    const parts = parseBcryptHash(sample);
    expect(parts).not.toBeNull();
    expect(parts!.version).toBe('$2b$');
    expect(parts!.cost).toBe('12$');
    expect(parts!.salt).toHaveLength(22);
    expect(parts!.hash).toHaveLength(31);
    // Round-trips back to the original string.
    expect(parts!.version + parts!.cost + parts!.salt + parts!.hash).toBe(sample);
  });

  it('accepts the $2a$ and $2y$ variants', () => {
    expect(parseBcryptHash(sample.replace('$2b$', '$2a$'))).not.toBeNull();
    expect(parseBcryptHash(sample.replace('$2b$', '$2y$'))).not.toBeNull();
  });

  it('returns null for malformed input', () => {
    expect(parseBcryptHash('not-a-hash')).toBeNull();
    expect(parseBcryptHash('')).toBeNull();
    expect(parseBcryptHash(sample.slice(0, -1))).toBeNull(); // one char short
  });
});

describe('isBcryptHash', () => {
  it('mirrors parseBcryptHash validity', () => {
    expect(isBcryptHash('$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW')).toBe(true);
    expect(isBcryptHash('plain')).toBe(false);
  });
});

describe('formatDuration', () => {
  it('selects a sensible unit', () => {
    expect(formatDuration(0.5)).toBe('0.5 seconds');
    expect(formatDuration(42)).toBe('42 seconds');
    expect(formatDuration(120)).toBe('2.0 minutes');
    expect(formatDuration(7_200)).toBe('2.0 hours');
    expect(formatDuration(172_800)).toBe('2.0 days');
    expect(formatDuration(63_072_000)).toBe('2.0 years');
  });

  it('handles infinity', () => {
    expect(formatDuration(Infinity)).toBe('∞');
  });
});

describe('variance', () => {
  it('is zero for constant or empty input', () => {
    expect(variance([])).toBe(0);
    expect(variance([5, 5, 5])).toBe(0);
  });

  it('computes population variance', () => {
    expect(variance([2, 4, 6])).toBeCloseTo(2.6667, 3);
  });
});
