/**
 * Integration test: exercises the *real* bcryptjs library through the same
 * parsing/validation the worker and UI rely on. Runs headlessly in Node, so
 * CI catches any drift between bcryptjs output and our hash anatomy parser.
 */
import { describe, it, expect } from 'vitest';
import bcrypt from 'bcryptjs';
import { parseBcryptHash, isBcryptHash } from './lib.ts';

describe('bcryptjs ↔ lib integration', () => {
  it('produces a hash our parser accepts, with the expected cost', () => {
    const salt = bcrypt.genSaltSync(8); // low cost keeps the test fast
    const hash = bcrypt.hashSync('correcthorsebatterystaple', salt);

    expect(isBcryptHash(hash)).toBe(true);
    const parts = parseBcryptHash(hash);
    expect(parts).not.toBeNull();
    expect(parts!.cost).toBe('08$');
    expect(parts!.salt).toHaveLength(22);
    expect(parts!.hash).toHaveLength(31);
  });

  it('verifies the correct password and rejects a wrong one', () => {
    const hash = bcrypt.hashSync('hunter2', bcrypt.genSaltSync(8));
    expect(bcrypt.compareSync('hunter2', hash)).toBe(true);
    expect(bcrypt.compareSync('hunter3', hash)).toBe(false);
  });

  it('gives identical passwords different hashes (unique salts)', () => {
    const a = bcrypt.hashSync('password123', bcrypt.genSaltSync(8));
    const b = bcrypt.hashSync('password123', bcrypt.genSaltSync(8));
    expect(a).not.toBe(b);
    // ...yet both still verify against the original password.
    expect(bcrypt.compareSync('password123', a)).toBe(true);
    expect(bcrypt.compareSync('password123', b)).toBe(true);
  });
});
