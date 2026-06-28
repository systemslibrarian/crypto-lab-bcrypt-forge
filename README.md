# crypto-lab-bcrypt-forge

## What It Is

bcrypt is a password hashing function designed by Niels Provos and David Mazières (1999), built on the Blowfish cipher with a deliberately slow and adaptive cost factor. It is the most widely deployed password hashing scheme in production systems, used by default in Rails, Node.js, PHP, and Linux PAM. Its adaptive cost factor allows security to be maintained as hardware improves without changing the stored hash format. The security model is one-way: hashes cannot be reversed, only verified.

## When to Use It

- ✅ Storing user passwords in any web application
- ✅ When your stack defaults to bcrypt (Rails, PHP, Node.js)
- ✅ When FIPS compliance is not required and Argon2 is not available
- ✅ Migrating away from plaintext, MD5, or raw SHA passwords
- ❌ Do not use for general-purpose data encryption (use AES-256-GCM)
- ❌ Do not use for API tokens or session IDs (use secure random bytes)
- ❌ Prefer Argon2id for new systems where you have freedom of choice
- ❌ Do NOT treat this as production crypto — it is a teaching demo, not a hardened auth system

## Live Demo

**[systemslibrarian.github.io/crypto-lab-bcrypt-forge](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/)**

Six exhibits: bcrypt anatomy with color-annotated output, live hash generator with cost slider and timing, cost factor benchmark across factors 8–14, timing-safe verify with attack visualizer, algorithm comparison table (bcrypt vs Argon2id vs PBKDF2 vs MD5), and a real-world breach simulation showing plaintext vs MD5 vs bcrypt outcomes.

Every hash is **real, computed in your browser** — never simulated. All CPU-heavy work (bcrypt, PBKDF2, MD5) runs in a **Web Worker**, so the UI stays smooth even while hashing at cost 14.

## What Can Go Wrong

- **72-byte input limit:** bcrypt only hashes the first 72 bytes of a password, so very long or multibyte passwords can share a prefix and collide.
- **Null-byte truncation:** some bcrypt implementations truncate at the first NUL byte, silently weakening passwords that contain one.
- **Cost factor set too low:** a cost that was safe years ago becomes cheap to brute-force as hardware improves, so it must be raised over time.
- **Cost factor set too high:** an excessive cost can turn login into a denial-of-service vector under load.
- **Wrong primitive:** bcrypt is for passwords, not general-purpose encryption, API tokens, or session identifiers.

## Real-World Usage

- Ruby on Rails `has_secure_password` uses bcrypt by default.
- PHP's `password_hash()` defaults to the bcrypt algorithm.
- Node.js applications widely use the `bcrypt` / `bcryptjs` libraries for credential storage.
- Linux PAM and many web frameworks have shipped bcrypt as a default password hash.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bcrypt-forge
cd crypto-lab-bcrypt-forge
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — HKDF, PBKDF2, scrypt, and Argon2id compared.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — chaining KDFs across HKDF/PBKDF2/scrypt/Argon2id.
- [crypto-lab-phantom-vault](https://systemslibrarian.github.io/crypto-lab-phantom-vault/) — PBKDF2-SHA-256 key derivation in practice.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — Argon2id with ChaCha20-Poly1305 encryption.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — the underlying hash families and why password hashing differs.

## Architecture

- **No frameworks.** Vanilla TypeScript, plain CSS with design tokens, mobile-first, WCAG 2.1 AA, dark/light theme, and `prefers-reduced-motion` support.
- **Web Worker crypto.** `src/crypto-worker.ts` runs bcrypt, PBKDF2, and MD5 off the main thread; `src/crypto-client.ts` is a promise-based RPC wrapper. Timings are measured *inside* the worker, so the benchmark numbers reflect the raw primitive rather than scheduling overhead — and the UI never freezes.
- **Pure, tested core.** `src/lib.ts` holds DOM-free helpers (MD5, bcrypt-hash parsing, duration formatting) covered by `npm test` — including MD5 known-answer vectors and a bcryptjs round-trip integration test.

## Deploy to GitHub Pages

This repository includes a workflow at `.github/workflows/deploy-pages.yml`.

1. Push to the `main` branch.
2. In GitHub, go to **Settings > Pages**.
3. Set **Source** to **GitHub Actions**.
4. Wait for the **Deploy to GitHub Pages** workflow to finish.

Your site will be published at:
**https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/**

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
