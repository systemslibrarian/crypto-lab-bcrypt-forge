# crypto-lab-bcrypt-forge

## What It Is

bcrypt is a password hashing function designed by Niels Provos and David Mazières (1999), built on the Blowfish cipher with a deliberately slow and adaptive cost factor. Its "cost" is literally an exponent: the expensive Eksblowfish key schedule re-mixes the password and salt into a 4 KB Blowfish state 2^cost times, so each +1 to the cost doubles the work — that iterated key setup is *why* bcrypt is intrinsically slow. It is one of the most widely deployed password hashing schemes in production systems: the default in Rails and PHP, a common choice in Node.js, and the default password hash on OpenBSD, where it originated. On Linux, bcrypt (`$2b$`) is supported through libxcrypt but is *not* the `/etc/shadow` default — most distributions use SHA-512-crypt (`$6$`), and Debian 11+, Ubuntu 22.04+, and Fedora 35+ default to yescrypt (`$y$`). Its adaptive cost factor allows security to be maintained as hardware improves without changing the stored hash format. The security model is one-way: hashes cannot be reversed, only verified.

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

Six exhibits:

1. **Anatomy** — color-annotated bcrypt output (version/cost/salt/hash), plus a "Why bcrypt is slow" panel that **executes the real Eksblowfish key schedule** at a cost you pick: the grid and round counter are driven by rounds that genuinely completed, so the wait you sit through doubles with every +1 to cost. Plus an interactive **72-byte-limit** demo where two long passwords that share a 72-byte prefix cross-verify.
2. **Hash Generator** — live cost slider with real timing.
3. **Benchmark** — cost factors 8–14 with a ~250 ms "login sweet spot" threshold marker so the recommended cost is visually motivated (fast enough for login, slow enough for attackers).
4. **Verify** — timing-safe comparison framed as a *secondary* hardening (slowness + salt is the headline), with a choice between measuring real microsecond timings over thousands of trials or a clearly-labeled simulated/exaggerated leak.
5. **Alternatives** — algorithm comparison table (bcrypt vs Argon2id vs scrypt vs PBKDF2 vs MD5) with inline definitions for terms like *timing oracle* and *PRF*.
6. **Attack Demo** — plaintext vs unsalted MD5 vs bcrypt, attacked for real. The MD5 scenario builds an **actual rainbow table** (MD5 of every word in the bundled common-password list) and recovers accounts by lookup — an account whose password is not in the list genuinely survives. The bcrypt scenario runs an **actual dictionary attack**: every guess is a real `bcrypt.compare` against a real stored hash, and the panel reports the attempts that executed and the rate measured. A **cost-downgrade selector** re-hashes the database at cost 4, 8, or 12 and reruns the identical attack, so the cost factor is the only variable — at cost 4 the list finishes in seconds and the weak accounts fall; at cost 12 the same attack barely starts. alice/eve share a password so salting's effect is visible at a glance.

Every hash is **real, computed in your browser** — never simulated, and no progress bar is driven by a timer. All CPU-heavy work (bcrypt, PBKDF2, MD5) runs in a **Web Worker**, so the UI stays smooth even while hashing at cost 14.

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
- OpenBSD uses bcrypt as its default password hash — the scheme was designed there (Provos & Mazières, USENIX 1999).
- On Linux, libxcrypt implements bcrypt (`$2b$`) so such hashes verify fine, but it is not the `/etc/shadow` default: distributions ship SHA-512-crypt (`$6$`), or yescrypt (`$y$`) on Debian 11+, Ubuntu 22.04+, and Fedora 35+.

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
- **Web Worker crypto.** `src/crypto-worker.ts` runs bcrypt, PBKDF2, and MD5 off the main thread; `src/crypto-client.ts` is a promise-based RPC wrapper. Timings are measured *inside* the worker, so the benchmark numbers reflect the raw primitive rather than scheduling overhead — and the UI never freezes. Long-running operations (the key schedule, the dictionary attack) stream **genuine progress** back over the same channel, so on-screen counters only ever report work that actually happened.
- **Pure, tested core.** `src/lib.ts` holds DOM-free helpers (MD5, bcrypt-hash parsing, duration formatting, and the common-password wordlist both attacks run against) covered by `npm test` — including MD5 known-answer vectors and a bcryptjs round-trip integration test.

## Deploy to GitHub Pages

This repository includes a workflow at `.github/workflows/deploy-pages.yml`.

1. Push to the `main` branch.
2. In GitHub, go to **Settings > Pages**.
3. Set **Source** to **GitHub Actions**.
4. Wait for the **Deploy to GitHub Pages** workflow to finish.

Your site will be published at:
**https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/**

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
