# crypto-lab-bcrypt-forge

**`Blowfish` · `bcrypt` · `Cost Factor` · `Timing-Safe`**

**Live demo:** [https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/)

---

## What It Is

bcrypt is a password hashing function designed by Niels Provos and David Mazières (1999), built on the Blowfish cipher with a deliberately slow and adaptive cost factor. It is the most widely deployed password hashing scheme in production systems, used by default in Rails, Node.js, PHP, and Linux PAM. Its adaptive cost factor allows security to be maintained as hardware improves without changing the stored hash format. The security model is one-way: hashes cannot be reversed, only verified.

---

## When to Use It

- ✅ Storing user passwords in any web application
- ✅ When your stack defaults to bcrypt (Rails, PHP, Node.js)
- ✅ When FIPS compliance is not required and Argon2 is not available
- ✅ Migrating away from plaintext, MD5, or raw SHA passwords
- ❌ Do not use for general-purpose data encryption (use AES-256-GCM)
- ❌ Do not use for API tokens or session IDs (use secure random bytes)
- ❌ Prefer Argon2id for new systems where you have freedom of choice

---

## Live Demo

**[https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/)**

Six exhibits: bcrypt anatomy with color-annotated output, live hash generator with cost slider and timing, cost factor benchmark across factors 8–14, timing-safe verify with attack visualizer, algorithm comparison table (bcrypt vs Argon2id vs PBKDF2 vs MD5), and a real-world breach simulation showing plaintext vs MD5 vs bcrypt outcomes.

---

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bcrypt-forge
cd crypto-lab-bcrypt-forge
npm install
npm run dev
```

---

## Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — browser-based cryptography demos spanning 2,500 years of cryptographic history to NIST FIPS 2024 post-quantum standards.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31