# Extension brief — `crypto-lab-bcrypt-forge`

**2026-10-20. Correctness fix to a live lab; no new repository.** Written against
`crypto-lab-bcrypt-forge` at `16fc3193fe11` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the issue:
Katz–Lindell, *Introduction to Modern Cryptography*, 3rd ed., §6.4.3 (time/space
tradeoffs) and §6.6.3 (password hashing).

**Verdict: relabel, not a feature.** The bcrypt mechanics are right. One exhibit calls
the wrong thing a rainbow table, and the label has spread through seven files.

## The issue

Exhibit 6, Scenario B builds a **full digest → password map**: it MD5s every word in
`COMMON_PASSWORDS` and stores every pair (`src/exhibits.ts:1056–1059`:
`const table = new Map<string, string>(); digests.forEach(... table.set(d, COMMON_PASSWORDS[i]) ...)`).
That is a precomputed lookup table — Katz–Lindell §6.4.3's first, trivial option: store
every `(x, H(x))` pair, invert in constant time, pay memory equal to the space covered.

A **rainbow table** is a different object: chains `x → H → R₁ → H → R₂ → …` with a
different reduction function per column, of which only the start and end points are
stored, trading memory for online lookup time (Hellman 1980; Oechslin 2003, who coined
"rainbow tables" — Katz–Lindell cite him for the term). Nothing in this lab builds chains
or reduction functions. The exhibit's lesson — an unsalted digest is a hash-map hit, and
a salt destroys precomputation — is correct and survives the relabel unchanged.

## Every place the claim appears (propagation sweep)

`grep -rni rainbow` over the repo at `16fc3193fe11` (excluding `node_modules`, `.git`,
`dist`) — twelve matching lines in seven files, all listed below (eleven to change, one
to leave). Fix each:

| # | Location | Now | Change to |
|---|---|---|---|
| 1 | `src/exhibits.ts:1014` (doc comment) | `Scenario B — a REAL rainbow table.` | `Scenario B — a REAL precomputed lookup table (every word stored; not a rainbow table).` |
| 2 | `src/exhibits.ts:1089` (summary copy) | `a rainbow table can only return what was put into it.` | `a precomputed table can only return what was put into it.` |
| 3 | `src/lib.ts:65` (doc comment) | `Scenario B precomputes the MD5 of every entry — that is the rainbow table.` | `Scenario B precomputes the MD5 of every entry — a full lookup table.` |
| 4 | `src/lib.test.ts:107` (test title) | `yields a collision-free MD5 rainbow table` | `yields a collision-free MD5 lookup table` |
| 5 | `index.html:167` (hero `.cl-hero-desc`) | `…hold up against breach and rainbow-table attacks.` | `…hold up against breach and precomputed-table attacks.` |
| 6 | `index.html:654` (button) | `Look Up in Rainbow Table` | `Look Up in Precomputed Table` |
| 7 | `index.html:660` (Impact callout) | `Rainbow tables precompute hashes for billions of common passwords.` | see wording below |
| 8 | `README.md:29` (Exhibits item 6) | `builds an **actual rainbow table** (MD5 of every word…)` | `builds an **actual precomputed lookup table** (MD5 of every word…)` plus the one-line distinction below |
| 9 | `e2e/claims.spec.ts:461, 480, 497` (test titles + failure message) | `the rainbow-table button…`, `the rainbow-table lookup…` | `the precomputed-table button…`, `the precomputed-table lookup…` |

**Leave alone, deliberately:** `src/exhibits.ts:818`, the MD5 row of the Alternatives table
(*"Rainbow tables for MD5 are freely available and cover most common passwords."*). That
is a statement about the real world, not about this exhibit, and it is accurate in kind.
If you touch it, widen it to "Precomputed tables — full lookup tables and rainbow tables —
for unsalted MD5 are freely available"; do not narrow it.

**Callout wording (#7)** — replace the first sentence; keep the rest of the callout:

> This exhibit stored every word's digest — a full lookup table. A rainbow table reaches
> the same answers while storing only the ends of long hash chains, trading memory for
> lookup time. Either way the work is done once and reused against every unsalted breach;
> a per-user salt defeats both, because no table built in advance matches a salt chosen
> afterwards.

**README distinction (#8)** — one sentence after the item: "A rainbow table would store
only chain endpoints and trade memory for lookup time; this exhibit stores every pair,
which is the simplest precomputation and enough to make the point about salts."

**Before committing, re-run the sweep** — `grep -rni rainbow . --exclude-dir={node_modules,.git,dist}`
— and confirm the only survivors are the deliberate ones (#7's new sentence, #8's new
sentence, and `src/exhibits.ts:818`).

## SECURITY / CORRECTNESS INVARIANTS

1. No behaviour changes: same wordlist, same MD5 calls, same lookup, same counts, same
   button states. This pass changes words.
2. Every sentence on the page that names the Scenario B object names it as a precomputed
   or lookup table.
3. The salt lesson stays: the page still says the salt is what defeats precomputation.

## Tests

The existing claims tests at `e2e/claims.spec.ts:461` and `:497` keep their logic; only
their titles and the failure message at `:480` change (#9). Add one assertion to the
`:497` test, in `claims.spec.ts` (copy belongs there per §4.1a, not in `e2e/gate.ts`):

- **The object is what the page calls it.** After the lookup runs, parse
  `Precomputed N MD5 digests` from `#p6b-summary` (already parsed at `:547`) and assert
  `N` equals the number of distinct MD5 digests of the wordlist — recomputed in the test,
  as the existing test already does for the per-cell checks. A full table stores one
  entry per word; a rainbow table stores far fewer entries than it covers. That
  equality is the property that makes "lookup table" true.
- **Label guard.** Assert `#p6-scenario-b` does not contain the phrase "rainbow table"
  except inside the one distinguishing sentence (match that sentence exactly and assert it
  is the only occurrence).

**§4.1c:** the repo has no mutation script at this commit (no `scripts/`); this pass
renders no new verdict, so the five-step manual check is enough. Mutate the button label
back to `Look Up in Rainbow Table` and confirm the label-guard assertion fails by name;
change the table build to skip every other word and confirm the `N` assertion fails by
name; restore both and confirm the bundle hash returns.

**§4.1d:** the lab has no negative-claim test at this commit
(`grep -in negative e2e/claims.spec.ts` → nothing). Not this pass's job; note it in the
handoff.

## README and card follow-up

- README: #8 above. No other section changes.
- Catalog handoff (do not edit `../crypto-lab` or `../crypto-counsel` from the lab
  window): the card at `../crypto-lab/index.html` for this lab does not mention rainbow
  tables at `f48d9d2f2f06` (checked). **Grep the crypto-counsel corpus entry
  `demo_crypto_lab_bcrypt-forge` for "rainbow"** — it was not available to this brief —
  and correct it in the catalog pass if it repeats the claim.
- Cross-link: `crypto-lab-hash-hunt` is proposed in this same batch to build real
  Hellman/rainbow chains. **Do not link it until its Pages site is live.** Until then the
  callout may name it in prose ("a separate lab, Hash Hunt, is planned to build real
  rainbow chains") or say nothing; never a dead link.

## Do not touch

bcrypt, PBKDF2 and MD5 code paths, the Web Worker, cost-factor logic, Scenario A and C,
the benchmark, timing-safe verification, header, theme pin, footer.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369): §6.4.3 (full table vs Hellman's tradeoff), §6.6.3 (rainbow tables and
  salts), References for Chapter 6 (Oechslin coined "rainbow tables").
- M. E. Hellman, "A Cryptanalytic Time-Memory Trade-Off", *IEEE Transactions on
  Information Theory*, vol. IT-26, no. 4, pp. 401–406, July 1980. Verified at
  https://ee.stanford.edu/~hellman/publications/36.pdf
- P. Oechslin, "Making a Faster Cryptanalytic Time-Memory Trade-Off", CRYPTO 2003, LNCS
  2729, pp. 617–630, doi:10.1007/978-3-540-45146-4_36. Verified at
  https://link.springer.com/chapter/10.1007/978-3-540-45146-4_36
