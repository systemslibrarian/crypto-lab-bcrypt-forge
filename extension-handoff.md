# Bcrypt Forge extension — terminology correction

Date: 2026-10-20. Brief read: `brief-extension.md`, copied without edits from
`extension-crypto-lab-bcrypt-forge.md`. Standard read in full:
`../crypto-lab/audits/_MASTER-TEMPLATE.md`.

## Starting evidence

Slug from `git remote -v`: `crypto-lab-bcrypt-forge`.
Starting main: `16fc3193fe11b1a1affc2ef77505085627451c07`.
`git log --oneline 16fc3193fe11..HEAD` was empty before editing.
The source really stores every distinct wordlist MD5 digest in a map.
The brief's listed labels were present. Its table calls this seven files;
the actual listed changes occupy six files. Its claim that the existing browser
test independently recomputed wordlist MD5 digests was not borne out by the test:
that independent Node/OpenSSL route is added by this change.

## Prepared changes

- Rename the exhibit's full map to a precomputed lookup table in UI, README,
  comments and test names. Leave the existing general MD5/rainbow-table statement
  in the Alternatives panel untouched.
- Explain the chain-endpoint distinction and qualify the salt lesson: a fresh,
  unpredictable salt prevents reuse of one unsalted table; separate guessing
  attacks remain possible. Avoid claiming rainbow chains cover every password.
- Check the button's initial label before it is replaced by the result count.
- Compare the displayed table size with independently recomputed distinct MD5
  digests using `node:crypto`, before checking recovered account cells.
- Allow the phrase “rainbow table” in Scenario B only in its explicit distinction.

No cryptographic behavior, dependencies, worker, theme, header, footer or workflow
changed. The final source sweep leaves intentional distinctions and their tests,
the existing Alternatives statement, and the supplied brief.

## Verification

- Production build passed, including both publishing-request tests.
- Unit suite: 25/25 passed, two test files.
- Browser gate: 18/18 passed, including the accessibility scan, against Chromium
  153.0.8010.0. The pinned Playwright browser download returned an unavailable page;
  the installed local browser was selected through an untracked configuration.
  The repository's original Playwright configuration and CI gate are unchanged.
- §4.1a: no setup helper or gate changed; assertions live in `e2e/claims.spec.ts`.
- §4.1b: the count is independently recomputed with Node/OpenSSL MD5. The label
  and the sole allowed rainbow-table distinction are asserted.
- §4.1c: 2/2 mutations killed by the named lookup claims test, with retries zero.
  Each had a green baseline, nonempty source diff, successful production build,
  changed production artifact digest, assertion failure, exact digest restoration,
  and restored green test. `mutation-evidence.json` records digests. The digest
  covers HTML and assets because the button label is shipped in HTML.
- §4.1d: no new negative fixture, explicitly outside this correction's scope.

## Catalog handoff

- Pages URL: https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/
- Implementation on main: `ec53d0342c2731ee2ea48f4e142a5d5ef18895fa`.
  Pages HTML contains the unique label once; served JS matches the tested build.
  `shipping-evidence.json` records the asset digest and successful workflow URL.
- Card copy and chips: no change proposed.
- New implemented algorithms: none. MD5 and the full-map lookup already existed.
  Rainbow chains remain explanatory prose, not an implemented algorithm.
- Concept: `concept-coverage.md`, “6. Key derivation and password hashing”.
- The actual corpus ID is `demo_crypto_lab_bcrypt_forge` (underscores). Its entry
  contains no “rainbow” claim to correct. Neither shared repository was modified.
  No link to the proposed Hash Hunt site was added.

Summary: build passed; 25 unit and 2 publish-request tests passed; 18 browser
tests passed; §4.1c 2/2 killed; accessibility gate passed.

The shared deploy-sync checker returned FLEET-UNREAD because only the task’s
14 sibling clones were available against its census of 236. Its census and gates
were not modified. The lab-specific deployment succeeded and the public asset
was compared byte-for-byte with the tested build.
