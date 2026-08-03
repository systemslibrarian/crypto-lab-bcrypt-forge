import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Claims gate. Every load-bearing verdict, counter and tamper path this demo
 * advertises is asserted here against the rendered DOM — never against a
 * hardcoded transcript of what it once printed.
 *
 * The rule throughout: a claim is checked against the artifact it is a claim
 * ABOUT. "Cracked 8 of 9" is checked against the cells that actually say a
 * password; "4×" is checked against the cost the slider actually holds; a
 * timing multiplier is checked against the two millisecond figures rendered
 * beside it. Nothing here asserts a number the page did not compute, and
 * nothing asserts a number that only this file knows.
 */

const DEMO_USERS = [
  { username: 'alice', password: 'password123' },
  { username: 'bob', password: 'letmein' },
  { username: 'carol', password: 'qwerty' },
  { username: 'dave', password: '123456' },
  { username: 'eve', password: 'password123' },
  { username: 'frank', password: 'dragon' },
  { username: 'grace', password: 'iloveyou' },
  { username: 'heidi', password: 'monkey' },
  // The control account: its password is in no wordlist, so both attacks must
  // genuinely fail on it. That failure is what makes the successes mean anything.
  { username: 'ivan', password: 'tR7#qLp2$Wm9zVx4' },
];

const BCRYPT_RE = /^\$2[aby]?\$(\d{2})\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function squash(text: string | null | undefined): string {
  return (text ?? '').replace(/\s+/gu, ' ').trim();
}

async function textOf(locator: Locator): Promise<string> {
  return squash(await locator.textContent());
}

/** Pull one anchored number out of a label that may contain several. */
function numberFrom(text: string, pattern: RegExp): number {
  const match = pattern.exec(text);
  expect(match, `expected ${String(pattern)} to match ${JSON.stringify(text)}`).not.toBeNull();
  return Number(match![1].replace(/,/gu, ''));
}

/** The cost factor a bcrypt string actually encodes. */
function costOf(hash: string): number {
  const match = BCRYPT_RE.exec(hash);
  expect(match, `not a well-formed bcrypt hash: ${JSON.stringify(hash)}`).not.toBeNull();
  return Number(match![1]);
}

async function openPanel(page: Page, index: number): Promise<void> {
  await page.locator('.panel-tab').nth(index - 1).click();
  await expect(page.locator(`#panel-${index}`)).toBeVisible();
}

async function boot(page: Page): Promise<string[]> {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.goto('.');
  return errors;
}

/** Set a range input the way the page's own `input` listener sees it. */
async function setRange(page: Page, id: string, value: number): Promise<void> {
  await page.locator(`#${id}`).evaluate((element, next) => {
    (element as HTMLInputElement).value = String(next);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, value);
}

/* ================================================================== */
/* 1. Anatomy — the four coloured segments ARE the hash                */
/* ================================================================== */

test('the anatomy display dissects a real bcrypt hash without losing a character', async ({
  page,
}) => {
  const errors = await boot(page);

  const display = page.locator('#p1-anatomy-display');
  await expect(display.locator('.anatomy-hash')).toBeVisible({ timeout: 30_000 });

  const whole = squash(await display.textContent());
  expect(whole).toMatch(BCRYPT_RE);

  // The parts are a partition of the whole: concatenating the four coloured
  // spans in order must reproduce exactly the string on screen, with nothing
  // dropped, duplicated or invented by the annotator.
  const version = await textOf(display.locator('.anatomy-version'));
  const cost = await textOf(display.locator('.anatomy-cost'));
  const salt = await textOf(display.locator('.anatomy-salt'));
  const hash = await textOf(display.locator('.anatomy-hash'));
  expect(version + cost + salt + hash).toBe(whole);

  // And the legend's stated widths are the widths actually rendered.
  expect(salt).toHaveLength(22);
  expect(hash).toHaveLength(31);
  await expect(page.locator('#p1-anatomy-legend')).toContainText('Salt (22 chars)');
  await expect(page.locator('#p1-anatomy-legend')).toContainText('Hash (31 chars)');

  expect(errors).toEqual([]);
});

/* ================================================================== */
/* 2. Hash generator — the cost on screen is the cost in the hash      */
/* ================================================================== */

test('the generated hash carries the requested cost and the work bar matches it', async ({
  page,
}) => {
  test.slow();
  await boot(page);
  await openPanel(page, 2);

  await setRange(page, 'p2-cost', 6);
  await expect(page.locator('#p2-cost-value')).toHaveText('6');

  await page.locator('#p2-hash-btn').click();
  await expect(page.locator('#p2-result .anatomy-hash')).toBeVisible({ timeout: 60_000 });

  const rendered = squash(await page.locator('#p2-result').textContent()).replace(/^Copy\s*/u, '');
  expect(rendered).toMatch(BCRYPT_RE);

  // The headline claim of this panel: you asked for cost 6 and bcrypt's own
  // modular-crypt string says cost 6. Read back off the hash, not off state.
  expect(costOf(rendered)).toBe(6);

  // The work bar is a claim about the same cost. 2^(6-10) = 1/16.
  await expect(page.locator('#p2-cost-bar')).toContainText('1/16×');

  // And the timing line reports the run that just happened.
  expect(await textOf(page.locator('#p2-timing'))).toMatch(/^Computed in [\d.]+ ms$/u);
});

test('a hash from Exhibit 2 verifies in Exhibit 4 — the two panels agree about one hash', async ({
  page,
}) => {
  test.slow();
  await boot(page);
  await openPanel(page, 2);

  const password = 'a-password-only-this-test-knows';
  await page.locator('#p2-password').fill(password);
  await setRange(page, 'p2-cost', 6);
  await page.locator('#p2-hash-btn').click();
  await expect(page.locator('#p2-result .anatomy-hash')).toBeVisible({ timeout: 60_000 });

  const hash = squash(await page.locator('#p2-result').textContent()).replace(/^Copy\s*/u, '');
  expect(hash).toMatch(BCRYPT_RE);

  // Cross-surface agreement: the generator's output, fed to the verifier, is
  // accepted for the password it was made from and rejected for any other.
  // Neither panel is asked to grade its own work.
  await openPanel(page, 4);
  await page.locator('#p4-password').fill(password);
  await page.locator('#p4-hash').fill(hash);
  await page.locator('#p4-verify-btn').click();
  await expect(page.locator('#p4-verify-result .verify-result--match')).toContainText('✓ Match', {
    timeout: 60_000,
  });

  await page.locator('#p4-password').fill(`${password}!`);
  await page.locator('#p4-verify-btn').click();
  await expect(page.locator('#p4-verify-result .verify-result--no-match')).toContainText(
    '✗ No match',
    { timeout: 60_000 },
  );
});

test('editing the generator inputs retires the hash they produced', async ({ page }) => {
  test.slow();
  await boot(page);
  await openPanel(page, 2);

  await setRange(page, 'p2-cost', 6);
  await page.locator('#p2-hash-btn').click();
  await expect(page.locator('#p2-result .anatomy-hash')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#p2-cost-bar')).toContainText('1/16×');

  // A rendered hash is an answer about one password at one cost. Move the cost
  // slider and the hash on screen — which still says $2b$06$ — is an answer to
  // a question nobody is asking any more, sitting under a work bar that now
  // contradicts the slider.
  await setRange(page, 'p2-cost', 12);
  await expect(page.locator('#p2-result .anatomy-hash')).toHaveCount(0);
  await expect(page.locator('#p2-cost-bar')).toBeEmpty();
  await expect(page.locator('#p2-timing')).toBeEmpty();

  // Same for the password: re-hash, then type, and the stale answer goes.
  await page.locator('#p2-hash-btn').click();
  await expect(page.locator('#p2-result .anatomy-hash')).toBeVisible({ timeout: 60_000 });
  await page.locator('#p2-password').fill('something-else');
  await expect(page.locator('#p2-result .anatomy-hash')).toHaveCount(0);
  await expect(page.locator('#p2-cost-bar')).toBeEmpty();
});

/* ================================================================== */
/* 3. Benchmark — every column checked against the milliseconds beside it */
/* ================================================================== */

test('the benchmark rows agree with their own timings, and the legend appears only after a run', async ({
  page,
}) => {
  test.slow();
  await boot(page);
  await openPanel(page, 3);

  // The `[hidden]` trap, asserted where it bit: the threshold legend explains
  // markers on bars that do not exist yet, so before the first run it must not
  // be painted — the attribute has to actually mean something.
  const legend = page.locator('#p3-thresholds');
  await expect(legend).toHaveAttribute('hidden', '');
  await expect(legend).not.toBeVisible();

  await page.locator('#p3-run-btn').click();
  await expect(page.locator('#p3-status')).toHaveText('Benchmark complete.', { timeout: 180_000 });

  await expect(legend).toBeVisible();

  const rows = page.locator('#p3-chart .bar-row');
  await expect(rows).toHaveCount(7);

  const costs: number[] = [];
  const times: number[] = [];
  const widths: number[] = [];

  for (let index = 0; index < 7; index += 1) {
    const row = rows.nth(index);
    const cost = Number(await textOf(row.locator('.bar-label')));
    const timeMs = numberFrom(await textOf(row.locator('.bar-time')), /^(\d+) ms$/u);
    const multiplier = numberFrom(await textOf(row.locator('.bar-multiplier')), /^([\d.]+)×$/u);
    const verdict = await textOf(row.locator('.bar-verdict'));

    costs.push(cost);
    times.push(timeMs);
    widths.push(
      Number(
        /width:\s*([\d.]+)%/u.exec((await row.locator('.bar-fill').getAttribute('style')) ?? '')![1],
      ),
    );

    // The multiplier column is a claim relating this row's time to the cost-8
    // row's time. Both numbers are on screen, so the claim must follow from
    // them. Each is rendered to whole milliseconds, so the true times lie
    // within ±0.5 ms of what is printed; the multiplier must fall inside the
    // interval that admits, and the multiplier's own 1dp rounding. That is the
    // exact slack the display introduces — not a tolerance picked to pass.
    const ratioLow = (timeMs - 0.5) / (times[0] + 0.5);
    const ratioHigh = (timeMs + 0.5) / (times[0] - 0.5);
    expect(multiplier).toBeGreaterThanOrEqual(ratioLow - 0.05);
    expect(multiplier).toBeLessThanOrEqual(ratioHigh + 0.05);

    // The verdict is a claim about the 250 ms human-perception threshold, and
    // the millisecond figure it is a claim about is rendered right beside it.
    expect(verdict).toBe(timeMs <= 250 ? 'feels instant' : 'attacker-costly');
    await expect(row.locator('.bar-verdict')).toHaveClass(
      timeMs <= 250 ? /bar-verdict--login/u : /bar-verdict--attack/u,
    );

    // Colour encodes the stated safe/danger boundary at cost 10.
    await expect(row.locator('.bar-fill')).toHaveClass(
      cost >= 10 ? /bar-fill--safe/u : /bar-fill--danger/u,
    );
  }

  expect(costs).toEqual([8, 9, 10, 11, 12, 13, 14]);

  // Bar widths are that row's time over the largest time — the bars have to be
  // to scale, or the picture contradicts the numbers printed on it.
  const maxTime = Math.max(...times);
  for (let index = 0; index < 7; index += 1) {
    expect(widths[index]).toBeGreaterThanOrEqual(((times[index] - 0.5) / (maxTime + 0.5)) * 100);
    expect(widths[index]).toBeLessThanOrEqual(((times[index] + 0.5) / (maxTime - 0.5)) * 100);
  }
  expect(Math.max(...widths)).toBeCloseTo(100, 1);

  // bcrypt's defining property, measured rather than asserted: the whole point
  // of the panel is that cost 14 is dramatically more work than cost 8.
  expect(times[6]).toBeGreaterThan(times[0]);

  // The cracking estimates are driven by the run that just happened: the stated
  // guess rate is the measured cost-8 time scaled by the stated GPU multiplier.
  const estimates = page.locator('#p3-cracking-estimates');
  const model = await textOf(estimates);
  const parallelism = numberFrom(model, /running ([\d,]+)× the single-thread rate/u);
  const quoted = numberFrom(model, /~([\d,]+) guesses\/second/u);
  const quotedAtCost = numberFrom(model, /At cost (\d+) that works out to/u);
  expect(parallelism).toBe(10_000);
  expect(quotedAtCost).toBe(costs[0]);
  // The stated guess rate is the cost-8 time this run measured, scaled by the
  // multiplier the same paragraph states. Both inputs are on screen; the only
  // slack allowed is the ±0.5 ms the whole-millisecond timing column hides.
  expect(quoted).toBeGreaterThanOrEqual(Math.floor((1000 / (times[0] + 0.5)) * parallelism));
  expect(quoted).toBeLessThanOrEqual(Math.ceil((1000 / (times[0] - 0.5)) * parallelism));

  // One estimate per benchmarked cost, in the same order the chart used.
  const estimateLabels = (await estimates.locator('span').allTextContents())
    .map(squash)
    .filter((label) => /^Cost \d+$/u.test(label));
  expect(estimateLabels).toEqual(costs.map((cost) => `Cost ${cost}`));
});

/* ================================================================== */
/* 4. Verify — the verdict, and the inputs it is a verdict about       */
/* ================================================================== */

test('the example pairs reach opposite verdicts, each earned from a real compare', async ({
  page,
}) => {
  test.slow();
  await boot(page);
  await openPanel(page, 4);

  const result = page.locator('#p4-verify-result');
  const correctBtn = page.locator('#p4-example-correct-btn');

  // The example buttons stay inert until the example hash exists — a control
  // that is enabled must be a control that works.
  await expect(correctBtn).toBeEnabled({ timeout: 60_000 });

  await correctBtn.click();
  const loadedHash = await page.locator('#p4-hash').inputValue();
  expect(loadedHash).toMatch(BCRYPT_RE);
  expect(await page.locator('#p4-password').inputValue()).toBe('correcthorsebatterystaple');

  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--match')).toContainText('✓ Match', {
    timeout: 60_000,
  });

  // Same hash, wrong password — the opposite verdict, so the verifier is live
  // and capable of answering both ways rather than always saying yes.
  await page.locator('#p4-example-wrong-btn').click();
  expect(await page.locator('#p4-hash').inputValue()).toBe(loadedHash);
  expect(await page.locator('#p4-password').inputValue()).toBe('wrongpassword');

  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--no-match')).toContainText('✗ No match', {
    timeout: 60_000,
  });
});

test('a verdict does not outlive the inputs it was computed from', async ({ page }) => {
  test.slow();
  await boot(page);
  await openPanel(page, 4);

  const result = page.locator('#p4-verify-result');
  await expect(page.locator('#p4-example-correct-btn')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#p4-example-correct-btn').click();
  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--match')).toBeVisible({ timeout: 60_000 });

  // Typing in the password retires it: "✓ Match" above a password the page has
  // not checked is a claim nobody computed.
  await page.locator('#p4-password').fill('correcthorsebatterystapl');
  await expect(result.locator('.verify-result')).toHaveCount(0);
  await expect(result).toContainText('Inputs changed');

  // And the retired verdict is genuinely retired, not merely repainted: running
  // the check on the edited pair now reaches the opposite answer.
  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--no-match')).toBeVisible({ timeout: 60_000 });

  // Editing the hash retires it too.
  await page.locator('#p4-example-correct-btn').click();
  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--match')).toBeVisible({ timeout: 60_000 });
  await page.locator('#p4-hash').fill('$2b$10$abcdefghijklmnopqrstuv');
  await expect(result.locator('.verify-result')).toHaveCount(0);
  await expect(result).toContainText('Inputs changed');

  // Loading an example pair replaces both inputs at once, so it must retire the
  // verdict as well — this is the route that changes the most under the answer.
  await page.locator('#p4-example-correct-btn').click();
  await page.locator('#p4-verify-btn').click();
  await expect(result.locator('.verify-result--match')).toBeVisible({ timeout: 60_000 });
  await page.locator('#p4-example-wrong-btn').click();
  await expect(result.locator('.verify-result')).toHaveCount(0);
});

test('a malformed hash is refused before any compare is attempted', async ({ page }) => {
  await boot(page);
  await openPanel(page, 4);

  await page.locator('#p4-password').fill('anything');
  await page.locator('#p4-hash').fill('not-a-bcrypt-hash');
  await page.locator('#p4-verify-btn').click();
  await expect(page.locator('#p4-verify-result')).toContainText('Invalid bcrypt hash format');

  // An empty field is a different refusal, and neither is a verdict.
  await page.locator('#p4-hash').fill('');
  await page.locator('#p4-verify-btn').click();
  await expect(page.locator('#p4-verify-result')).toContainText(
    'Please enter both a password and a hash',
  );
  await expect(page.locator('#p4-verify-result .verify-result--match')).toHaveCount(0);
});

/* ================================================================== */
/* 5. Comparison table — the expand rows really are hidden             */
/* ================================================================== */

test('every algorithm row expands, and its detail is hidden until it does', async ({ page }) => {
  await boot(page);
  await openPanel(page, 5);

  const triggers = page.locator('#p5-table-body [data-expandable]');
  await expect(triggers).toHaveCount(6);

  const details = page.locator('#p5-table-body .expand-row');
  await expect(details).toHaveCount(6);
  for (let index = 0; index < 6; index += 1) {
    await expect(details.nth(index)).not.toBeVisible();
    await expect(triggers.nth(index)).toHaveAttribute('aria-expanded', 'false');
  }

  // The state the row advertises and the state the browser paints must agree,
  // in both directions.
  await triggers.first().click();
  await expect(triggers.first()).toHaveAttribute('aria-expanded', 'true');
  await expect(details.first()).toBeVisible();
  await expect(details.first()).not.toBeEmpty();

  await triggers.first().click();
  await expect(triggers.first()).toHaveAttribute('aria-expanded', 'false');
  await expect(details.first()).not.toBeVisible();
});

/* ================================================================== */
/* 6. The three breach scenarios                                       */
/* ================================================================== */

test('the plaintext breach reveals exactly the stored passwords', async ({ page }) => {
  await boot(page);
  await openPanel(page, 6);

  const cells = page.locator('#p6a-table-container .p6a-pw');
  await expect(cells).toHaveCount(DEMO_USERS.length);
  for (const cell of await cells.all()) {
    expect(await textOf(cell)).toBe('••••••••');
  }

  await page.locator('#p6a-breach-btn').click();

  // Plaintext storage means the breach is total — every account, no exceptions,
  // including the one both hashed scenarios fail to crack.
  const revealed = (await cells.allTextContents()).map(squash);
  expect(revealed).toEqual(DEMO_USERS.map((user) => user.password));
  await expect(page.locator('#p6a-callout')).toBeVisible();
  await expect(page.locator('#p6a-breach-btn')).toBeDisabled();
});

test('the rainbow-table button is never live before its table exists', async ({ page }) => {
  await boot(page);
  await page.locator('.panel-tab').nth(5).click();

  const button = page.locator('#p6b-breach-btn');
  const table = page.locator('#p6b-table-container table');

  // The MD5 digests queue behind every bcrypt hash this page starts on load, so
  // there is a real window in which the button exists but its handler does not.
  // An enabled button that silently swallows the click is worse than a disabled
  // one: sample the pair until the table lands and hold the invariant at every
  // sample.
  let sawTablePending = false;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const [enabled, ready] = await Promise.all([button.isEnabled(), table.count()]);
    if (!ready) {
      sawTablePending = true;
      expect(
        enabled,
        'the rainbow-table button was enabled while its table had not been built yet',
      ).toBe(false);
    } else {
      break;
    }
    await page.waitForTimeout(20);
  }

  expect(sawTablePending, 'never observed the pre-table window').toBe(true);
  await expect(table).toBeVisible({ timeout: 60_000 });
  await expect(button).toBeEnabled({ timeout: 60_000 });

  // And once enabled it genuinely acts on the very first click.
  await button.click();
  await expect(page.locator('#p6b-summary')).toContainText('Precomputed', { timeout: 120_000 });
});

test('the rainbow-table lookup is a real lookup, and its counter matches the cells', async ({
  page,
}) => {
  test.slow();
  await boot(page);
  await openPanel(page, 6);

  const rows = page.locator('#p6b-table-container tbody tr');
  await expect(rows).toHaveCount(DEMO_USERS.length, { timeout: 60_000 });

  // Unsalted means identical passwords produce identical digests — the whole
  // reason a precomputed table works. alice and eve share a password.
  const digests = (await page.locator('#p6b-table-container tbody tr td:nth-child(2)').allTextContents()).map(
    squash,
  );
  expect(digests[0]).toMatch(/^[0-9a-f]{32}$/u);
  expect(digests[0]).toBe(digests[4]);
  expect(new Set(digests).size).toBe(DEMO_USERS.length - 1);

  // The page's own duplicate notice must count the duplicates actually present.
  await expect(page.locator('#p6b-table-container')).toContainText('1 hash(es) appear more than once');

  await expect(page.locator('#p6b-breach-btn')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#p6b-breach-btn').click();
  await expect(page.locator('#p6b-summary')).toContainText('Precomputed', { timeout: 120_000 });

  const cells = page.locator('#p6b-table-container .p6b-crack');
  const verdicts = (await cells.allTextContents()).map(squash);

  // Recovered cells must name the true password, and a miss must be a real
  // miss — the cell only ever held a digest, so it cannot reveal on a whim.
  const hits: string[] = [];
  const misses: string[] = [];
  for (const [index, verdict] of verdicts.entries()) {
    if (verdict === 'not in table') {
      misses.push(DEMO_USERS[index].username);
    } else {
      expect(verdict).toBe(DEMO_USERS[index].password);
      hits.push(DEMO_USERS[index].username);
    }
  }

  // ivan's password is in no wordlist; every other demo password is.
  expect(misses).toEqual(['ivan']);
  expect(hits).toHaveLength(DEMO_USERS.length - 1);

  // The summary counter is a claim about those cells.
  const summary = await textOf(page.locator('#p6b-summary'));
  expect(numberFrom(summary, /recovered ([\d,]+) of/u)).toBe(hits.length);
  expect(numberFrom(summary, /of (\d+) passwords by table lookup/u)).toBe(DEMO_USERS.length);
  expect(numberFrom(summary, /^Precomputed ([\d,]+) MD5 digests/u)).toBeGreaterThan(200);
  expect(summary).toContain(`${misses.length} account(s) survived`);

  // The button's own label repeats the same count.
  expect(await textOf(page.locator('#p6b-breach-btn'))).toBe(
    `${hits.length} of ${DEMO_USERS.length} Cracked`,
  );
  await expect(page.locator('#p6b-callout')).toBeVisible();
});

test('the bcrypt dictionary attack reports the accounts it actually cracked, and retires that report when the cost changes', async ({
  page,
}) => {
  test.slow();
  test.setTimeout(300_000);
  await boot(page);
  await openPanel(page, 6);

  const button = page.locator('#p6c-breach-btn');
  const summary = page.locator('#p6c-summary');
  const impact = page.locator('#p6c-impact');
  const callout = page.locator('#p6c-callout');

  // Wait out the cost-12 table the panel builds on load, then downgrade to the
  // cost the experiment is about.
  await expect(button).toBeEnabled({ timeout: 240_000 });
  await page.locator('input[name="p6c-cost"][value="4"]').check();
  await expect(page.locator('#p6c-cost-label')).toHaveText('4');
  await expect(button).toBeEnabled({ timeout: 240_000 });

  // Every stored hash really is bcrypt at the selected cost.
  const stored = (await page.locator('#p6c-table-container .p6c-hash').allTextContents()).map(squash);
  expect(stored).toHaveLength(DEMO_USERS.length);
  for (const hash of stored) {
    expect(costOf(hash)).toBe(4);
  }
  // Per-account salt: alice and eve share a password and must not share a hash.
  expect(stored[0]).not.toBe(stored[4]);
  expect(new Set(stored).size).toBe(DEMO_USERS.length);

  await button.click();
  await expect(summary).toContainText('Result at cost', { timeout: 240_000 });

  // The counter is a claim about the cells beside it.
  const cracked: string[] = [];
  const survived: string[] = [];
  for (const user of DEMO_USERS) {
    const verdict = await textOf(page.locator(`#p6c-crack-${user.username}`));
    if (verdict === 'survived') {
      survived.push(user.username);
    } else {
      // A cracked cell names the password the attack recovered — and it has to
      // be the real one, recovered by a real bcrypt.compare.
      expect(verdict).toMatch(new RegExp(`^${user.password.replace(/[$#]/gu, '\\$&')} \\(word #\\d+\\)$`, 'u'));
      cracked.push(user.username);
    }
  }

  const summaryText = await textOf(summary);
  expect(numberFrom(summaryText, /Result at cost \d+: (\d+) of/u)).toBe(cracked.length);
  expect(numberFrom(summaryText, /of (\d+) accounts cracked/u)).toBe(DEMO_USERS.length);
  expect(numberFrom(summaryText, /(\d+) survived/u)).toBe(survived.length);
  expect(numberFrom(summaryText, /Result at cost (\d+):/u)).toBe(4);

  // ivan's password is outside the wordlist, so no amount of budget cracks it.
  expect(survived).toContain('ivan');
  // At cost 4 the list runs fast enough that the weak accounts genuinely fall;
  // without that the panel would be demonstrating nothing.
  expect(cracked.length).toBeGreaterThan(0);

  // The progress line and the Impact panel must quote the same run.
  const progress = await textOf(page.locator('#p6c-progress-text'));
  const attempts = numberFrom(progress, /^([\d,]+) real bcrypt comparisons/u);
  const rate = numberFrom(progress, /a measured ([\d.]+) ms per guess/u);
  expect(numberFrom(progress, /at cost (\d+)/u)).toBe(4);
  expect(numberFrom(summaryText, /Every one of those ([\d,]+) guesses/u)).toBe(attempts);

  const impactText = await textOf(impact);
  expect(numberFrom(impactText, /At the cost-(\d+) rate/u)).toBe(4);
  expect(numberFrom(impactText, /\(([\d.]+) ms per guess\)/u)).toBe(rate);
  await expect(callout).toBeVisible();

  // ── The retirement ───────────────────────────────────────────────
  // Switching the stored cost re-hashes the database, which retires the run.
  // The Impact paragraph quotes a rate measured at the OLD cost; leaving it up
  // puts a cost-4 conclusion under a cost-8 table.
  await page.locator('input[name="p6c-cost"][value="8"]').check();
  await expect(page.locator('#p6c-cost-label')).toHaveText('8');

  await expect(summary).toBeEmpty();
  await expect(impact).toBeEmpty();
  await expect(callout).not.toBeVisible();
  await expect(page.locator('#p6c-progress')).not.toBeVisible();
  expect(await textOf(button)).toBe('Run Real Dictionary Attack');

  // The verdict cells go with it: the table is being rebuilt at the new cost,
  // so no account may still be labelled cracked from the previous run.
  await expect(button).toBeEnabled({ timeout: 240_000 });
  for (const user of DEMO_USERS) {
    expect(await textOf(page.locator(`#p6c-crack-${user.username}`))).toBe('not attempted');
  }
  const rehashed = (await page.locator('#p6c-table-container .p6c-hash').allTextContents()).map(squash);
  for (const hash of rehashed) {
    expect(costOf(hash)).toBe(8);
  }
});
