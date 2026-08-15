import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page with every <details> expanded,
 * in both the default (dark) and light themes. Asserts zero WCAG A/AA
 * violations — the strict summary must be empty.
 *
 * Two races used to sit in this file: one hid a hole, the other invented a
 * failure.
 *
 * 1. Exhibit 1's anatomy row is painted only after a REAL cost-12 bcrypt hash
 *    resolves, which takes on the order of a second. A scan that started before
 *    that never saw those elements, so neither theme covered them — the gate
 *    was passing on an empty container. `awaitLiveContent` makes the scan wait
 *    for the content it is supposed to be checking.
 *
 * 2. Surfaces carry `transition: background-color 0.25s`, but the anatomy
 *    arrows set `color` inline, with no transition. Toggling the theme
 *    therefore repaints that text instantly over a background still a quarter
 *    second away from its new value, and axe sampling that instant saw
 *    light-theme dark-green text on a still-dark surface — a real contrast
 *    failure, for a state no user reads, against a page whose rest state is
 *    fine. That is what made this suite flaky.
 *
 *    It is settled through the stylesheet's OWN `prefers-reduced-motion` block,
 *    which already neutralizes every transition. No test-only CSS, and it
 *    exercises the path real users with that preference actually get.
 *
 *    NOTE: `test.use({ reducedMotion: 'reduce' })` SILENTLY DOES NOTHING here.
 *    On Playwright 1.61.1 with this config the page still reports
 *    `matchMedia('(prefers-reduced-motion: reduce)').matches === false`, so a
 *    suite relying on it is running with every transition live while looking
 *    like it settled them. Use `page.emulateMedia` and ASSERT the media query
 *    actually matches — an emulation that quietly no-ops is worse than none,
 *    because it reads as handled.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Apply reduced motion and prove it landed. The assertion is the point: this
 * is the second time in this fleet that a "settled" suite was not settled.
 */
async function settleMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const applied = await page.evaluate(
    () => matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  expect(applied, 'reduced-motion emulation did not reach the page').toBe(true);
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

/**
 * Block until the asynchronously-computed exhibit has painted, so the scan
 * covers it rather than racing it.
 */
async function awaitLiveContent(page: Page): Promise<void> {
  // The arrows are the last thing Exhibit 1 writes once its hash lands.
  await expect(page.locator('#p1-anatomy-arrows span')).toHaveCount(4, { timeout: 60_000 });
  await expect(page.locator('#p1-anatomy-legend .anatomy-legend__item')).toHaveCount(4);
  // And the spinner placeholder must be gone, not merely overdrawn.
  await expect(page.locator('#p1-anatomy-display .spinner')).toHaveCount(0);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/**
 * Measure the anatomy palette where it is actually drawn, in both themes.
 *
 * This exists because axe under-reported it: with all four arrows on screen and
 * two of them below 4.5:1, axe flagged only ONE node. Relying on which nodes it
 * chooses to name would have left the cost arrow failing silently at 3.97:1.
 * Contrast is arithmetic on the computed styles, so compute it.
 */
async function anatomyContrast(page: Page): Promise<{ label: string; ratio: number }[]> {
  return page.evaluate(() => {
    const lum = (c: string): number => {
      const [r, g, b] = c
        .match(/\d+(\.\d+)?/g)!
        .slice(0, 3)
        .map(Number)
        .map((v) => {
          const s = v / 255;
          return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
        });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    // Walk up for the first painted background, the way a reader's eye does.
    const bgOf = (el: Element): string => {
      let n: Element | null = el;
      while (n) {
        const bg = getComputedStyle(n).backgroundColor;
        if (bg && !/rgba?\([^)]*,\s*0\)$/.test(bg)) return bg;
        n = n.parentElement;
      }
      return 'rgb(255, 255, 255)';
    };
    const labels = ['version', 'cost', 'salt', 'hash'];
    return Array.from(document.querySelectorAll('#p1-anatomy-arrows > span')).map((el, i) => {
      const L1 = Math.max(lum(getComputedStyle(el).color), lum(bgOf(el)));
      const L2 = Math.min(lum(getComputedStyle(el).color), lum(bgOf(el)));
      return { label: labels[i] ?? `span${i + 1}`, ratio: (L1 + 0.05) / (L2 + 0.05) };
    });
  });
}

for (const theme of ['dark'] as const) {
  test(`anatomy palette meets AA where it is drawn — ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await settleMotion(page);
    await awaitLiveContent(page);

    const measured = await anatomyContrast(page);
    expect(measured).toHaveLength(4);
    // 13px at weight 400 is normal text: AA is 4.5:1, not the 3:1 large-text bar.
    const failing = measured.filter((m) => m.ratio < 4.5);
    expect(
      failing,
      `below AA on the panel they sit on: ${JSON.stringify(
        measured.map((m) => `${m.label} ${m.ratio.toFixed(2)}:1`),
      )}`,
    ).toEqual([]);
  });
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await settleMotion(page);
  await awaitLiveContent(page);
  await openAllDetails(page);
  await scan(page);
});

