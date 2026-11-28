import { expect, test } from '@playwright/test';

test('editing either password clears the completed or pending comparison', async ({ page }) => {
  await page.goto('.');
  const a = page.locator('#p1-72-a');
  const b = page.locator('#p1-72-b');
  const run = page.locator('#p1-72-run-btn');
  const result = page.locator('#p1-72-result');
  await a.fill('sample A');
  await b.fill('sample A');
  await run.click();
  await expect(result).toContainText('true');
  await b.fill('sample B');
  await expect(result).toBeEmpty();
  await run.click();
  await expect(result).toContainText('false');
  await a.fill('example');
  await expect(result).toBeEmpty();
  await run.click();
  await b.fill('edited during hashing');
  await expect(run).toBeEnabled();
  await expect(result).toBeEmpty();
  await expect(page.locator('#p1-anatomy-heading')).toHaveText('Four-Part Output Anatomy');
});
