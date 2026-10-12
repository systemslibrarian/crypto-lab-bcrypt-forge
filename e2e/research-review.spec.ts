import {test,expect} from '@playwright/test';
test('expanded Argon2id comparison cites the precise NIST edition',async({page})=>{
 await page.goto('./');
 await page.locator('[role="tab"]').nth(4).click();
 const row=page.locator('[data-algo="Argon2id"]');
 await row.click();
 const detail=row.locator('xpath=following-sibling::tr[1]');
 await expect(detail).toContainText('SP 800-63B-4 (July 2025)');
 await expect(detail.locator('a')).toHaveAttribute('href','https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#passwordver');
 await expect(detail).not.toContainText('names PBKDF2 and Balloon');
});
