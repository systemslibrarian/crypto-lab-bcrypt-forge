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
test('the cost callout attributes the minimum to OWASP and gives its figure',async({page})=>{
 await page.goto('./');
 await page.locator('[role="tab"]').nth(1).click();
 const callout=page.locator('#panel-2 .callout');
 await expect(callout).toContainText('minimum at cost 10');
 await expect(callout).toContainText('Password Storage Cheat Sheet');
 await expect(callout.locator('a')).toHaveAttribute('href','https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html');
 // OWASP's bcrypt minimum is 10, not 12, and no source makes 12 a minimum.
 await expect(callout).not.toContainText('Cost 12 is the current recommended minimum');
});
test('the bcrypt-over-Argon2id callout sends FIPS users to PBKDF2, not to bcrypt',async({page})=>{
 await page.goto('./');
 await page.locator('[role="tab"]').nth(4).click();
 const callout=page.locator('#panel-5 .callout--valid');
 await expect(callout).toContainText('PBKDF2');
 // A FIPS-140 requirement rules out bcrypt (Blowfish) as well as Argon2, so
 // FIPS can never be the reason to pick bcrypt.
 await expect(callout).not.toContainText('FIPS compliance rules out Argon2');
});
