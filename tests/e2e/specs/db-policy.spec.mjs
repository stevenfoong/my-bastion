// Phase 4a: database statement policies in the admin policy editor.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

test('a db_query policy is created with statement classes and listed', async ({ page }) => {
    let policies = [];
    const api = await installApi(page, {
        routes: {
            'GET /api/admin/policies': () => policies,
            'POST /api/admin/policies': (req) => {
                const p = { id: 1, enabled: true, ...req.postDataJSON() };
                policies = [p];
                return { status: 201, contentType: 'application/json', body: JSON.stringify(p) };
            }
        }
    });
    await page.goto('/admin.html');
    await settle(page);
    await page.locator('#pol-name').fill('no unbounded writes');
    await page.locator('#pol-subject-kind').selectOption('any');
    await page.locator('#pol-target-kind').selectOption('any');
    await page.locator('#pol-action').selectOption('db_query');
    await expect(page.locator('#pol-classes')).toBeVisible();
    await expect(page.locator('#pol-commands')).toBeVisible();
    await page.locator('#pol-classes').fill('unbounded, ddl');
    await page.locator('#pol-effect').selectOption('deny');
    await page.locator('#pol-add-btn').click();
    await expect.poll(() => api.calls.find(c => c.method === 'POST' && c.path === '/api/admin/policies')?.body)
        .toMatchObject({ action: 'db_query', classes: ['unbounded', 'ddl'], commands: [] });
    await expect(page.locator('body')).toContainText('DB statement (unbounded, ddl)');
    // Classes belong to db_query only.
    await page.locator('#pol-action').selectOption('connect');
    await expect(page.locator('#pol-classes')).toBeHidden();
});
