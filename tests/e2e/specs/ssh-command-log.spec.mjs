// Phase 2e: the admin page lists the lines typed in interactive SSH
// sessions, with their flags, and filters them.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const now = Math.floor(Date.now() / 1000);
const rows = [
    { id: 3, at: now - 10, session_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', actor: 'op@example.com',
      requester: 'op@example.com', target: 'shared/prod/web01', line: 'rm -rf /var/www',
      uncertain: false, pasted: false, redacted: false, policy: 'no rm in prod', effect: 'deny' },
    { id: 2, at: now - 20, session_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', actor: 'op@example.com',
      requester: 'op@example.com', target: 'shared/prod/web01', line: '',
      uncertain: false, pasted: false, redacted: true, policy: null, effect: null },
    { id: 1, at: now - 30, session_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', actor: 'op@example.com',
      requester: 'op@example.com', target: 'shared/prod/web01', line: 'systemctl restart ng',
      uncertain: true, pasted: false, redacted: false, policy: null, effect: null }
];

test('typed lines are listed with their flags and filtered', async ({ page }) => {
    const api = await installApi(page, {
        routes: {
            'GET /api/admin/ssh-commands': (req, url) =>
                url.searchParams.get('alerts') === 'true' ? rows.filter(r => r.policy) : rows
        }
    });
    await page.goto('/admin.html');
    await settle(page);

    const body = page.locator('#cmd-body');
    await expect(body.locator('tr')).toHaveCount(3);
    await expect(body.locator('tr').nth(0)).toContainText('rm -rf /var/www');
    await expect(body.locator('tr').nth(0)).toContainText('no rm in prod (deny)');
    await expect(body.locator('tr').nth(1)).toContainText('(hidden)');
    await expect(body.locator('tr').nth(1)).toContainText('redacted');
    await expect(body.locator('tr').nth(2)).toContainText('uncertain');

    await page.locator('#cmd-search').fill('rm -rf');
    await page.locator('#cmd-alerts').check();
    await page.locator('#cmd-filter-btn').click();
    await expect(body.locator('tr')).toHaveCount(1);
    const last = api.calls.filter(c => c.path === '/api/admin/ssh-commands').pop();
    expect(last.query).toMatchObject({ q: 'rm -rf', alerts: 'true' });
});

test('an empty log says so', async ({ page }) => {
    await installApi(page, { routes: { 'GET /api/admin/ssh-commands': [] } });
    await page.goto('/admin.html');
    await settle(page);
    await expect(page.locator('#no-cmd')).toBeVisible();
});
