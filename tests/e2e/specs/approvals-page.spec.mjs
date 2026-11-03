// Phase 2a/2c: the Approvals page lists the requests the user may decide and
// their own, and Approve/Deny post the decision with the comment.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const now = Math.floor(Date.now() / 1000);
const waiting = {
    id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', requester_display: 'contractor@example.com',
    target_label: 'shared/prod/web01', policy_name: 'contractors to prod', reason: 'patching',
    status: 'pending', created_at: now - 60, expires_at: now + 1740
};
const mine = {
    id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', requester_display: 'admin@example.com',
    target_label: 'shared/lab/box', policy_name: 'everyone to lab', status: 'approved',
    decided_by: 'boss@example.com', comment: 'go ahead', created_at: now - 600, grant_until: now + 3000
};

test('approve a waiting request with a comment', async ({ page }) => {
    const state = { decided: false };
    const api = await installApi(page, {
        routes: {
            'GET /api/approvals': () => ({ to_decide: state.decided ? [] : [waiting], mine: [mine], recent: [] }),
            [`POST /api/approvals/${waiting.id}/approve`]: () => {
                state.decided = true;
                return { ...waiting, status: 'approved' };
            }
        }
    });
    await page.goto('/approvals.html');
    await settle(page);

    const row = page.locator(`tr[data-approval-id="${waiting.id}"]`);
    await expect(row).toContainText('contractor@example.com');
    await expect(row).toContainText('Connect to shared/prod/web01');
    await expect(row).toContainText('patching');
    await expect(page.locator('#mine-body')).toContainText('go ahead');

    await row.locator('.approval-comment').fill('ok for today');
    await row.locator('.approval-approve').click();
    await expect.poll(() => api.calls.find(c => c.path === `/api/approvals/${waiting.id}/approve`)?.body?.comment)
        .toBe('ok for today');
    await expect(page.locator('#decide-empty')).toBeVisible();
});

test('the Approvals link is in everyone\'s nav', async ({ page }) => {
    await installApi(page, { role: 'viewer', routes: { 'GET /api/approvals': { to_decide: [], mine: [], recent: [] } } });
    await page.goto('/approvals.html');
    await settle(page);
    await expect(page.locator('nav a', { hasText: 'Approvals' })).toBeVisible();
    await expect(page.locator('#mine-empty')).toBeVisible();
});

test('a command request shows the command to be run', async ({ page }) => {
    const cmd = { ...waiting, id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', command: 'sudo systemctl restart nginx', policy_name: 'sudo needs approval' };
    await installApi(page, { routes: { 'GET /api/approvals': { to_decide: [cmd], mine: [], recent: [] } } });
    await page.goto('/approvals.html');
    await settle(page);
    await expect(page.locator(`tr[data-approval-id="${cmd.id}"]`))
        .toContainText('Run on shared/prod/web01: sudo systemctl restart nginx');
    await expect(page.locator(`tr[data-approval-id="${waiting.id}"]`)).toHaveCount(0);
});

test('Telegram linking: hidden when off, a code and deep link when on', async ({ page }) => {
    await installApi(page, { routes: { 'GET /api/approvals': { to_decide: [], mine: [], recent: [] } } });
    await page.goto('/approvals.html');
    await settle(page);
    await expect(page.locator('#telegram-section')).toBeHidden();

    const state = { linked: null };
    await installApi(page, {
        routes: {
            'GET /api/approvals': { to_decide: [], mine: [], recent: [] },
            'GET /api/telegram': () => ({ enabled: true, bot_username: 'bastion_bot', linked: state.linked }),
            'POST /api/telegram/link': { code: 'ABCD2345XY', expires_at: now + 600, url: 'https://t.me/bastion_bot?start=ABCD2345XY' },
            'DELETE /api/telegram/link': () => { state.linked = null; return { status: 204, contentType: 'application/json', body: '' }; }
        }
    });
    await page.goto('/approvals.html');
    await settle(page);
    await expect(page.locator('#tg-state')).toContainText('Not linked');
    await page.locator('#tg-link-btn').click();
    await expect(page.locator('#tg-code-cmd')).toHaveText('/link ABCD2345XY');
    await expect(page.locator('#tg-code-link')).toHaveAttribute('href', 'https://t.me/bastion_bot?start=ABCD2345XY');

    state.linked = { telegram_username: '@boss', linked_at: now };
    await page.reload();
    await settle(page);
    await expect(page.locator('#tg-state')).toContainText('Linked to @boss');
    await page.locator('#tg-unlink-btn').click();
    await expect(page.locator('#tg-state')).toContainText('Not linked');
});

test('a web-only request is marked and explains a refused decision', async ({ page }) => {
    const webOnly = { ...waiting, id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', policy_name: 'prod db', web_only: true };
    await installApi(page, {
        routes: {
            'GET /api/approvals': { to_decide: [webOnly], mine: [], recent: [] },
            [`POST /api/approvals/${webOnly.id}/approve`]: {
                status: 403, contentType: 'application/json',
                body: JSON.stringify({ error: 'this request needs a fresh sign-in: sign out, sign in again and decide within 15 minutes', fresh_signin_required: true })
            }
        }
    });
    await page.goto('/approvals.html');
    await settle(page);
    const row = page.locator(`tr[data-approval-id="${webOnly.id}"]`);
    await expect(row).toContainText('prod db (web only, fresh sign-in)');
    await row.locator('.approval-approve').click();
    await expect(page.locator('#error')).toContainText('fresh sign-in');
    await expect(row.locator('.approval-approve')).toBeEnabled();
});
