// Phase 2a: the Approvals page lists the requests the user may decide and
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
    await expect(row).toContainText('shared/prod/web01');
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
