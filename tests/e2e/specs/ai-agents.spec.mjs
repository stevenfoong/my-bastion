// Phase 3a: admins manage AI agent keys on the Admin page, and a folder's
// AI mode is set (and kept) in the folder dialog.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const agents = [
    { id: 1, name: 'nightly', folders: [], allowed_ips: null, expires_at: null, disabled: false,
      created_by: 'admin', created_at: '2026-11-01 10:00:00', last_used_at: '2026-11-04 09:00:00' },
    { id: 2, name: 'lab-bot', folders: ['shared/lab'], allowed_ips: '10.0.0.0/8', expires_at: '2027-01-01',
      created_by: 'admin', created_at: '2026-11-01 10:00:00', last_used_at: null, disabled: true }
];

test('agents are listed, created with their key shown once, and disabled', async ({ page }) => {
    const api = await installApi(page, {
        routes: {
            'GET /api/admin/ai-agents': agents,
            'POST /api/admin/ai-agents': { status: 201, contentType: 'application/json',
                body: JSON.stringify({ key: 'mbai_0123456789', agent: { name: 'patcher' } }) },
            'POST /api/admin/ai-agents/nightly/disable': { ok: true }
        }
    });
    await page.goto('/admin.html');
    await settle(page);

    const rows = page.locator('#agents-body tr');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0)).toContainText('ai:nightly');
    await expect(rows.nth(0)).toContainText('all AI folders');
    await expect(rows.nth(1)).toContainText('shared/lab');
    await expect(rows.nth(1)).toContainText('disabled');

    await page.locator('#agent-name').fill('patcher');
    await page.locator('#agent-folders').fill('shared/lab, shared/dev');
    await page.locator('#agent-add-btn').click();
    await expect(page.locator('#agent-key-value')).toHaveText('mbai_0123456789');
    const created = api.calls.find(c => c.method === 'POST' && c.path === '/api/admin/ai-agents');
    expect(created.body).toEqual({ name: 'patcher', folders: ['shared/lab', 'shared/dev'] });

    await rows.nth(0).locator('.agent-toggle').click();
    await expect.poll(() => api.calls.some(c => c.path === '/api/admin/ai-agents/nightly/disable')).toBe(true);
});

test('a folder\'s AI mode is loaded, saved, and left alone until loaded', async ({ page }) => {
    const api = await installApi(page, {
        routes: {
            'GET /api/addressbook/folders/shared/acme/config': {
                allowed_groups: ['ops'], allowed_users: [], description: 'Acme', display_name: '', ai_mode: 'approve'
            }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /Pizzeria/ }).first().click();
    await page.locator('#btn-edit-folder').click();
    await expect(page.locator('#fm-ai-mode')).toHaveValue('approve');
    await page.locator('#fm-ai-mode').selectOption('auto');
    await page.locator('#fm-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && c.path === '/api/addressbook/folders/shared/acme')?.body?.ai_mode)
        .toBe('auto');
});
