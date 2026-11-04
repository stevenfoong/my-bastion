// Phase 3d: admins approve AI clients and see people's AI grants; people
// see and revoke their own on the My Tokens page.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const now = Math.floor(Date.now() / 1000);
const grant = { id: 'g-1', email: 'tester@example.com', client_id: 'mbc_1', client_name: 'Claude',
    scopes: 'mcp:read mcp:act', idp_linked: true, created_at: now - 3600, last_used_at: now - 60,
    revoked_at: null, revoked_why: null };

test('admins approve a waiting AI client and revoke a grant', async ({ page }) => {
    let clients = [{ name: 'Claude', status: 'pending', first_seen: now - 100, decided_by: null, clients: 1, grants: 0 }];
    let grants = [grant];
    const api = await installApi(page, {
        routes: {
            'GET /api/admin/oauth-clients': () => clients,
            'POST /api/admin/oauth-clients/Claude/approve': () => {
                clients = [{ ...clients[0], status: 'approved' }];
                return { ok: true };
            },
            'GET /api/admin/ai-grants': () => grants,
            'DELETE /api/admin/ai-grants/g-1': () => {
                grants = [{ ...grant, revoked_at: now, revoked_why: 'revoked by a person' }];
                return { ok: true };
            }
        }
    });
    await page.goto('/admin.html');
    await settle(page);
    const row = page.locator('tr[data-client="Claude"]');
    await expect(row).toContainText('pending');
    await row.locator('.oauth-approve').click();
    await expect(row).toContainText('approved');
    await expect(row.locator('.oauth-approve')).toHaveCount(0);

    await expect(page.locator('#ai-grants-body')).toContainText('tester@example.com');
    await page.locator('#ai-grants-body .ai-grant-revoke').click();
    await expect(page.locator('#ai-grants-body')).toContainText('revoked (revoked by a person)');
    expect(api.calls.some(c => c.method === 'DELETE' && c.path === '/api/admin/ai-grants/g-1')).toBe(true);
});

test('a person sees and revokes their AI access', async ({ page }) => {
    let mine = [grant];
    const api = await installApi(page, {
        role: 'viewer',
        routes: {
            'GET /api/me/ai-grants': () => mine,
            'DELETE /api/me/ai-grants/g-1': () => { mine = []; return { ok: true }; }
        }
    });
    await page.goto('/tokens.html');
    await settle(page);
    // Even a viewer, who has no tokens of their own, sees this.
    await expect(page.locator('#ai-access-section')).toBeVisible();
    const row = page.locator('tr[data-grant="g-1"]');
    await expect(row).toContainText('Claude');
    await expect(row).toContainText('mcp:read mcp:act');
    await row.locator('.ai-grant-revoke').click();
    await expect(page.locator('#no-ai-grants')).toBeVisible();
    expect(api.calls.some(c => c.method === 'DELETE' && c.path === '/api/me/ai-grants/g-1')).toBe(true);
});
