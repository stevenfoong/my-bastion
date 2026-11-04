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

test('admins see AI sessions and can end them all', async ({ page }) => {
    let open = [
        { session_id: '55555555-5555-4555-8555-555555555555', agent: 'ai:nightly', connection: 'shared/lab/desk',
          type: 'vnc', ended: null, idle_secs: 120 }
    ];
    const api = await installApi(page, {
        routes: {
            'GET /api/admin/ai-agents': agents,
            'GET /api/admin/ai-sessions': () => open,
            'POST /api/admin/ai-sessions/kill': () => { open = []; return { sessions_ended: 1, agents_disabled: 2 }; }
        }
    });
    page.on('dialog', d => d.accept());
    await page.goto('/admin.html');
    await settle(page);
    await expect(page.locator('#ai-sessions-body tr')).toHaveCount(1);
    await expect(page.locator('#ai-sessions-body')).toContainText('shared/lab/desk');
    await page.locator('#ai-kill-disable').check();
    await page.locator('#ai-kill-btn').click();
    await expect(page.locator('#ai-kill-result')).toContainText('1 session(s) ended, 2 key(s) disabled');
    const kill = api.calls.find(c => c.path === '/api/admin/ai-sessions/kill');
    expect(kill.body).toEqual({ disable_agents: true });
    await expect(page.locator('#no-ai-sessions')).toBeVisible();
});

test('AI sessions carry an AI badge on the Sessions page', async ({ page }) => {
    await installApi(page, {
        sessions: [
            { session_id: '66666666-6666-4666-8666-666666666666', session_type: 'rdp', status: 'Active',
              created_at: '2026-11-04T01:00:00Z', client_url: '/client.html?session=6666', ws_url: '/ws/6666',
              hostname: 'win01.lab', username: 'bot', active_connections: 1, created_by: 'ai:nightly' },
            { session_id: '77777777-7777-4777-8777-777777777777', session_type: 'ssh', status: 'Active',
              created_at: '2026-11-04T01:00:00Z', client_url: '/client.html?session=7777', ws_url: '/ws/7777',
              hostname: 'web01', username: 'root', active_connections: 1, created_by: 'alice@example.com' }
        ]
    });
    await page.goto('/sessions.html');
    await settle(page);
    await expect(page.locator('.ai-badge')).toHaveCount(1);
    await expect(page.locator('tr', { has: page.locator('.ai-badge') })).toContainText('ai:nightly');
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
