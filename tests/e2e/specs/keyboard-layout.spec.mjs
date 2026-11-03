// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
// #318: "My keyboard layout" in Settings is remembered per browser and sent
// with each connect, so the server can use it for an RDP or desktop entry
// that leaves its layout at the server default. Not set sends nothing.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

async function connectDc01(page) {
    const acme = page.locator('.folder-row').filter({ hasText: /acme/ }).first();
    await acme.click();
    const dc01 = page.locator('.entries-table tbody tr').filter({ hasText: 'dc01' });
    await expect(dc01).toHaveCount(1);
    await dc01.locator('button', { hasText: /^Connect/ }).first().click();
}

test('the keyboard layout chosen in Settings goes with each connect', async ({ page, context }) => {
    const api = await installApi(page);
    await page.goto('/connections.html');
    await settle(page);

    // Not set: nothing is sent.
    await connectDc01(page);
    await expect.poll(() => api.calls.filter(c => c.method === 'POST' && c.path.endsWith('/entries/dc01/connect')).length).toBe(1);
    let connect = api.calls.filter(c => c.path.endsWith('/entries/dc01/connect'))[0];
    expect(connect.body.keyboard_layout).toBeUndefined();
    for (const p of context.pages()) if (p !== page) await p.close();

    // Choose German (Swiss) in the Settings menu; the menu stays open while choosing.
    await page.locator('#user-menu-btn').click();
    const sel = page.locator('#um-kb-layout');
    await expect(sel).toBeVisible();
    expect(await sel.locator('option').count(), 'every guacd layout plus Not set').toBe(24);
    await sel.selectOption('de-ch-qwertz');
    await expect(page.locator('#user-menu')).toBeVisible();
    expect(await page.evaluate(() => localStorage.getItem('mybastion_keyboard_layout'))).toBe('de-ch-qwertz');

    // Remembered across a reload.
    await page.reload();
    await settle(page);
    await expect(page.locator('#um-kb-layout')).toHaveValue('de-ch-qwertz');

    await connectDc01(page);
    await expect.poll(() => api.calls.filter(c => c.path.endsWith('/entries/dc01/connect')).length).toBe(2);
    connect = api.calls.filter(c => c.path.endsWith('/entries/dc01/connect'))[1];
    expect(connect.body.keyboard_layout).toBe('de-ch-qwertz');
});
