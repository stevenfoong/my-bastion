// Every page carries the same navigation, gated by role through the
// data-role-level attribute on <html> and data-min-role on the links: a
// viewer never sees Sessions, Reports, Tokens or Admin, an admin sees all
// of them, and the link order is identical from page to page.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const PAGES = ['/connections.html', '/sessions.html', '/recordings.html', '/reports.html'];
const ALL = ['Connections', 'Sessions', 'Recordings', 'Reports', 'Docs', 'Approvals', 'Tokens', 'Admin'];

async function visibleNav(page) {
    return page.locator('nav a:visible').evaluateAll(as => as.map(a => a.textContent.trim()).filter(t => /^[A-Z][a-z]+$/.test(t)));
}

for (const path of PAGES) {
    test(`admin sees the full nav on ${path}`, async ({ page }) => {
        await installApi(page, { role: 'admin' });
        await page.goto(path);
        await settle(page);
        await expect(page.locator('html')).toHaveAttribute('data-role-level', '4');
        const links = await visibleNav(page);
        for (const l of ALL) expect(links, `${l} must be in the nav`).toContain(l);
        // Same order on every page.
        expect(links.filter(l => ALL.includes(l))).toEqual(ALL);
    });
}

test('a viewer sees no gated links', async ({ page }) => {
    await installApi(page, { role: 'viewer' });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-role-level', '1');
    const links = await visibleNav(page);
    for (const gated of ['Sessions', 'Reports', 'Tokens', 'Admin']) expect(links).not.toContain(gated);
    expect(links).toContain('Connections');
    expect(links).toContain('Recordings');
});

test('an operator sees Tokens but not Sessions, Reports or Admin', async ({ page }) => {
    await installApi(page, { role: 'operator' });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-role-level', '2');
    const links = await visibleNav(page);
    expect(links).toContain('Tokens');
    for (const gated of ['Sessions', 'Reports', 'Admin']) expect(links).not.toContain(gated);
});
