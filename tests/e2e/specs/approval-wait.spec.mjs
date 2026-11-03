// Phase 2a: a connect a policy holds for approval (202) shows a waiting
// dialog, sends the requester's reason, and offers "Connect now" once
// approved: a click, because a window opened outside one is popup-blocked.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CONNECT = 'POST /api/addressbook/folders/shared/acme/entries/dc01/connect';

function request(extra = {}) {
    return {
        id: ID, policy_name: 'contractors to prod', target_label: 'shared/acme/dc01',
        status: 'pending', reason: '', expires_at: Math.floor(Date.now() / 1000) + 1800,
        resource: { kind: 'entry', scope: 'shared', folder: 'acme', entry: 'dc01' },
        ...extra
    };
}

async function connectDc01(page) {
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    const row = page.locator('.entries-table tbody tr').filter({ hasText: 'dc01' });
    await expect(row).toHaveCount(1);
    await row.locator('button', { hasText: /^Connect/ }).first().click();
}

test('a held connect waits for approval, then connects on click', async ({ page }) => {
    const state = { decided: false };
    const api = await installApi(page, {
        routes: {
            [CONNECT]: () => state.decided
                ? { status: 201, contentType: 'application/json', body: JSON.stringify({
                    session_id: '55555555-5555-4555-8555-555555555555',
                    client_url: '/client.html?session=5555', ws_url: '/ws/5555', session_type: 'rdp' }) }
                : { status: 202, contentType: 'application/json', body: JSON.stringify({
                    approval_required: true, approval: request() }) },
            [`GET /api/approvals/${ID}`]: () => state.decided
                ? request({ status: 'approved', decided_by: 'boss@example.com', comment: 'ok for today' })
                : request(),
            [`POST /api/approvals/${ID}/reason`]: { status: 204, contentType: 'text/plain', body: '' }
        }
    });

    await connectDc01(page);
    const modal = page.locator('#approval-modal');
    await expect(modal).toBeVisible();
    await expect(modal).toContainText('contractors to prod');
    await expect(modal).toContainText('shared/acme/dc01');
    await expect(page.locator('#approval-status')).toContainText('Waiting for an approver');
    await expect(page.locator('#approval-connect')).toBeHidden();

    await page.locator('#approval-reason').fill('patching dc01');
    await modal.locator('button', { hasText: 'Send reason' }).click();
    await expect.poll(() => api.calls.find(c => c.path === `/api/approvals/${ID}/reason`)?.body?.reason)
        .toBe('patching dc01');

    // An approver decides; the dialog's poll picks it up.
    state.decided = true;
    await expect(page.locator('#approval-status')).toContainText('Approved by boss@example.com', { timeout: 10000 });
    await expect(page.locator('#approval-status')).toContainText('ok for today');
    const go = page.locator('#approval-connect');
    await expect(go).toBeVisible();

    const popup = page.waitForEvent('popup');
    await go.click();
    await popup;
    await expect(modal).toHaveCount(0);
    await expect.poll(() => api.calls.filter(c => `${c.method} ${c.path}` === CONNECT).length).toBe(2);
});

test('a denied request says so and offers no connect', async ({ page }) => {
    await installApi(page, {
        routes: {
            [CONNECT]: { status: 202, contentType: 'application/json', body: JSON.stringify({
                approval_required: true, approval: request() }) },
            [`GET /api/approvals/${ID}`]: request({ status: 'denied', decided_by: 'boss@example.com', comment: 'not today' })
        }
    });
    await connectDc01(page);
    await expect(page.locator('#approval-status')).toContainText('Denied by boss@example.com', { timeout: 10000 });
    await expect(page.locator('#approval-status')).toContainText('not today');
    await expect(page.locator('#approval-connect')).toBeHidden();
    await page.locator('#approval-cancel').click();
    await expect(page.locator('#approval-modal')).toHaveCount(0);
});

test('withdrawing a waiting request cancels it on the server', async ({ page }) => {
    const api = await installApi(page, {
        routes: {
            [CONNECT]: { status: 202, contentType: 'application/json', body: JSON.stringify({
                approval_required: true, approval: request() }) },
            [`GET /api/approvals/${ID}`]: request(),
            [`POST /api/approvals/${ID}/cancel`]: { status: 204, contentType: 'text/plain', body: '' }
        }
    });
    await connectDc01(page);
    await expect(page.locator('#approval-modal')).toBeVisible();
    await page.locator('#approval-cancel').click();
    await expect(page.locator('#approval-modal')).toHaveCount(0);
    await expect.poll(() => api.calls.some(c => c.path === `/api/approvals/${ID}/cancel`)).toBe(true);
});

// Phase 2d: break-glass. An admin may override a deny, or an approval
// nobody has given yet, with a reason; others are not offered it.
const SESSION = { status: 201, contentType: 'application/json', body: JSON.stringify({
    session_id: '55555555-5555-4555-8555-555555555555',
    client_url: '/client.html?session=5555', ws_url: '/ws/5555', session_type: 'rdp' }) };

test('an admin breaks the glass on a denied connect, then connects', async ({ page }) => {
    const state = { broken: false };
    const api = await installApi(page, {
        routes: {
            [CONNECT]: () => state.broken ? SESSION : { status: 403, contentType: 'application/json',
                body: JSON.stringify({ error: "denied by policy 'nobody in acme'", policy: 'nobody in acme' }) },
            'POST /api/break-glass': () => {
                state.broken = true;
                return { approval: request({ status: 'approved', break_glass: true, grant_until: Math.floor(Date.now() / 1000) + 3600 }), minutes: 60 };
            }
        }
    });
    await connectDc01(page);
    const modal = page.locator('#approval-modal');
    await expect(modal).toContainText('Break glass');
    await expect(modal).toContainText('nobody in acme');
    await page.locator('#break-glass-reason').fill('short');
    await page.locator('#break-glass-confirm').click();
    await expect(page.locator('#break-glass-status')).toContainText('at least 10');
    await page.locator('#break-glass-reason').fill('dc01 is down, approvers unreachable');
    await page.locator('#break-glass-confirm').click();
    await expect(page.locator('#break-glass-status')).toContainText('Override granted');
    const body = api.calls.find(c => c.path === '/api/break-glass').body;
    expect(body).toEqual({ scope: 'shared', folder: 'acme', entry: 'dc01', reason: 'dc01 is down, approvers unreachable' });
    const popup = page.waitForEvent('popup');
    await page.locator('#break-glass-connect').click();
    await popup;
    await expect.poll(() => api.calls.filter(c => `${c.method} ${c.path}` === CONNECT).length).toBe(2);
});

test('break-glass from the approval dialog, and the fresh sign-in message', async ({ page }) => {
    await installApi(page, {
        routes: {
            [CONNECT]: { status: 202, contentType: 'application/json', body: JSON.stringify({
                approval_required: true, approval: request() }) },
            [`GET /api/approvals/${ID}`]: request(),
            'POST /api/break-glass': { status: 403, contentType: 'application/json', body: JSON.stringify({
                error: 'break-glass needs a fresh sign-in: sign out, sign in again and retry within 15 minutes',
                fresh_signin_required: true }) }
        }
    });
    await connectDc01(page);
    await page.locator('#approval-break-glass').click();
    await page.locator('#break-glass-reason').fill('the approver is on a plane');
    await page.locator('#break-glass-confirm').click();
    await expect(page.locator('#break-glass-status')).toContainText('fresh sign-in');
    await expect(page.locator('#break-glass-connect')).toBeHidden();
});

test('operators are not offered break-glass', async ({ page }) => {
    await installApi(page, {
        role: 'operator',
        routes: {
            [CONNECT]: { status: 202, contentType: 'application/json', body: JSON.stringify({
                approval_required: true, approval: request() }) },
            [`GET /api/approvals/${ID}`]: request()
        }
    });
    await connectDc01(page);
    await expect(page.locator('#approval-modal')).toBeVisible();
    await expect(page.locator('#approval-break-glass')).toHaveCount(0);
});
