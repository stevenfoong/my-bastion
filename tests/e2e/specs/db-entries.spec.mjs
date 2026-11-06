// Phase 4b: database entries on the Connections page: admins create them,
// and everyone gets a DB token (with the psql command) instead of Connect.
import { test, expect } from '@playwright/test';
import { installApi, settle, folder, entry } from '../lib/api.mjs';

function dbFolders() {
    return [folder('data', {
        entries: [
            entry('pg', 'postgres', { hostname: 'db.internal', port: 5432, username: 'app', fields: { database: 'app' } }),
            entry('web01', 'ssh')
        ]
    })];
}

test('a database entry gets a DB token button that shows the psql command', async ({ page }) => {
    const api = await installApi(page, {
        folders: dbFolders(),
        routes: {
            'POST /api/addressbook/folders/shared/data/entries/pg/db-token': {
                token: 'mbdb_abc123', expires_at: Math.floor(Date.now() / 1000) + 900,
                host: 'bastion.example.com', port: '5433', user: 'tester@example.com', database: 'app',
                psql: 'PGPASSWORD=<token> psql "..."'
            }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /data/ }).first().click();
    const row = page.locator('tr', { has: page.locator('[data-dbtoken="pg"]') });
    await expect(row.locator('[data-connect]')).toHaveCount(0);
    await expect(page.locator('[data-connect="web01"]')).toHaveCount(1);
    await row.locator('[data-dbtoken="pg"]').click();
    await expect(page.locator('#dbtoken-value')).toHaveText('mbdb_abc123');
    await expect(page.locator('#dbtoken-psql')).toContainText(
        `PGPASSWORD='mbdb_abc123' psql "host=bastion.example.com port=5433 dbname=app user=tester@example.com sslmode=require"`);
    expect(api.calls.some(c => c.method === 'POST' && c.path.endsWith('/entries/pg/db-token'))).toBe(true);
});

test('a refused DB token shows the reason', async ({ page }) => {
    await installApi(page, {
        folders: dbFolders(),
        routes: {
            'POST /api/addressbook/folders/shared/data/entries/pg/db-token': {
                status: 403, contentType: 'application/json',
                body: JSON.stringify({ error: "denied by policy 'no db for contractors'", policy: 'no db for contractors' })
            }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /data/ }).first().click();
    await page.locator('[data-dbtoken="pg"]').click();
    await expect(page.locator('body')).toContainText("denied by policy 'no db for contractors'");
    await expect(page.locator('#dbtoken-value')).toHaveCount(0);
});

test('admins create a PostgreSQL entry with its database', async ({ page }) => {
    const api = await installApi(page, { folders: dbFolders() });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /data/ }).first().click();
    await page.locator('#btn-new-entry').click();
    await page.locator('#em-name').fill('reports');
    await page.locator('#em-type').selectOption('postgres');
    await expect(page.locator('#em-pg-fields')).toBeVisible();
    await expect(page.locator('#em-ssh-fields')).toBeHidden();
    await expect(page.locator('#em-recording-section')).toBeHidden();
    await page.locator('#em-pg-hostname').fill('10.0.5.20');
    await page.locator('#em-pg-database').fill('reports');
    await page.locator('#em-pg-username').fill('ro');
    await page.locator('#em-pg-password').fill('pw');
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'POST' && c.path === '/api/addressbook/folders/shared/data/entries')?.body)
        .toMatchObject({ name: 'reports', type: 'postgres', hostname: '10.0.5.20', port: 5432, database: 'reports', username: 'ro', password: 'pw' });
});

// Phase 4c: MySQL/MariaDB entries.
test('a MySQL entry shows the mysql command', async ({ page }) => {
    await installApi(page, {
        folders: [folder('data', { entries: [entry('my', 'mysql', { hostname: 'db.internal', port: 3306, username: 'app' })] })],
        routes: {
            'POST /api/addressbook/folders/shared/data/entries/my/db-token': {
                token: 'mbdb_xyz', expires_at: Math.floor(Date.now() / 1000) + 900, protocol: 'mysql',
                host: 'bastion.example.com', port: '3307', user: 'tester@example.com', database: ''
            }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /data/ }).first().click();
    await page.locator('[data-dbtoken="my"]').click();
    await expect(page.locator('#dbtoken-value')).toHaveText('mbdb_xyz');
    await expect(page.locator('#dbtoken-psql')).toHaveText(
        `MYSQL_PWD='mbdb_xyz' mysql -h bastion.example.com -P 3307 -u 'tester@example.com' --ssl`);
    await expect(page.locator('#dbtoken-target')).toContainText('(server default)');
});

test('admins create a MySQL entry; the port follows the type', async ({ page }) => {
    const api = await installApi(page, { folders: dbFolders() });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /data/ }).first().click();
    await page.locator('#btn-new-entry').click();
    await page.locator('#em-name').fill('shop');
    await page.locator('#em-type').selectOption('mysql');
    await expect(page.locator('#em-pg-fields')).toBeVisible();
    await expect(page.locator('#em-pg-port')).toHaveValue('3306');
    await page.locator('#em-pg-hostname').fill('10.0.5.30');
    await page.locator('#em-pg-database').fill('shop');
    await page.locator('#em-pg-username').fill('ro');
    await page.locator('#em-pg-password').fill('pw');
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'POST' && c.path === '/api/addressbook/folders/shared/data/entries')?.body)
        .toMatchObject({ name: 'shop', type: 'mysql', hostname: '10.0.5.30', port: 3306, database: 'shop', username: 'ro', password: 'pw' });
});
