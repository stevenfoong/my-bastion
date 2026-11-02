// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
// Seed a fresh mybastion with demo data, then capture the screenshots/ set.
//
// Output (under /out):
//   <name>.png          aurora theme (the default)
//   light/<name>.png    the page views again in the light theme
// THEMES picks the themes; the first one is written to /out itself.

import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';
import { BASE, api, log, openPage, signIn, sleep, waitForMy Bastion } from './lib.mjs';
import {
  ADMIN, USERS, openMoreSessions, openShownSessions, runFinishedSessions, seedAdminExtras, seedDirectory,
} from './seed.mjs';

const OUT = process.env.OUT_DIR || '/out';
const THEMES = (process.env.THEMES || 'aurora,light').split(',').map((t) => t.trim()).filter(Boolean);

const EDITOR = { width: 1600, height: 2000, scale: 0.9 }; // 1440x1800 pixels
const REPORTS = { width: 1800, height: 1125, scale: 0.8 }; // 1440x900, more columns

async function shoot(page, dir, name) {
  await fs.mkdir(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`) });
  log(`wrote ${path.join(dir, `${name}.png`)}`);
}

async function selectFolder(page, displayName) {
  await page.locator('#folder-list .folder-name', { hasText: displayName }).first().click();
  await page.waitForSelector('#entries-content table');
  await sleep(800);
}

async function editEntry(page, folder, entry) {
  await selectFolder(page, folder);
  await page.locator(`button[data-edit-entry="${entry}"]`).click();
  await page.waitForSelector('#entry-modal', { state: 'visible' });
  await sleep(800);
}

// Finished sessions leave the Sessions page once mybastion's cleanup runs.
async function waitForLiveOnly(context) {
  for (let i = 0; i < 90; i++) {
    const sessions = await api(context, 'GET', '/api/sessions');
    if (sessions.every((s) => s.status === 'active')) return;
    await sleep(1000);
  }
  throw new Error('finished sessions are still listed after 90 seconds');
}

// The page views, shot once per theme.
async function pageViews(browser, theme, dir, recordingName) {
  const { context } = await signIn(browser, ADMIN, { theme });

  let page = await openPage(context, '/connections.html');
  await selectFolder(page, 'Production');
  await shoot(page, dir, 'connections');

  await selectFolder(page, 'Customer: Example Corp');
  await page.locator('#my-creds-nav').click();
  await page.waitForSelector('#my-creds-modal', { state: 'visible' });
  await sleep(800);
  await shoot(page, dir, 'my_credentials');
  await page.close();

  await context.close();
  const editor = (await signIn(browser, ADMIN, { theme, size: EDITOR })).context;

  page = await openPage(editor, '/connections.html');
  await editEntry(page, 'Windows fleet', 'rds-01');
  if (!(await page.locator('#em-video-perf-fields').isVisible())) await page.locator('#em-video-perf-toggle').click();
  await shoot(page, dir, 'rdp_connection');
  await page.close();

  page = await openPage(editor, '/connections.html');
  await editEntry(page, 'Staging', 'admin-portal');
  await shoot(page, dir, 'web_connection');
  await page.close();

  page = await openPage(editor, '/connections.html');
  await editEntry(page, 'Lab', 'xfce-desktop');
  await shoot(page, dir, 'vdi_connection');
  await page.close();

  page = await openPage(editor, '/connections.html');
  await editEntry(page, 'Production', 'db-01');
  if (!(await page.locator('#em-tunnel-fields').isVisible())) await page.locator('#em-tunnel-toggle').click();
  await page.locator('#em-hops-list button', { hasText: 'expand' }).first().click();
  await page.locator('#entry-modal .modal').evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await sleep(500);
  await shoot(page, dir, 'ssh-tunnel');
  await page.close();
  await editor.close();

  const admin = (await signIn(browser, ADMIN, { theme })).context;
  await waitForLiveOnly(admin);
  page = await openPage(admin, '/sessions.html');
  await shoot(page, dir, 'sessions_view_with_adhoc');
  await page.close();

  page = await openPage(admin, '/recordings.html');
  await shoot(page, dir, 'recordings_view');
  await page.locator(`button[data-play="${recordingName}"]`).click();
  // The time reads "0:00 / 0:00" until the recording's length is known.
  await page.waitForFunction(() => !/\/ 0:00$/.test(document.getElementById('player-time').textContent));
  await sleep(4000); // let the whole recording load so the histogram is complete
  await page.locator('#seek-slider').evaluate((el) => {
    el.value = 520;
    el.dispatchEvent(new Event('input'));
  });
  await sleep(1500);
  await page.mouse.move(0, 0);
  await shoot(page, dir, 'recordings_player_histogram');
  await page.close();

  page = await openPage(admin, '/admin.html');
  await shoot(page, dir, 'admin_console');
  await page.close();

  page = await openPage(admin, '/tokens.html');
  await shoot(page, dir, 'tokens_view');
  await page.close();
  await admin.close();

  const wide = (await signIn(browser, ADMIN, { theme, size: REPORTS })).context;
  page = await openPage(wide, '/reports.html');
  await shoot(page, dir, 'reports_view');
  await wide.close();
}

// The Connections page in four themes, two by two, at the size of one shot.
async function themesComposite(browser, dir) {
  const tiles = [];
  for (const theme of ['aurora', 'light', 'nord', 'jaguar']) {
    const { context } = await signIn(browser, ADMIN, { theme });
    const page = await openPage(context, '/connections.html');
    await selectFolder(page, 'Production');
    tiles.push((await page.screenshot()).toString('base64'));
    await context.close();
  }
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await page.setContent(`<!doctype html><style>
    body { margin: 0; background: #0b1220; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px; height: 900px; box-sizing: border-box; }
    img { width: 100%; height: 100%; object-fit: cover; object-position: top left; border-radius: 6px; display: block; }
  </style><div class="grid">${tiles.map((b) => `<img src="data:image/png;base64,${b}">`).join('')}</div>`);
  await sleep(500);
  await shoot(page, dir, 'themes');
  await context.close();
}

async function main() {
  const browser = await chromium.launch();
  const probe = await browser.newContext({ ignoreHTTPSErrors: true });
  await waitForMy Bastion(probe.request);
  await probe.close();
  log(`mybastion is up at ${BASE}`);

  const users = {};
  users[ADMIN.email] = await signIn(browser, ADMIN);
  const admin = users[ADMIN.email].context;
  // mybastion logs in to OpenBao in the background after it starts.
  let existing;
  for (let i = 0; !existing; i++) {
    try {
      existing = await api(admin, 'GET', '/api/addressbook/folders');
    } catch (err) {
      if (i >= 60) throw err;
      await sleep(1000);
    }
  }
  if (existing.length) {
    throw new Error('mybastion already has data; start from a clean stack (docker compose down -v)');
  }
  await seedDirectory(admin);
  await seedAdminExtras(admin);
  for (const user of USERS) users[user.email] = await signIn(browser, user);

  await runFinishedSessions(users);
  const list = await api(admin, 'GET', '/api/recordings');
  const htop = list
    .filter((r) => r.address_book_entry === 'shared/production/app-01' && r.user === ADMIN.email)
    .sort((a, b) => b.size_bytes - a.size_bytes)[0];
  if (!htop) throw new Error(`no recording of the htop session among ${list.length} recordings`);

  const live = await openShownSessions(users);
  await shoot(live.ssh.page, OUT, 'ssh_session');
  await shoot(live.web.page, OUT, 'web_session');
  await openMoreSessions(users);

  for (const [i, theme] of THEMES.entries()) {
    await pageViews(browser, theme, i === 0 ? OUT : path.join(OUT, theme), htop.name);
  }
  await themesComposite(browser, OUT);

  await browser.close();
  log('done');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
