// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
// Demo data for the screenshots, loaded through the mybastion API.
//
// Every name, host and address is reserved example data: users are
// @example.com, hosts are *.example.com, *.example.net or
// *.example.internal, and addresses come from the documentation ranges
// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. The SSH entries in
// Production and Staging, and the status page, point at the throwaway
// containers in compose.yaml; the rest are never connected.

import { BASE, api, log, signIn, sleep } from './lib.mjs';

// The password of the `deploy` account in targets/ssh. The display names
// repeat the entry names because Recordings and Reports show the entry's
// full path when it has none.
const DEMO_SSH = { username: 'deploy', password: 'demo-password', enable_drive: true };

// Added by the mybastion-init service in compose.yaml; keep the two in step.
export const ADMIN = {
  email: 'alex@example.com', name: 'Alex Rivera', role: 'admin', groups: ['platform-admins', 'sre'],
};

export const USERS = [
  { email: 'casey@example.com', name: 'Casey Morgan', role: 'viewer', groups: ['auditors'] },
  { email: 'taylor@example.com', name: 'Taylor Brooks', role: 'operator', groups: ['helpdesk'] },
  { email: 'morgan@example.com', name: 'Morgan Lee', role: 'poweruser', groups: ['platform-admins'] },
  { email: 'priya@example.com', name: 'Priya Natarajan', role: 'operator', groups: ['windows-admins', 'helpdesk'] },
  { email: 'jordan@example.com', name: 'Jordan Okafor', role: 'operator', groups: ['network-ops', 'sre'] },
  { email: 'sam@example.com', name: 'Sam Chen', role: 'poweruser', groups: ['sre', 'network-ops'] },
];

export const byEmail = (email) => [ADMIN, ...USERS].find((u) => u.email === email);

const RDP = { type: 'rdp', port: 3389, username: '$ad_username', password: '$ad_password', domain: '$ad_domain', ignore_cert: true };

export const FOLDERS = [
  {
    name: 'customer-example-corp',
    display_name: 'Customer: Example Corp',
    description: 'Managed hosts for Example Corp',
    allowed_groups: ['network-ops'],
    entries: [
      { name: 'ec-app-01', type: 'ssh', hostname: 'ec-app-01.example.net', port: 22, username: '$examplecorp_username', password: '$examplecorp_password', display_name: 'ec-app-01 (via jump host)', jump_hosts: [{ hostname: 'gw.example.net', port: 22, username: '$examplecorp_username', password: '$examplecorp_password' }] },
      { name: 'erp-portal', type: 'web', url: 'https://erp.example.net/', username: '$examplecorp_username', password: '$examplecorp_password', display_name: 'ERP portal' },
      { name: 'ec-ts-01', ...RDP, hostname: '198.51.100.20', username: '$examplecorp_username', password: '$examplecorp_password', domain: '$examplecorp_domain', display_name: 'Example Corp terminal server' },
      { name: 'ec-file-01', ...RDP, hostname: '198.51.100.21', username: '$examplecorp_username', password: '$examplecorp_password', domain: '$examplecorp_domain', display_name: 'Example Corp file server' },
    ],
  },
  {
    name: 'lab',
    display_name: 'Lab',
    description: 'Throwaway test machines',
    allowed_groups: ['platform-admins'],
    entries: [
      { name: 'dev-workstation', type: 'vdi', container_image: 'registry.example.com/vdi/dev-workstation:latest', display_name: 'Developer workstation (VDI)' },
      { name: 'lab-vnc', type: 'vnc', hostname: '192.0.2.60', port: 5901, password: 'lab-vnc-demo', display_name: 'Lab Linux (VNC)' },
      { name: 'qemu-test', type: 'spice', hostname: '192.0.2.61', port: 5900, password: 'spice-demo', display_name: 'QEMU test VM (SPICE)' },
      { name: 'app-03', type: 'ssh', hostname: 'app-03.example.internal', port: 22, username: '$corp_username', password: '$corp_password', display_name: 'app-03 (Proxmox guest)' },
      { name: 'ubuntu-120', type: 'proxmox', proxmox_url: 'https://pve.example.internal:8006', proxmox_vmid: 120, proxmox_token_id: 'mybastion@pve!console', proxmox_token_secret: '00000000-0000-4000-8000-000000000000', display_name: 'Ubuntu 120 (Proxmox VE)' },
      { name: 'xfce-desktop', type: 'vdi', container_image: 'registry.example.com/vdi/xfce-desktop:latest', container_cpu_limit: 2, container_memory_limit: 4096, container_env: { LANG: 'en_US.UTF-8', TZ: 'UTC' }, container_idle_timeout_mins: 120, display_name: 'Disposable XFCE desktop (VDI)' },
    ],
  },
  {
    name: 'network',
    display_name: 'Network gear',
    description: 'Switches, routers and firewalls',
    allowed_groups: ['network-ops'],
    entries: [
      { name: 'core-sw-01', type: 'ssh', hostname: '192.0.2.2', port: 22, username: '$corp_username', password: '$corp_password' },
      { name: 'core-sw-02', type: 'ssh', hostname: '192.0.2.3', port: 22, username: '$corp_username', password: '$corp_password' },
      { name: 'edge-rtr-01', type: 'ssh', hostname: '203.0.113.1', port: 22, username: '$corp_username', password: '$corp_password' },
      { name: 'edge-fw-01', type: 'web', url: 'https://edge-fw-01.example.internal/', username: '$corp_username', password: '$corp_password', display_name: 'edge-fw-01 (admin UI)' },
      { name: 'oob-console', type: 'ssh', hostname: '203.0.113.10', port: 2222, username: '$corp_username', password: '$corp_password', display_name: 'Out-of-band console' },
    ],
  },
  {
    name: 'production',
    display_name: 'Production',
    description: 'Customer-facing production services',
    allowed_groups: ['sre'],
    entries: [
      { name: 'app-01', type: 'ssh', hostname: 'app-01.example.internal', port: 22, ...DEMO_SSH, display_name: 'app-01' },
      { name: 'app-02', type: 'ssh', hostname: 'app-02.example.internal', port: 22, ...DEMO_SSH, display_name: 'app-02' },
      { name: 'bastion', type: 'ssh', hostname: 'bastion.example.com', port: 22, username: '$corp_username', password: '$corp_password', display_name: 'Bastion host' },
      {
        name: 'db-01', type: 'ssh', hostname: 'db-01.example.internal', port: 22, username: '$corp_username', password: '$corp_password', display_name: 'db-01 (Postgres)',
        jump_hosts: [
          { hostname: 'bastion.example.com', port: 22, username: '$corp_username', password: '$corp_password' },
          { hostname: 'jump-db.example.internal', port: 22, username: '$corp_username', password: '$corp_password' },
        ],
      },
      { name: 'status', type: 'web', url: 'http://status.example.internal/', display_name: 'Service status page' },
    ],
  },
  {
    name: 'staging',
    display_name: 'Staging',
    description: 'Pre-production copies of the production services',
    allowed_groups: ['sre'],
    entries: [
      {
        name: 'admin-portal', type: 'web', url: 'https://admin.staging.example.com/', username: '$corp_username', password: '$corp_password', display_name: 'Staging admin portal',
        autofill: JSON.stringify([{ url: 'https://sso.example.com', username: '$USERNAME', password: '$PASSWORD' }]),
        allowed_domains: ['admin.staging.example.com', 'sso.example.com'],
      },
      { name: 'stg-app-01', type: 'ssh', hostname: 'stg-app-01.example.internal', port: 22, ...DEMO_SSH, display_name: 'stg-app-01' },
      { name: 'stg-db-01', type: 'ssh', hostname: 'stg-db-01.example.internal', port: 22, username: '$corp_username', password: '$corp_password' },
      { name: 'win-agent', ...RDP, hostname: '192.0.2.80', display_name: 'Windows agent (build host)' },
    ],
  },
  {
    name: 'windows',
    display_name: 'Windows fleet',
    description: 'Domain controllers and application servers',
    allowed_groups: ['windows-admins'],
    entries: [
      { name: 'dc-01', ...RDP, hostname: '192.0.2.10', display_name: 'dc-01 (domain controller)' },
      { name: 'erp-client', ...RDP, hostname: '192.0.2.20', remote_app: '||ERPClient', display_name: 'ERP client (RemoteApp)' },
      { name: 'fs-01', ...RDP, hostname: '192.0.2.12' },
      { name: 'helpdesk-11', ...RDP, hostname: '192.0.2.31', display_name: 'Helpdesk 11 (Windows 11)' },
      { name: 'rds-01', ...RDP, hostname: '192.0.2.41', enable_drive: true, enable_gfx: true, enable_h264: true, display_name: 'rds-01 (H.264)' },
    ],
  },
];

// Per-user credential variables. The examplecorp_* ones are left unset so
// the Connections page shows its "credentials to set up" banner.
const CREDENTIALS = {
  ad_username: 'arivera', ad_password: 'demo-ad-password', ad_domain: 'EXAMPLE',
  corp_username: 'arivera', corp_password: 'demo-corp-password',
};

const DAY = 24 * 3600 * 1000;
const inDays = (n) => new Date(Date.now() + n * DAY).toISOString().replace(/\.\d+Z$/, 'Z');

// Personal API tokens; `use` ones are called once so they show a last use.
const TOKENS = [
  { name: 'terraform-ci', max_role: 'poweruser', expires_at: inDays(180), use: true },
  { name: 'ansible-inventory', max_role: 'operator', expires_at: inDays(90), use: true },
  { name: 'laptop-cli', use: true },
  { name: 'reporting-export', max_role: 'viewer', expires_at: inDays(60) },
];

// Folders, entries and users, as the admin.
export async function seedDirectory(admin) {
  for (const user of USERS) {
    await api(admin, 'POST', '/api/users', { email: user.email, role: user.role, name: user.name });
  }
  for (const folder of FOLDERS) {
    const { entries, ...config } = folder;
    await api(admin, 'POST', '/api/addressbook/folders', { scope: 'shared', ...config });
    for (const entry of entries) {
      await api(admin, 'POST', `/api/addressbook/folders/shared/${folder.name}/entries`, entry);
    }
  }
  log(`seeded ${FOLDERS.length} folders, ${FOLDERS.reduce((n, f) => n + f.entries.length, 0)} entries, ${USERS.length} users`);
}

export async function seedAdminExtras(admin) {
  await api(admin, 'PUT', '/api/me/credentials', { credentials: CREDENTIALS });
  for (const { use, ...token } of TOKENS) {
    const created = await api(admin, 'POST', '/api/me/tokens', token);
    if (use) await api(admin, 'GET', '/api/me', undefined, { Authorization: `Bearer ${created.token}` });
  }
  log(`seeded credentials and ${TOKENS.length} tokens`);
}

// Open an entry in its own page, as the Connect button does: create the
// session from the page (so it is sized to it), then load the client.
export async function openSession(context, folder, entry) {
  const page = await context.newPage();
  await page.goto(`${BASE}/connections.html`, { waitUntil: 'domcontentloaded' });
  const size = page.viewportSize();
  const created = await page.evaluate(async ({ folder, entry, size }) => {
    const res = await fetch(`/api/addressbook/folders/shared/${folder}/entries/${entry}/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ width: size.width, height: size.height }),
    });
    return { status: res.status, body: await res.text() };
  }, { folder, entry, size });
  if (created.status >= 300) throw new Error(`connect ${folder}/${entry}: ${created.status} ${created.body}`);
  const session = JSON.parse(created.body);
  await page.goto(`${BASE}${session.client_url}`);
  await page.waitForSelector('#status.connected', { state: 'attached', timeout: 60000 });
  await sleep(2500);
  return { page, id: session.session_id };
}

export async function typeLine(page, text) {
  await page.keyboard.type(text, { delay: 40 });
  await page.keyboard.press('Enter');
}

// End a session the way a user would: `exit` for a shell, close otherwise.
export async function endSession(context, session, { shell = true } = {}) {
  if (shell) {
    await typeLine(session.page, 'exit');
    await sleep(2000);
  } else {
    await api(context, 'DELETE', `/api/sessions/${session.id}`);
  }
  await session.page.close();
}

// Short sessions that finish, so Recordings and Reports have history.
export async function runFinishedSessions(users) {
  const plan = [
    { who: 'sam@example.com', folder: 'staging', entry: 'stg-app-01', lines: ['uptime', 'df -h /', 'ls /usr/local/bin'] },
    { who: 'sam@example.com', folder: 'production', entry: 'app-02', lines: ['ps aux | grep [a]pi-server', 'free -m'] },
    { who: 'jordan@example.com', folder: 'production', entry: 'app-01', lines: ['tail -n 5 /etc/os-release', 'uptime'] },
    { who: 'alex@example.com', folder: 'production', entry: 'app-01', htop: 150 },
    { who: 'sam@example.com', folder: 'production', entry: 'status', web: 8 },
    { who: 'alex@example.com', folder: 'staging', entry: 'stg-app-01', lines: ['who', 'ps -u app -o pid,args'] },
  ];
  for (const step of plan) {
    const { context } = users[step.who];
    const session = await openSession(context, step.folder, step.entry);
    if (step.web) {
      await sleep(step.web * 1000);
      await endSession(context, session, { shell: false });
    } else if (step.htop) {
      await typeLine(session.page, 'htop -d 10');
      await sleep(step.htop * 1000);
      await session.page.keyboard.press('q');
      await sleep(500);
      await endSession(context, session);
    } else {
      for (const line of step.lines) {
        await typeLine(session.page, line);
        await sleep(6000);
      }
      await endSession(context, session);
    }
    log(`finished session: ${step.who} ${step.folder}/${step.entry}`);
  }
}

// Sessions left open while the Sessions page and the live views are shot.
// The two shown full screen open first, so htop lists only its own login.
export async function openShownSessions(users) {
  const sam = users['sam@example.com'].context;
  const ssh = await openSession(sam, 'production', 'app-01');
  await typeLine(ssh.page, 'htop -d 10');
  const web = await openSession(sam, 'production', 'status');
  await sleep(3000);
  // Park the pointer away from the content; the client shows it remotely.
  for (const { page } of [ssh, web]) await page.mouse.move(1500, 960);
  await sleep(1500);
  return { ssh, web };
}

export async function openMoreSessions(users) {
  const jordan = await openSession(users['jordan@example.com'].context, 'production', 'app-02');
  await typeLine(jordan.page, 'uptime');
  const stg = await openSession(users['sam@example.com'].context, 'staging', 'stg-app-01');
  await typeLine(stg.page, 'uptime');
  await sleep(2000);
  log('opened 4 live sessions');
}
