<script>
  import { onMount } from 'svelte';
  import { get, post } from '../lib/api.js';
  import { router, link } from '../lib/router.svelte.js';
  import { theme } from '../lib/theme.svelte.js';
  import { ui, restartServer } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { duration } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Logo from '../lib/Logo.svelte';
  import Avatar from '../lib/Avatar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Palette from '../lib/Palette.svelte';
  import Overview from './Overview.svelte';
  import Domains from './Domains.svelte';
  import Accounts from './Accounts.svelte';
  import Aliases from './Aliases.svelte';
  import Queue from './Queue.svelte';
  import Delivery from './Delivery.svelte';
  import Security from './Security.svelte';
  import Storage from './Storage.svelte';
  import Activity from './Activity.svelte';
  import Settings from './Settings.svelte';
  import Configuration from './Configuration.svelte';
  import ApiPage from './Api.svelte';
  import Access from './Access.svelte';
  import Branding from './Branding.svelte';
  import Filter from './Filter.svelte';
  import Tls from './Tls.svelte';
  import Reports from './Reports.svelte';
  import Relay from './Relay.svelte';
  import Dav from './Dav.svelte';
  import Audit from './Audit.svelte';
  import Maintenance from './Maintenance.svelte';
  import { brand } from '../lib/brand.svelte.js';

  // Navigation grouped by what a postmaster is doing.
  const GROUPS = [
    { title: '', items: [{ path: '/', label: 'Overview', icon: 'overview', keywords: 'dashboard status home' }] },
    {
      title: 'Mail',
      items: [
        { path: '/domains', label: 'Domains', icon: 'globe', keywords: 'dns dkim mx spf dmarc' },
        { path: '/accounts', label: 'Accounts', icon: 'users', keywords: 'users mailboxes quota password sieve vacation export import migrate' },
        { path: '/aliases', label: 'Aliases', icon: 'at', keywords: 'forwarding catch-all' },
        { path: '/dav', label: 'Calendars & contacts', icon: 'calendar', keywords: 'dav caldav carddav webdav files principals' },
      ],
    },
    {
      title: 'Delivery',
      items: [
        { path: '/queue', label: 'Queue', icon: 'queue', badge: 'queue', keywords: 'outgoing retry bounce' },
        { path: '/delivery', label: 'Routing & relays', icon: 'send', keywords: 'smtp relay smarthost webhook transport route retry' },
        { path: '/relay', label: 'Relay link', icon: 'link', keywords: 'upstream downstream peer picacho https relay token port 25' },
      ],
    },
    {
      title: 'Protection',
      items: [
        { path: '/filter', label: 'Spam filter', icon: 'filter', keywords: 'spam junk bayes rspamd clamav virus greylist rules score content' },
        { path: '/security', label: 'Security', icon: 'shield', keywords: 'bans spf dkim dmarc dnsbl password policy' },
        { path: '/tls', label: 'TLS & MTA-STS', icon: 'certificate', keywords: 'certificate acme lets encrypt renew mta-sts dane arc tls' },
        { path: '/reports', label: 'Reports', icon: 'chart', keywords: 'dmarc tls-rpt aggregate rua' },
      ],
    },
    {
      title: 'Server',
      items: [
        { path: '/access', label: 'Sign-in & access', icon: 'lock', keywords: 'sso oidc oauth single sign-on okta entra keycloak password apps consent' },
        { path: '/storage', label: 'Storage & limits', icon: 'database', keywords: 'disk s3 postgres sqlite quota size' },
        { path: '/maintenance', label: 'Retention', icon: 'wrench', keywords: 'retention cleanup trash junk sweep orphan maintenance backup' },
        { path: '/configuration', label: 'Configuration', icon: 'server', keywords: 'config.toml listeners ports tls certificate restart' },
        { path: '/api', label: 'API & tokens', icon: 'key', keywords: 'rest jmap token app password automation' },
        { path: '/branding', label: 'Branding', icon: 'edit', keywords: 'logo name color accent theme look' },
        { path: '/audit', label: 'Audit log', icon: 'history', keywords: 'audit who changed history admin actions' },
        { path: '/activity', label: 'Activity', icon: 'activity', keywords: 'log events' },
      ],
    },
  ];
  const PAGES_FLAT = [
    ...GROUPS.flatMap((g) => g.items.map((i) => ({ ...i, group: g.title || 'Page' }))),
    { path: '/settings', label: 'Settings', icon: 'settings', group: 'Page', keywords: 'appearance theme hostname greeting password' },
  ];
  const PAGES = {
    '': Overview, domains: Domains, accounts: Accounts, aliases: Aliases, queue: Queue, delivery: Delivery,
    security: Security, storage: Storage, activity: Activity, settings: Settings, configuration: Configuration, api: ApiPage, access: Access, branding: Branding,
    filter: Filter, tls: Tls, reports: Reports, relay: Relay, dav: Dav, audit: Audit, maintenance: Maintenance,
  };

  const section = $derived(router.parts[0] ?? '');
  const Page = $derived(PAGES[section] ?? Overview);
  let narrow = $state(false);
  let collapsed = $derived(ui.sidebarCollapsed || narrow);
  let about = $state(false);
  let menu = $state(false);
  let overview = $state(null);
  const mac = navigator.platform.toLowerCase().includes('mac');

  onMount(() => {
    const mq = matchMedia('(max-width: 900px)');
    narrow = mq.matches;
    mq.addEventListener('change', (e) => (narrow = e.matches));
    refreshBadges();
    const t = setInterval(refreshBadges, 30000);
    return () => clearInterval(t);
  });

  async function refreshBadges() {
    overview = await get('/admin/overview').catch(() => overview);
    if (overview) ui.restartRequired = overview.restart_required;
  }

  const queueCount = $derived(overview ? overview.queue.queued + overview.queue.deferred + overview.queue.failed : 0);

  function create() {
    const kind = section === 'domains' ? 'domain' : section === 'aliases' ? 'alias' : section === 'dav' ? 'dav' : 'account';
    const target = { domain: '/domains', alias: '/aliases', account: '/accounts', dav: '/dav' }[kind];
    if (!router.path.startsWith(target)) router.go(target);
    queueMicrotask(() => ui.requestCreate(kind));
  }
  const createLabel = $derived(section === 'domains' ? 'New domain' : section === 'aliases' ? 'New alias' : section === 'dav' ? 'New DAV user' : 'New account');

  async function restart() {
    try {
      await restartServer(post);
    } catch (e) {
      toast.error(e);
    }
  }

  async function logout() {
    await post('/auth/logout').catch(() => {});
    location.href = '/';
  }
</script>

<div class="app">
  <header class="titlebar">
    <a href="/" use:link class="brand"><Logo size={22} /><span>{brand.name}</span></a>
    <span class="host muted truncate">{ui.status?.hostname}</span>
    <button class="search" onclick={() => (ui.paletteOpen = true)} aria-label="Search">
      <Icon name="search" size={16} /><span class="label-text">Search or jump to…</span><kbd>{mac ? '⌘' : 'Ctrl'} K</kbd>
    </button>
    <span class="spacer"></span>
    <button class="icon-btn" onclick={() => theme.toggle()} title="Toggle dark mode" aria-label="Toggle dark mode"><Icon name={theme.dark ? 'sun' : 'moon'} /></button>
    <button class="icon-btn" onclick={() => { about = true; refreshBadges(); }} title="About this server" aria-label="About"><Icon name="info" /></button>
    <a class="icon-btn" href="/settings" use:link title="Settings" aria-label="Settings"><Icon name="settings" /></a>
    <div class="menu-wrap">
      <button class="me" onclick={() => (menu = !menu)} aria-label="Account menu"><Avatar text={ui.me?.display_name || ui.me?.email} size={28} /></button>
      {#if menu}
        <div class="menu fade-in" role="menu">
          <div class="who"><strong>{ui.me?.display_name || 'Administrator'}</strong><span class="muted small">{ui.me?.email}</span></div>
          <a href="/settings" use:link onclick={() => (menu = false)} role="menuitem"><Icon name="key" size={16} /> Change password</a>
          <a href="/api" use:link onclick={() => (menu = false)} role="menuitem"><Icon name="link" size={16} /> API tokens</a>
          <button onclick={logout} role="menuitem"><Icon name="logout" size={16} /> Sign out</button>
        </div>
        <button class="scrim" onclick={() => (menu = false)} aria-label="Close menu"></button>
      {/if}
    </div>
  </header>

  {#if ui.restartRequired}
    <div class="restart-bar">
      <Icon name="refresh" size={16} />
      <span>config.toml changed. Restart the server to apply it.</span>
      <span class="spacer"></span>
      <a href="/configuration" use:link class="small">Review</a>
      <button class="btn small primary" onclick={restart} disabled={ui.restarting}>{ui.restarting ? 'Restarting…' : 'Restart now'}</button>
    </div>
  {/if}

  <div class="body">
    <aside class="sidebar" class:rail={collapsed}>
      <div class="top">
        <button class="btn primary compose" onclick={create} title={createLabel}>
          <Icon name="edit" /><span class="label-text">{createLabel}</span>
        </button>
        {#if !narrow}
          <button class="icon-btn collapse" onclick={() => (ui.sidebarCollapsed = !ui.sidebarCollapsed)} aria-label="Toggle sidebar">
            <Icon name={collapsed ? 'panelOpen' : 'panel'} />
          </button>
        {/if}
      </div>
      <nav>
        {#each GROUPS as g}
          {#if g.title}<div class="group">{g.title}</div>{/if}
          {#each g.items as n}
            {@const active = n.path === '/' ? section === '' : router.path.startsWith(n.path)}
            <a href={n.path} use:link class:active title={n.label}>
              <Icon name={n.icon} size={20} />
              <span class="label-text">{n.label}</span>
              {#if n.badge === 'queue' && queueCount}<span class="count">{queueCount}</span>{/if}
            </a>
          {/each}
        {/each}
      </nav>
    </aside>
    <main>
      {#key section}
        <Page onChanged={refreshBadges} />
      {/key}
    </main>
  </div>
</div>

<Palette pages={PAGES_FLAT} />

{#if ui.restarting}
  <div class="restarting"><div class="card"><Icon name="refresh" size={22} /><strong>Restarting…</strong><span class="muted small">The console reloads when the server is back.</span></div></div>
{/if}

<Modal title="About this server" bind:open={about} width={460}>
  {#if overview}
    <dl class="about">
      <dt>Host name</dt><dd>{overview.hostname}</dd>
      <dt>Primary domain</dt><dd>{overview.primary_domain ?? '—'}</dd>
      <dt>Version</dt><dd>Picacho Server {overview.version}</dd>
      <dt>Sign-in</dt><dd>{ui.status?.auth?.oidc ? `Single sign-on (${ui.status.auth.oidc.name})` : 'Password'}{ui.status?.auth?.oidc && ui.status?.auth?.password ? ' or password' : ''}</dd>
      <dt>Uptime</dt><dd>{duration(overview.uptime_secs)}</dd>
      <dt>Listening</dt><dd>{#each overview.listeners as l}<div>{l.protocol} <span class="mono muted">{l.address}</span></div>{/each}</dd>
    </dl>
  {/if}
</Modal>

<style>
  .app { height: 100%; display: flex; flex-direction: column; }
  .titlebar { height: 50px; flex: none; display: flex; align-items: center; gap: 4px; padding: 0 12px 0 18px; border-bottom: 1px solid var(--border); background: var(--bg); }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 600; font-size: 16px; color: var(--text); text-decoration: none !important; }
  .host { margin-left: 12px; font-size: 13.5px; max-width: 22vw; }
  .search { margin-left: 18px; display: flex; align-items: center; gap: 8px; height: 32px; padding: 0 8px 0 10px; width: min(340px, 30vw); border-radius: 9px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); cursor: pointer; font-size: 13.5px; }
  .search:hover { border-color: color-mix(in srgb, var(--border) 60%, var(--text)); }
  .search kbd { margin-left: auto; font-family: var(--mono); font-size: 11px; padding: 1px 6px; border: 1px solid var(--border); border-radius: 5px; background: var(--raised); }
  .menu-wrap { position: relative; margin-left: 6px; }
  .me { border: 0; background: none; padding: 2px; border-radius: 50%; cursor: pointer; display: grid; }
  .menu { position: absolute; right: 0; top: 40px; z-index: 30; width: 240px; padding: 6px; border-radius: 12px; background: var(--raised); border: 1px solid var(--border); box-shadow: var(--shadow); display: grid; }
  .menu .who { display: grid; padding: 8px 10px 10px; border-bottom: 1px solid var(--border); margin-bottom: 4px; }
  .menu a, .menu button { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: 8px; border: 0; background: none; color: var(--text); text-align: left; cursor: pointer; font-size: 14px; text-decoration: none; }
  .menu a:hover, .menu button:hover { background: var(--surface); }
  .scrim { position: fixed; inset: 0; z-index: 20; background: transparent; border: 0; cursor: default; }
  .restart-bar { display: flex; align-items: center; gap: 10px; padding: 8px 18px; background: var(--warning-soft); border-bottom: 1px solid var(--border); font-size: 14px; }
  .body { flex: 1; display: flex; min-height: 0; }
  .sidebar { width: 248px; flex: none; padding: 16px 14px; display: flex; flex-direction: column; gap: 14px; background: var(--bg); border-right: 1px solid var(--border); transition: width 0.24s ease; overflow-y: auto; overflow-x: hidden; }
  .top { display: flex; gap: 8px; align-items: center; }
  .compose { flex: 1; height: 50px; border-radius: 12px; justify-content: center; font-size: 16px; min-width: 0; }
  .collapse { width: 44px; height: 50px; border-radius: 10px; background: var(--surface); flex: none; }
  nav { display: grid; gap: 2px; }
  .group { font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); padding: 14px 16px 6px; }
  nav a { display: flex; align-items: center; gap: 14px; height: 42px; padding: 0 14px 0 16px; border-radius: 10px; color: var(--text); text-decoration: none !important; font-size: 15px; white-space: nowrap; }
  nav a :global(svg) { color: var(--muted); flex: none; }
  nav a:hover { background: var(--surface); }
  nav a.active { background: var(--soft); }
  nav a.active :global(svg) { color: var(--accent); }
  nav .count { margin-left: auto; }
  .rail { width: 72px; padding: 16px 10px; }
  .rail .top { flex-direction: column; }
  .rail .compose { width: 52px; flex: none; padding: 0; }
  .rail .collapse { width: 52px; height: 40px; }
  .rail .label-text, .rail nav .count { display: none; }
  .rail .group { height: 1px; padding: 0; margin: 8px 6px; background: var(--border); font-size: 0; }
  .rail nav a { justify-content: center; padding: 0; }
  main { flex: 1; min-width: 0; min-height: 0; }
  .about { display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; margin: 0; }
  .about dt { color: var(--muted); }
  .about dd { margin: 0; }
  .restarting { position: fixed; inset: 0; z-index: 90; display: grid; place-items: center; background: var(--overlay); }
  .restarting .card { display: grid; justify-items: center; gap: 8px; padding: 26px 34px; }
  @media (max-width: 900px) {
    .search { width: 36px; padding: 0; justify-content: center; }
    .search .label-text, .search kbd { display: none; }
  }
  @media (max-width: 640px) {
    .host { display: none; }
    .sidebar.rail { width: 60px; padding: 12px 6px; }
    .rail .compose, .rail .collapse { width: 46px; }
  }
</style>
