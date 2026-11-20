<script>
  // Console for regular (non-admin) users: their settings, filters, app passwords and data.
  import { onMount } from 'svelte';
  import { get, post, put } from '../lib/api.js';
  import { ui } from '../lib/ui.svelte.js';
  import { theme } from '../lib/theme.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Logo from '../lib/Logo.svelte';
  import Avatar from '../lib/Avatar.svelte';
  import Copy from '../lib/Copy.svelte';
  import ClientSettings from './ClientSettings.svelte';
  import AppPasswords from '../lib/AppPasswords.svelte';
  import VacationEditor from '../lib/VacationEditor.svelte';
  import SieveEditor from '../lib/SieveEditor.svelte';
  import DataTools from '../lib/DataTools.svelte';
  import { brand } from '../lib/brand.svelte.js';
  import { bytes } from '../lib/format.js';

  const TABS = [
    ['account', 'Account', 'user'],
    ['vacation', 'Out of office', 'reply'],
    ['filters', 'Filters', 'filter'],
    ['apps', 'Apps & passwords', 'key'],
    ['dav', 'Calendars', 'calendar'],
    ['data', 'Your data', 'download'],
  ];
  const fromHash = () => (TABS.some(([k]) => k === location.hash.slice(1)) ? location.hash.slice(1) : 'account');
  let tab = $state(fromHash());
  function go(k) {
    tab = k;
    history.replaceState(null, '', k === 'account' ? location.pathname : `#${k}`);
  }

  let client = $state(null);
  let servers = $state(null);
  let current = $state('');
  let next = $state('');
  let busy = $state(false);

  onMount(async () => {
    [client, servers] = await Promise.all([get('/me/client').catch(() => null), get('/me/servers').catch(() => null)]);
  });

  async function change(e) {
    e.preventDefault();
    busy = true;
    try {
      await post('/me/password', { current, new: next });
      current = next = '';
      toast.ok('Password changed. Other sessions were signed out.');
    } catch (err) {
      toast.error(err);
    } finally {
      busy = false;
    }
  }
  async function logout() {
    await post('/auth/logout').catch(() => {});
    location.href = '/';
  }

  // ---- calendars & contacts
  let dav = $state(null);
  let davLoaded = $state(false);
  let davPassword = $state('');
  async function loadDav() {
    dav = await get('/me/dav').catch((e) => (toast.error(e), null));
    davLoaded = true;
  }
  $effect(() => {
    if (tab === 'dav' && !davLoaded) loadDav();
  });
  async function setDavPassword(e) {
    e?.preventDefault();
    try {
      await put('/me/dav', { password: davPassword || null });
      toast.ok(davPassword ? 'Calendar and contacts apps now use this password.' : 'Separate password removed.');
      davPassword = '';
      loadDav();
    } catch (err) {
      toast.error(err);
    }
  }
</script>

<div class="me">
  <header class="bar">
    <Logo size={22} /><strong>{brand.name}</strong><span class="spacer"></span>
    <button class="icon-btn" onclick={() => theme.toggle()} aria-label="Toggle dark mode"><Icon name={theme.dark ? 'sun' : 'moon'} /></button>
    <button class="btn ghost small" onclick={logout}><Icon name="logout" size={16} /> Sign out</button>
  </header>
  <div class="page"><div class="page-inner">
    <div class="lead"><Avatar text={ui.me.display_name || ui.me.email} size={52} /><div><h1>{ui.me.display_name || ui.me.email}</h1><div class="muted">{ui.me.email}</div></div></div>

    <nav class="tabs" aria-label="Sections">
      {#each TABS as [k, label, icon]}
        <button class:on={tab === k} onclick={() => go(k)} aria-current={tab === k ? 'page' : undefined}><Icon name={icon} size={16} /><span>{label}</span></button>
      {/each}
    </nav>

    {#if tab === 'account'}
      <div class="card">
        <h3>Storage</h3>
        <p class="sub">{bytes(ui.me.used_bytes)} used{ui.me.quota_bytes ? ` of ${bytes(ui.me.quota_bytes)}` : ''}</p>
        {#if ui.me.quota_bytes}<div class="meter"><div style="width:{Math.min(100, (ui.me.used_bytes / ui.me.quota_bytes) * 100)}%"></div></div>{/if}
      </div>
      <div class="card"><h3>Mail app settings</h3><p class="sub">Use these in Apple Mail, Thunderbird, Outlook, Picacho or any IMAP client.</p><ClientSettings {client} /></div>
      {#if ui.me.sso_linked}
        <div class="notice" style="margin-top:14px"><Icon name="lock" size={18} /><span>You sign in with single sign-on.{ui.me.has_password ? '' : ' Your mailbox has no password, so mail apps use app passwords or sign in with your account.'}</span></div>
      {/if}
      {#if ui.me.has_password}
        <form class="card" onsubmit={change}>
          <h3>Change password</h3>
          <div class="grid2">
            <label class="field"><span>Current password</span><input class="input" type="password" bind:value={current} autocomplete="current-password" required /></label>
            <label class="field"><span>New password</span><input class="input" type="password" bind:value={next} autocomplete="new-password" required /></label>
          </div>
          <div class="row" style="margin-top:14px"><button class="btn primary" disabled={busy}>Change password</button></div>
        </form>
      {/if}
    {:else if tab === 'vacation'}
      <div class="card">
        <h3>Out of office</h3>
        <p class="sub">Reply automatically while you're away.</p>
        <VacationEditor base="/me" />
      </div>
    {:else if tab === 'filters'}
      <div class="card">
        <h3>Filters</h3>
        <p class="sub">Sieve scripts that sort, flag, forward or reject mail as it arrives.{servers?.managesieve ? ' Mail apps with filter support can also edit them over ManageSieve.' : ''}</p>
        <SieveEditor base="/me" />
      </div>
      {#if servers?.managesieve}
        <div class="card row">
          <Icon name="server" />
          <div style="flex:1"><strong>ManageSieve</strong><div class="muted small mono">{servers.managesieve.host}:{servers.managesieve.port}</div></div>
          <Copy value="{servers.managesieve.host}:{servers.managesieve.port}" />
        </div>
      {/if}
    {:else if tab === 'apps'}
      <div class="card">
        <h3>App passwords</h3>
        <p class="sub">Give each mail, calendar or contacts app its own password you can revoke any time.{servers?.jmap ? ' JMAP clients connect at ' : ''}{#if servers?.jmap}<code>{servers.jmap}</code>.{/if}</p>
        <AppPasswords />
      </div>
      {#if ui.status?.auth?.provider}
        <div class="card row">
          <div style="flex:1"><h3>Connected apps</h3><p class="sub" style="margin:0">Apps get access to your mailbox through your {ui.status.auth.provider.name} account. See and disconnect them there.</p></div>
          <a class="btn" href={`${ui.status.auth.provider.issuer}/account`} target="_blank" rel="noopener"><Icon name="external" size={16} /> Manage apps</a>
        </div>
      {/if}
      {#if servers?.apple_profile}
        <div class="card row">
          <div style="flex:1"><h3>Apple devices</h3><p class="sub" style="margin:0">Install a profile that sets up Mail, Calendar and Contacts on iPhone, iPad or Mac.</p></div>
          <a class="btn" href={servers.apple_profile}><Icon name="download" size={16} /> Download profile</a>
        </div>
      {/if}
    {:else if tab === 'dav'}
      {#if dav?.principal}
        <div class="card">
          <h3>Addresses for apps</h3>
          <p class="sub">Sign in as <span class="mono">{dav.principal.username}</span>. Most apps only need the server name; use these if they ask for a full URL.</p>
          <div class="urls">
            {#each [['Calendars', dav.urls.caldav], ['Contacts', dav.urls.carddav], ['Files', dav.urls.webdav]] as [l, u]}
              <span class="muted small">{l}</span><code class="truncate">{u}</code><Copy value={u} />
            {/each}
          </div>
          <p class="sub" style="margin:14px 0 0">Files: {bytes(dav.principal.used_bytes)} used{dav.principal.quota_bytes ? ` of ${bytes(dav.principal.quota_bytes)}` : ''}</p>
          {#if dav.principal.quota_bytes}<div class="meter"><div style="width:{Math.min(100, (dav.principal.used_bytes / dav.principal.quota_bytes) * 100)}%"></div></div>{/if}
        </div>
        <form class="card" onsubmit={setDavPassword}>
          <h3>Calendar &amp; contacts password</h3>
          <p class="sub">{dav.principal.has_dav_password ? 'Calendar, contacts and file apps use a separate password.' : 'Apps sign in with your mail password or an app password. You can set a separate password just for them.'}</p>
          <div class="row">
            <input class="input" type="password" autocomplete="new-password" bind:value={davPassword} placeholder={dav.principal.has_dav_password ? 'New password' : 'Separate password'} style="max-width:300px" />
            <button class="btn primary" disabled={!davPassword}>{dav.principal.has_dav_password ? 'Change' : 'Set password'}</button>
            {#if dav.principal.has_dav_password}<button type="button" class="btn" onclick={() => { davPassword = ''; setDavPassword(); }}>Remove</button>{/if}
          </div>
        </form>
      {:else if davLoaded}
        <div class="card empty"><Icon name="calendar" size={30} /><h3>Not available</h3><p>Calendars and contacts aren't turned on for your account. Ask your administrator.</p></div>
      {/if}
    {:else if tab === 'data'}
      <div class="card">
        <h3>Your data</h3>
        <DataTools base="/me" label="your mailbox" />
      </div>
    {/if}
  </div></div>
</div>

<style>
  .me { height: 100%; display: flex; flex-direction: column; }
  .bar { display: flex; align-items: center; gap: 10px; padding: 8px 16px; border-bottom: 1px solid var(--border); }
  .page { flex: 1; }
  .page-inner { max-width: 820px; margin: 0 auto; }
  .lead { display: flex; align-items: center; gap: 16px; margin-bottom: 18px; }
  .tabs { display: flex; gap: 4px; margin-bottom: 16px; overflow-x: auto; padding-bottom: 2px; border-bottom: 1px solid var(--border); }
  .tabs button { display: flex; align-items: center; gap: 7px; height: 38px; padding: 0 12px; border: 0; background: none; color: var(--muted); cursor: pointer; white-space: nowrap; font-weight: 500; border-bottom: 2px solid transparent; margin-bottom: -3px; }
  .tabs button:hover { color: var(--text); }
  .tabs button.on { color: var(--text); border-bottom-color: var(--accent); }
  .tabs button.on :global(svg) { color: var(--accent); }
  .urls { display: grid; grid-template-columns: 80px minmax(0, 1fr) auto; gap: 6px 12px; align-items: center; }
  .card.row :global(svg) { color: var(--muted); }
  form.card { margin-top: 14px; }
  .tabs + .card { margin-top: 0; }
</style>
