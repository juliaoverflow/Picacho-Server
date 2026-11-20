<script>
  // OAuth consent: an app asks for access to this mailbox.
  import { onMount } from 'svelte';
  import { get, post } from '../lib/api.js';
  import { ui } from '../lib/ui.svelte.js';
  import { brand } from '../lib/brand.svelte.js';
  import Logo from '../lib/Logo.svelte';
  import Icon from '../lib/Icon.svelte';

  let req = $state(null);
  let fatal = $state('');
  let grant = $state({});
  let busy = $state(false);
  const params = Object.fromEntries(new URLSearchParams(location.search));

  const SERVICES = [
    ['jmap', 'JMAP', 'Modern mail apps over HTTPS', ['none', 'read', 'write']],
    ['imap', 'IMAP', 'Read and organize mail in folders', ['none', 'read', 'write']],
    ['smtp', 'Send mail (SMTP)', 'Send messages as you', ['none', 'write']],
    ['dav', 'Calendars, contacts & files', 'CalDAV, CardDAV and WebDAV', ['none', 'read', 'write']],
    ['sieve', 'Mail filters', 'Read and change your filter rules (ManageSieve)', ['none', 'write']],
    ['account', 'Account settings', 'Your name, forwarding, vacation reply, filters and app passwords', ['none', 'read', 'write']],
  ];
  const LABEL = { none: 'No access', read: 'Read only', write: 'Read & write' };
  const SEND = { none: 'Not allowed', write: 'Allowed' };

  onMount(async () => {
    try {
      const r = await get(`/oauth/request${location.search}`);
      if (r.redirect) return (location.href = r.redirect);
      if (r.fatal) return (fatal = r.fatal);
      req = r;
      grant = { ...r.requested };
    } catch (e) {
      fatal = e.message;
    }
  });

  const options = (svc, levels) => levels.filter((l) => levels.indexOf(l) <= levels.indexOf(req.requested[svc] ?? 'none') || l === 'none');

  async function decide(deny) {
    busy = true;
    try {
      const r = await post('/oauth/approve', { params, grant, deny });
      location.href = r.redirect;
    } catch (e) {
      fatal = e.message;
      busy = false;
    }
  }
</script>

<div class="wrap">
  <div class="card panel fade-in">
    <div class="head"><Logo size={30} /><strong>{brand.name}</strong></div>
    {#if fatal}
      <div class="notice danger"><Icon name="alert" size={18} /><span>{fatal}</span></div>
      <p class="muted small">You can close this window.</p>
    {:else if req}
      <h1><span class="app">{req.client.name}</span> wants to access your mailbox</h1>
      <p class="muted">Signed in as <strong>{ui.me?.email}</strong>. After you choose, you'll return to <span class="mono">{req.redirect_host}</span>.</p>
      {#if req.client.dynamic}<div class="notice warning"><Icon name="alert" size={18} /><span>This app registered itself. Only continue if you started this sign-in.</span></div>{/if}
      <div class="services">
        {#each SERVICES.filter(([k]) => req.requested[k] && req.requested[k] !== 'none') as [k, name, sub, levels]}
          <label class="svc">
            <div><strong>{name}</strong><span class="muted small">{sub}</span></div>
            <select class="input" bind:value={grant[k]}>
              {#each options(k, levels) as l}<option value={l}>{k === 'smtp' ? SEND[l] : LABEL[l]}</option>{/each}
            </select>
          </label>
        {/each}
      </div>
      <p class="small muted">You can revoke access at any time from your account page.</p>
      <div class="actions">
        <button class="btn" onclick={() => decide(true)} disabled={busy}>Deny</button>
        <button class="btn primary" onclick={() => decide(false)} disabled={busy || Object.values(grant).every((v) => v === 'none')}>Allow</button>
      </div>
    {:else}
      <p class="muted">Loading…</p>
    {/if}
  </div>
</div>

<style>
  .wrap { min-height: 100%; display: grid; place-items: center; padding: 24px 16px; }
  .panel { width: min(480px, 100%); display: grid; gap: 16px; padding: 28px; border-radius: 16px; box-shadow: var(--shadow); }
  .head { display: flex; align-items: center; gap: 10px; }
  h1 { font-size: 20px; line-height: 1.35; }
  .app { color: var(--accent); }
  p { margin: 0; }
  .services { display: grid; gap: 10px; }
  .svc { display: flex; align-items: center; gap: 14px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 12px; background: var(--surface); }
  .svc > div { flex: 1; display: grid; gap: 2px; }
  .svc select { width: 160px; }
  .actions { display: flex; justify-content: flex-end; gap: 10px; }
</style>
