<script>
  import { onMount } from 'svelte';
  import { get, post, patch, del } from '../lib/api.js';
  import { router, link } from '../lib/router.svelte.js';
  import { ui, onCreate } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { bytes, ago, dateTime } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Avatar from '../lib/Avatar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import ClientSettings from './ClientSettings.svelte';
  import SieveEditor from '../lib/SieveEditor.svelte';
  import VacationEditor from '../lib/VacationEditor.svelte';
  import DataTools from '../lib/DataTools.svelte';

  let { onChanged } = $props();
  let accounts = $state([]);
  let domains = $state([]);
  let query = $state('');
  let detail = $state(null);
  let form = $state({});
  let saving = $state(false);
  let creating = $state(false);
  let draft = $state({});
  let resetting = $state(false);
  let newPassword = $state('');
  let confirmDelete = $state(false);
  let testing = $state(false);

  const selectedId = $derived(Number(router.parts[1]) || null);
  const filtered = $derived(
    accounts.filter((a) => (a.email + ' ' + a.display_name).toLowerCase().includes(query.toLowerCase())),
  );
  const localDomains = $derived(domains.filter((d) => d.mode === 'local'));

  async function load() {
    [accounts, domains] = await Promise.all([get('/admin/accounts'), get('/admin/domains')]);
  }
  onMount(load);

  function fill(a) {
    form = {
      display_name: a.display_name,
      role: a.role,
      quota_mb: Math.round(a.quota_bytes / 1048576),
      forward_to: a.forward_to,
      keep_copy: a.keep_copy,
      can_send_external: a.can_send_external,
    };
  }

  let davPrincipal = $state(undefined);
  $effect(() => {
    const id = selectedId;
    detail = null;
    davPrincipal = undefined;
    if (id) {
      get(`/admin/accounts/${id}`).then((a) => { detail = a; fill(a); }).catch((e) => toast.error(e));
      get(`/admin/accounts/${id}/dav`).then((p) => (davPrincipal = p)).catch(() => (davPrincipal = null));
    }
  });

  function generatePassword() {
    const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    return [...bytes].map((b) => alphabet[b % alphabet.length]).join('').replace(/(.{5})(?!$)/g, '$1-');
  }

  onCreate('account', () => {
    draft = { local: '', domain: localDomains[0]?.name ?? '', display_name: '', password: generatePassword(), role: 'user', quota_mb: null, show: true };
    creating = true;
  });

  async function create(e) {
    e?.preventDefault();
    try {
      const a = await post('/admin/accounts', {
        email: `${draft.local.trim()}@${draft.domain}`,
        password: draft.password,
        display_name: draft.display_name,
        role: draft.role,
        quota_mb: draft.quota_mb === null || draft.quota_mb === '' ? undefined : Number(draft.quota_mb),
      });
      creating = false;
      toast.ok(`${a.email} created.`);
      await load();
      onChanged?.();
      router.go(`/accounts/${a.id}`);
    } catch (err) {
      toast.error(err);
    }
  }

  async function save() {
    saving = true;
    try {
      const a = await patch(`/admin/accounts/${detail.id}`, { ...form, quota_mb: Number(form.quota_mb) || 0 });
      detail = { ...detail, ...a };
      toast.ok('Account saved.');
      load();
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }

  async function setActive(v) {
    try {
      const a = await patch(`/admin/accounts/${detail.id}`, { active: v });
      detail = { ...detail, ...a };
      toast.ok(v ? 'Account enabled.' : 'Account disabled. It can’t sign in or receive mail.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }

  async function resetPassword(e) {
    e?.preventDefault();
    try {
      await post(`/admin/accounts/${detail.id}/password`, { password: newPassword });
      resetting = false;
      toast.ok('Password changed. The account’s console sessions were signed out.');
    } catch (err) {
      toast.error(err);
    }
  }

  async function remove() {
    try {
      await del(`/admin/accounts/${detail.id}`);
      confirmDelete = false;
      toast.ok('Account and its mail deleted.');
      await load();
      onChanged?.();
      router.go('/accounts');
    } catch (e) {
      toast.error(e);
    }
  }

  async function sendTest() {
    testing = true;
    try {
      await post('/admin/test-message', { to: detail.email });
      toast.ok(`Test message delivered to ${detail.email}.`);
      setTimeout(() => get(`/admin/accounts/${detail.id}`).then((a) => (detail = a)), 600);
    } catch (e) {
      toast.error(e);
    } finally {
      testing = false;
    }
  }

  function usage(a) {
    if (!a.quota_bytes) return 0;
    return Math.min(100, (a.used_bytes / a.quota_bytes) * 100);
  }
</script>

<div class="panes" class:has-detail={!!selectedId}>
  <section class="list-pane">
    <div class="list-head">
      <h1>Accounts</h1><span class="count">{accounts.length}</span><span class="spacer"></span>
      <button class="icon-btn" onclick={load} title="Refresh" aria-label="Refresh"><Icon name="refresh" /></button>
    </div>
    <div class="list-search"><input class="input" placeholder="Search accounts" bind:value={query} /></div>
    <div class="list">
      {#each filtered as a (a.id)}
        <button class="list-item" class:active={a.id === selectedId} onclick={() => router.go(`/accounts/${a.id}`)}>
          {#if !a.active}<span class="dot bad"></span>{:else if usage(a) > 90}<span class="dot warn"></span>{/if}
          <Avatar text={a.display_name || a.email} />
          <div class="main">
            <div class="top"><span class="name">{a.display_name || a.email.split('@')[0]}</span>{#if a.role === 'admin'}<span class="chip accent">Admin</span>{/if}<span class="meta">{ago(a.last_login)}</span></div>
            <div class="line2">{a.email}</div>
            <div class="line3">{bytes(a.used_bytes)}{a.quota_bytes ? ` of ${bytes(a.quota_bytes)}` : ' · no quota'}{a.forward_to ? ' · forwarding' : ''}{!a.active ? ' · disabled' : ''}</div>
          </div>
        </button>
      {:else}
        <div class="empty"><Icon name="users" size={30} /><h3>{query ? 'No matches' : 'No accounts yet'}</h3></div>
      {/each}
    </div>
  </section>

  <section class="detail-pane">
    {#if detail}
      <div class="toolbar">
        <button class="btn ghost only-narrow" onclick={() => router.go('/accounts')}><Icon name="back" /> Accounts</button>
        <button class="btn ghost" onclick={() => { newPassword = generatePassword(); resetting = true; }}><Icon name="key" /><span class="label-text">Reset password</span></button>
        <button class="btn ghost" onclick={sendTest} disabled={testing}><Icon name="send" /><span class="label-text">Send test message</span></button>
        <span class="spacer"></span>
        <button class="icon-btn" onclick={() => (confirmDelete = true)} title="Delete account" aria-label="Delete account"><Icon name="trash" /></button>
      </div>
      <div class="detail fade-in"><div class="detail-inner">
        <h1>{detail.display_name || detail.email}</h1>
        <div class="lead">
          <Avatar text={detail.display_name || detail.email} size={48} />
          <div class="grow">
            <div><strong>{detail.email}</strong> {#if detail.role === 'admin'}<span class="chip accent">Administrator</span>{/if} {#if !detail.active}<span class="chip danger">Disabled</span>{/if}</div>
            <div class="muted small">Last sign-in {ago(detail.last_login)} · {detail.sessions} IMAP session{detail.sessions === 1 ? '' : 's'} open</div>
          </div>
          <Toggle checked={detail.active} onchange={setActive} />
        </div>

        <div class="card">
          <h3>Profile</h3>
          <div class="grid2" style="margin-top:10px">
            <label class="field"><span>Display name</span><input class="input" bind:value={form.display_name} /></label>
            <label class="field"><span>Role</span>
              <select class="input" bind:value={form.role}><option value="user">User</option><option value="admin">Administrator</option></select>
            </label>
          </div>
        </div>

        <div class="card">
          <h3>Storage</h3>
          <p class="sub">{bytes(detail.used_bytes)} used{detail.quota_bytes ? ` of ${bytes(detail.quota_bytes)}` : ''}</p>
          {#if detail.quota_bytes}<div class="meter" class:warn={usage(detail) > 80} class:full={usage(detail) > 95}><div style="width:{usage(detail)}%"></div></div>{/if}
          <label class="field" style="margin-top:14px;max-width:260px"><span>Quota (MB)</span><input class="input" type="number" min="0" bind:value={form.quota_mb} /><span class="hint">0 means unlimited.</span></label>
          {#if detail.mailboxes?.length}
            <table class="table" style="margin-top:14px">
              <thead><tr><th>Folder</th><th>Messages</th><th>Unread</th><th>Size</th></tr></thead>
              <tbody>
                {#each detail.mailboxes as m}
                  <tr><td><Icon name={m.name === 'INBOX' ? 'inbox' : 'folder'} size={15} /> {m.name}</td><td>{m.messages}</td><td>{m.unseen}</td><td>{bytes(m.size)}</td></tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>

        <div class="card">
          <h3>Forwarding</h3>
          <p class="sub">Send a copy of incoming mail to other addresses.</p>
          <label class="field"><span>Forward to</span><input class="input" bind:value={form.forward_to} placeholder="someone@example.net, other@example.org" /></label>
          <Toggle bind:checked={form.keep_copy} label="Keep a copy in this mailbox" />
        </div>

        <div class="card">
          <h3>Permissions</h3>
          <Toggle bind:checked={form.can_send_external} label="Can send to external addresses" hint="Turn off to limit this account to local delivery." />
        </div>

        <div class="row" style="margin:16px 0"><button class="btn primary" onclick={save} disabled={saving}>Save changes</button></div>

        <div class="card">
          <div class="row"><h3>Aliases</h3><span class="spacer"></span><a href="/aliases" use:link class="small">Manage aliases</a></div>
          {#if detail.aliases?.length}
            <ul class="plain">{#each detail.aliases as al}<li><span class="mono">{al.source}</span> {#if !al.active}<span class="chip">off</span>{/if}</li>{/each}</ul>
          {:else}<p class="sub">No aliases deliver to this account.</p>{/if}
        </div>

        <div class="card">
          <h3>Recent deliveries</h3>
          <p class="sub">Sender and size only; message contents stay private.</p>
          {#if detail.recent?.length}
            <table class="table">
              <thead><tr><th>From</th><th>Folder</th><th>Size</th><th>Received</th></tr></thead>
              <tbody>{#each detail.recent as m}<tr><td class="truncate" style="max-width:260px">{m.from || '—'}</td><td>{m.mailbox}</td><td>{bytes(m.size)}</td><td class="muted">{dateTime(m.date)}</td></tr>{/each}</tbody>
            </table>
          {:else}<p class="muted small">No messages yet.</p>{/if}
        </div>

        {#key detail.id}
          <div class="card">
            <h3>Out of office</h3>
            <p class="sub">An automatic reply the owner can also change from their own console.</p>
            <VacationEditor base="/admin/accounts/{detail.id}" />
          </div>

          <div class="card">
            <h3>Filters (Sieve)</h3>
            <p class="sub">Scripts that sort, flag, forward or reject mail on delivery. Mail apps can also edit them over ManageSieve.</p>
            <SieveEditor base="/admin/accounts/{detail.id}" />
          </div>

          <div class="card">
            <div class="row"><h3>Calendars &amp; contacts</h3><span class="spacer"></span><a href="/dav" use:link class="small">Manage DAV users</a></div>
            {#if davPrincipal}
              <p class="sub" style="margin:4px 0 0">DAV user <span class="mono">{davPrincipal.username}</span> · {bytes(davPrincipal.used_bytes)} of files{davPrincipal.quota_bytes ? ` of ${bytes(davPrincipal.quota_bytes)}` : ''}{davPrincipal.active ? '' : ' · disabled'}</p>
            {:else if davPrincipal === null}
              <p class="sub" style="margin:4px 0 0">Not set up yet. It is created the first time the account signs in to a calendar or contacts app, if mail accounts get DAV automatically.</p>
            {/if}
          </div>

          <div class="card">
            <h3>Backup &amp; migration</h3>
            <DataTools base="/admin/accounts/{detail.id}" canImport label="this account" />
          </div>
        {/key}

        <div class="card"><h3>Mail app settings</h3><p class="sub">Share these with the account’s owner.</p><ClientSettings client={detail.client} /></div>
      </div></div>
    {:else if !selectedId}
      <div class="empty"><Icon name="users" size={34} /><h3>Select an account</h3><p>Edit quotas, forwarding, filters and auto-replies, or export and migrate a mailbox.</p></div>
    {/if}
  </section>
</div>

<Modal title="New account" bind:open={creating} width={520}>
  <form id="new-account" onsubmit={create} style="display:grid;gap:14px">
    <label class="field"><span>Name</span><input class="input" bind:value={draft.display_name} placeholder="Sophie Chen" /></label>
    <label class="field"><span>Address</span>
      <div class="addr">
        <input class="input" bind:value={draft.local} placeholder="sophie" required autofocus />
        <span class="muted">@</span>
        <select class="input" bind:value={draft.domain}>{#each localDomains as d}<option>{d.name}</option>{/each}</select>
      </div>
    </label>
    <label class="field"><span>Password</span>
      <div class="addr">
        <input class="input mono" type={draft.show ? 'text' : 'password'} bind:value={draft.password} required autocomplete="new-password" />
        <button type="button" class="btn small" onclick={() => (draft.password = generatePassword())}>Generate</button>
      </div>
      <span class="hint">Copy it now and share it securely; it isn’t shown again.</span>
    </label>
    <div class="grid2">
      <label class="field"><span>Role</span><select class="input" bind:value={draft.role}><option value="user">User</option><option value="admin">Administrator</option></select></label>
      <label class="field"><span>Quota (MB)</span><input class="input" type="number" min="0" bind:value={draft.quota_mb} placeholder="Default" /></label>
    </div>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-account">Create account</button>
  {/snippet}
</Modal>

<Modal title="Reset password" bind:open={resetting} width={440}>
  <form id="reset" onsubmit={resetPassword} style="display:grid;gap:10px">
    <label class="field"><span>New password for {detail?.email}</span>
      <div class="addr"><input class="input mono" bind:value={newPassword} required /><button type="button" class="btn small" onclick={() => (newPassword = generatePassword())}>Generate</button></div>
    </label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (resetting = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="reset">Set password</button>
  {/snippet}
</Modal>

<Modal title="Delete account?" bind:open={confirmDelete} width={440}>
  <p>This permanently deletes <strong>{detail?.email}</strong> and all of its mail. It can’t be undone.</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (confirmDelete = false)}>Cancel</button>
    <button class="btn danger" onclick={remove}>Delete account and mail</button>
  {/snippet}
</Modal>

<style>
  .grow { flex: 1; display: grid; gap: 4px; }
  .addr { display: flex; align-items: center; gap: 8px; }
  .addr .input { flex: 1; }
  .plain { list-style: none; padding: 0; margin: 8px 0 0; display: grid; gap: 6px; }
</style>
