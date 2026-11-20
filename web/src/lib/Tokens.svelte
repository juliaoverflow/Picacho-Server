<script>
  // Create, list and revoke API tokens / app passwords.
  import { onMount } from 'svelte';
  import { get, post, del } from './api.js';
  import { toast } from './toast.svelte.js';
  import { ago, date } from './format.js';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import Copy from './Copy.svelte';

  let { admin = false } = $props();
  let tokens = $state([]);
  let accounts = $state([]);
  let creating = $state(false);
  let draft = $state({});
  let secret = $state(null);

  // Per-protocol access levels, shown as dropdowns.
  const SERVICES = [
    ['imap', 'IMAP', 'Mail apps reading folders', ['none', 'read', 'write']],
    ['smtp', 'SMTP', 'Sending mail from apps', ['none', 'write']],
    ['jmap', 'JMAP', 'Modern clients and integrations over HTTPS', ['none', 'read', 'write']],
  ];
  const LEVEL = { none: 'No access', read: 'Read only', write: 'Read & write' };
  const SEND = { none: 'Not allowed', write: 'Can send' };
  function scopesOf(d) {
    const out = [];
    for (const [k] of SERVICES) {
      if (d[k] === 'write') out.push(k);
      if (d[k] === 'read') out.push(`${k}:read`);
    }
    if (d.admin) out.push('admin');
    return out;
  }

  async function load() {
    tokens = await get(`/tokens${admin ? '?all=1' : ''}`);
    if (admin) accounts = await get('/admin/accounts').catch(() => []);
  }
  onMount(() => load().catch((e) => toast.error(e)));

  function open() {
    draft = { name: '', imap: admin ? 'none' : 'write', smtp: admin ? 'none' : 'write', jmap: 'none', admin, expires_days: 0, account: '' };
    creating = true;
  }

  async function create(e) {
    e?.preventDefault();
    try {
      const body = { name: draft.name, scopes: scopesOf(draft), expires_days: Number(draft.expires_days) || null };
      if (admin && draft.account) body.account = draft.account;
      const r = await post('/tokens', body);
      creating = false;
      secret = r;
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  async function revoke(t) {
    if (!confirm(`Revoke "${t.name}"? Anything using it stops working immediately.`)) return;
    try {
      await del(`/tokens/${t.id}`);
      toast.ok('Token revoked.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }
  const label = (s) =>
    ({ imap: 'IMAP read & write', 'imap:read': 'IMAP read only', smtp: 'SMTP sending', jmap: 'JMAP read & write', 'jmap:read': 'JMAP read only', admin: 'Admin API', mail: 'IMAP & SMTP' })[s] ?? s;
</script>

<div class="row" style="margin-bottom:10px">
  <span class="spacer"></span>
  <button class="btn small primary" onclick={open}><Icon name="plus" size={16} /> {admin ? 'New token' : 'New app password'}</button>
</div>
{#if tokens.length}
  <table class="table">
    <thead><tr><th>Name</th>{#if admin}<th>Account</th>{/if}<th>Scopes</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
    <tbody>
      {#each tokens as t}
        <tr>
          <td><strong>{t.name}</strong><div class="mono small muted">{t.prefix}…</div></td>
          {#if admin}<td class="small">{t.account}</td>{/if}
          <td>{#each t.scopes.split(',') as s}<span class="chip" style="margin:0 4px 4px 0">{label(s)}</span>{/each}</td>
          <td class="small muted">{ago(t.last_used)}</td>
          <td class="small muted">{t.expires_at ? date(t.expires_at) : 'Never'}</td>
          <td><button class="btn small danger" onclick={() => revoke(t)}>Revoke</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
{:else}
  <p class="muted small">No tokens yet.</p>
{/if}

<Modal title={admin ? 'New API token' : 'New app password'} bind:open={creating} width={520}>
  <form id="new-token" onsubmit={create} style="display:grid;gap:14px">
    <label class="field"><span>Name</span><input class="input" bind:value={draft.name} placeholder={admin ? 'Provisioning script' : 'Phone'} required autofocus /></label>
    {#if admin}
      <label class="field"><span>For account</span>
        <select class="input" bind:value={draft.account}><option value="">Me</option>{#each accounts as a}<option value={a.email}>{a.email}</option>{/each}</select>
      </label>
    {/if}
    <div class="field"><span>Access</span>
      <div class="scopes">
        {#each SERVICES as [k, title, sub, levels]}
          <label class="scope" class:on={draft[k] !== 'none'}>
            <span><strong>{title}</strong><span class="hint">{sub}</span></span>
            <select class="input" bind:value={draft[k]}>{#each levels as l}<option value={l}>{k === 'smtp' ? SEND[l] : LEVEL[l]}</option>{/each}</select>
          </label>
        {/each}
        {#if admin}
          <label class="scope" class:on={draft.admin}>
            <span><strong>Admin REST API</strong><span class="hint">Manage the server from scripts and automation.</span></span>
            <input type="checkbox" bind:checked={draft.admin} />
          </label>
        {/if}
      </div>
    </div>
    <label class="field"><span>Expires after (days)</span><input class="input" type="number" min="0" bind:value={draft.expires_days} /><span class="hint">0 means never.</span></label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-token" disabled={!draft.name || !scopesOf(draft).length}>Create</button>
  {/snippet}
</Modal>

<Modal title="Copy your token now" open={!!secret} width={520}>
  {#if secret}
    <p class="muted">This is the only time it's shown. Store it somewhere safe.</p>
    <div class="secret"><code>{secret.token}</code><Copy value={secret.token} /></div>
    <p class="small muted">Scopes: {secret.scopes.map(label).join(', ')}</p>
  {/if}
  {#snippet footer()}
    <button class="btn primary" onclick={() => (secret = null)}>Done</button>
  {/snippet}
</Modal>

<style>
  .scopes { display: grid; gap: 8px; }
  .scope { display: flex; gap: 12px; align-items: center; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; }
  .scope select { width: 150px; flex: none; }
  .scope > span { flex: 1; }
  .scope.on { border-color: var(--accent); background: var(--soft); }
  .scope > span { display: grid; gap: 2px; }
  .scope input { accent-color: var(--accent); width: 18px; height: 18px; }
  .secret { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); }
  .secret code { flex: 1; word-break: break-all; font-size: 13px; }
</style>
