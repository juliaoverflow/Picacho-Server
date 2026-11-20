<script>
  // The signed-in user's app passwords (/api/me/app-passwords).
  import { onMount } from 'svelte';
  import { get, post, del } from './api.js';
  import { toast } from './toast.svelte.js';
  import { ago, date } from './format.js';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';
  import Copy from './Copy.svelte';

  const SCOPES = [
    ['mail', 'Mail', 'IMAP and SMTP in mail apps'],
    ['jmap', 'JMAP', 'Modern apps and integrations over HTTPS'],
    ['dav', 'Calendars, contacts & files', 'CalDAV, CardDAV and WebDAV'],
    ['sieve', 'Filters', 'Editing filters over ManageSieve'],
  ];
  const LABEL = { mail: 'Mail', imap: 'IMAP', 'imap:read': 'IMAP (read)', smtp: 'SMTP', jmap: 'JMAP', 'jmap:read': 'JMAP (read)', dav: 'DAV', 'dav:read': 'DAV (read)', sieve: 'Filters', account: 'Account', 'account:read': 'Account (read)' };

  let tokens = $state([]);
  let loaded = $state(false);
  let creating = $state(false);
  let draft = $state({});
  let secret = $state(null);
  let revoking = $state(null);

  async function load() {
    try {
      tokens = await get('/me/app-passwords');
    } catch (e) {
      toast.error(e);
    } finally {
      loaded = true;
    }
  }
  onMount(load);

  function open() {
    draft = { name: '', scopes: { mail: true, jmap: true, dav: true, sieve: true }, expires_days: 0 };
    creating = true;
  }
  async function create(e) {
    e?.preventDefault();
    const scopes = SCOPES.map(([k]) => k).filter((k) => draft.scopes[k]);
    if (!scopes.length) return toast.error('Choose at least one kind of access.');
    try {
      const r = await post('/me/app-passwords', { name: draft.name.trim(), scopes, expires_days: Number(draft.expires_days) || null });
      creating = false;
      secret = { ...r, name: draft.name.trim() };
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  async function revoke() {
    try {
      await del(`/me/app-passwords/${revoking.id}`);
      toast.ok(`${revoking.name} can't sign in any more.`);
      revoking = null;
      load();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

{#if tokens.length}
  <table class="table">
    <thead><tr><th>Name</th><th>Access</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
    <tbody>
      {#each tokens as t (t.id)}
        <tr>
          <td><strong>{t.name}</strong><div class="muted small mono">{t.prefix}…</div></td>
          <td>{#each t.scopes.split(/[ ,]+/).filter(Boolean) as sc}<span class="chip">{LABEL[sc] ?? sc}</span> {/each}</td>
          <td class="muted">{ago(t.last_used)}</td>
          <td class="muted">{t.expires_at ? date(t.expires_at) : 'Never'}</td>
          <td><button class="btn small danger" onclick={() => (revoking = t)}>Revoke</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
{:else if loaded}
  <p class="muted small">No app passwords yet.</p>
{/if}
<div class="row" style="margin-top:12px"><button class="btn" onclick={open}><Icon name="plus" size={16} /> New app password</button></div>

<Modal title="New app password" bind:open={creating} width={480}>
  <form id="new-app-pw" onsubmit={create} style="display:grid;gap:14px">
    <label class="field"><span>Name</span><input class="input" bind:value={draft.name} placeholder="iPhone Mail" required autofocus /><span class="hint">So you can recognize it later.</span></label>
    <fieldset class="scopes">
      <legend class="label">Can be used for</legend>
      {#each SCOPES as [k, l, h]}
        <label class="scope"><input type="checkbox" bind:checked={draft.scopes[k]} /><span><strong>{l}</strong><span class="muted small">{h}</span></span></label>
      {/each}
    </fieldset>
    <label class="field" style="max-width:220px"><span>Expires</span>
      <select class="input" bind:value={draft.expires_days}><option value={0}>Never</option><option value={30}>In 30 days</option><option value={90}>In 90 days</option><option value={365}>In a year</option></select>
    </label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-app-pw">Create</button>
  {/snippet}
</Modal>

<Modal title="App password for {secret?.name ?? ''}" open={!!secret} width={480} onclose={() => (secret = null)}>
  {#if secret}
    <div class="notice warning"><Icon name="alert" size={18} /><span>Copy it now. It is shown only once.</span></div>
    <div class="secret"><code>{secret.token}</code><Copy value={secret.token} /></div>
    <p class="small muted">Enter it in the app instead of your password, with your email address as the user name.</p>
  {/if}
  {#snippet footer()}<button class="btn primary" onclick={() => (secret = null)}>Done</button>{/snippet}
</Modal>

<Modal title="Revoke {revoking?.name ?? ''}?" open={!!revoking} width={420} onclose={() => (revoking = null)}>
  <p>Apps using it are signed out and must be given a new password.</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (revoking = null)}>Cancel</button>
    <button class="btn danger" onclick={revoke}>Revoke</button>
  {/snippet}
</Modal>

<style>
  .scopes { border: 0; margin: 0; padding: 0; display: grid; gap: 8px; }
  .scopes legend { margin-bottom: 6px; }
  .scope { display: flex; gap: 10px; align-items: flex-start; cursor: pointer; }
  .scope input { margin-top: 4px; }
  .scope > span { display: grid; }
  .secret { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 9px; background: var(--surface); border: 1px solid var(--border); }
  .secret code { flex: 1; word-break: break-all; }
</style>
