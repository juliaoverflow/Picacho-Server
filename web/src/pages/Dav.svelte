<script>
  import { onMount } from 'svelte';
  import { get, post, patch, del } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { onCreate } from '../lib/ui.svelte.js';
  import { bytes, date } from '../lib/format.js';
  import { link } from '../lib/router.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Copy from '../lib/Copy.svelte';

  const s = liveSettings();
  const dav = $derived(s.data?.dav);
  let principals = $state([]);
  let accounts = $state([]);
  let server = $state(null);
  let loaded = $state(false);
  let query = $state('');
  let creating = $state(false);
  let draft = $state({});
  let editing = $state(null);
  let removing = $state(null);

  async function load() {
    try {
      [principals, accounts] = await Promise.all([get('/admin/dav/principals'), get('/admin/accounts').catch(() => [])]);
    } catch (e) {
      toast.error(e);
    } finally {
      loaded = true;
    }
  }
  onMount(() => {
    load();
    get('/admin/server').then((r) => (server = r)).catch(() => {});
  });

  const root = $derived(server?.dav?.root ?? `${location.origin}/dav/`);
  const linkedIds = $derived(new Set(principals.map((p) => p.account_id).filter(Boolean)));
  const free = $derived(accounts.filter((a) => !linkedIds.has(a.id)));
  const filtered = $derived(principals.filter((p) => `${p.username} ${p.display_name} ${p.email} ${p.linked_account ?? ''}`.toLowerCase().includes(query.toLowerCase())));
  const mb = (b) => Math.round(b / 1048576);

  function startCreate() {
    draft = { kind: 'standalone', username: '', password: '', display_name: '', email: '', account: free[0]?.email ?? '', own_password: false, quota_mb: dav?.default_quota_mb ?? '' };
    creating = true;
  }
  onCreate('dav', startCreate);

  async function create(e) {
    e?.preventDefault();
    const body = { quota_mb: draft.quota_mb === '' ? undefined : Number(draft.quota_mb) };
    if (draft.kind === 'linked') {
      body.account = draft.account;
      if (draft.own_password && draft.password) body.password = draft.password;
    } else {
      Object.assign(body, { username: draft.username.trim(), password: draft.password, display_name: draft.display_name, email: draft.email });
    }
    try {
      const p = await post('/admin/dav/principals', body);
      creating = false;
      toast.ok(`${p.username} can now use calendars, contacts and files.`);
      load();
    } catch (err) {
      toast.error(err);
    }
  }

  function startEdit(p) {
    editing = { p, display_name: p.display_name, email: p.email, quota_mb: mb(p.quota_bytes), active: p.active, password: '', clear_password: false, account: p.linked_account ?? '' };
  }
  async function saveEdit(e) {
    e?.preventDefault();
    const x = editing;
    const body = { display_name: x.display_name, email: x.email, quota_mb: Number(x.quota_mb) || 0, active: x.active };
    if (x.password) body.password = x.password;
    else if (x.clear_password) body.clear_password = true;
    if (x.account !== (x.p.linked_account ?? '')) body.account = x.account;
    try {
      await patch(`/admin/dav/principals/${encodeURIComponent(x.p.username)}`, body);
      toast.ok('Saved.');
      editing = null;
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  async function remove() {
    try {
      const r = await del(`/admin/dav/principals/${encodeURIComponent(removing.username)}`);
      toast.ok(`${removing.username} deleted with ${r.objects} item${r.objects === 1 ? '' : 's'}. Stored files are removed by the next sweep.`);
      removing = null;
      load();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head">
    <div><h1>Calendars &amp; contacts</h1><p class="muted" style="margin:6px 0 0">CalDAV, CardDAV and WebDAV files. Mail accounts can share their sign-in, or you can add DAV-only users.</p></div>
    <span class="spacer"></span>
    <button class="btn primary" onclick={startCreate}><Icon name="plus" size={16} /> New DAV user</button>
  </div>

  <div class="card">
    <h3>Addresses for apps</h3>
    <p class="sub">Most apps only need the server address and discover the rest. Use the full URLs when an app asks for them.</p>
    <div class="urls">
      {#each [['Server', root], ['CalDAV', server?.dav?.caldav ?? `${location.origin}/.well-known/caldav`], ['CardDAV', server?.dav?.carddav ?? `${location.origin}/.well-known/carddav`]] as [l, u]}
        <span class="muted small">{l}</span><code class="truncate">{u}</code><Copy value={u} />
      {/each}
    </div>
  </div>

  <div class="card">
    <div class="row"><h3>Users</h3><span class="count">{principals.length}</span><span class="spacer"></span><input class="input" style="max-width:240px" placeholder="Search" bind:value={query} /></div>
    {#if filtered.length}
      <table class="table" style="margin-top:10px">
        <thead><tr><th>User</th><th>Sign-in</th><th>Files</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {#each filtered as p (p.id)}
            <tr class:off={!p.active}>
              <td><strong class="mono">{p.username}</strong>{#if !p.active} <span class="chip danger">Disabled</span>{/if}<div class="muted small">{p.display_name}{p.email && p.email !== p.username ? ` · ${p.email}` : ''}</div></td>
              <td>
                {#if p.account_id}<a href="/accounts/{p.account_id}" use:link class="chip accent">Mail account</a>{#if p.has_password} <span class="chip">+ DAV password</span>{/if}
                {:else}<span class="chip">Standalone</span>{/if}
              </td>
              <td>{bytes(p.used_bytes)}{p.quota_bytes ? ` of ${bytes(p.quota_bytes)}` : ''}</td>
              <td class="muted">{date(p.created_at)}</td>
              <td class="actions">
                <Copy value="{root}calendars/{p.username}/" label="Copy CalDAV URL" />
                <button class="btn small" onclick={() => startEdit(p)}>Edit</button>
                <button class="icon-btn" onclick={() => (removing = p)} aria-label="Delete {p.username}" title="Delete"><Icon name="trash" size={16} /></button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else if loaded}
      <p class="muted small" style="margin-top:10px">{query ? 'No matches.' : 'No DAV users yet.'}</p>
    {/if}
  </div>

  {#if dav}
    <div class="card">
      <h3>Settings</h3>
      <Toggle bind:checked={dav.enabled} label="Serve calendars, contacts and files" hint="Turn off to answer /dav/ with 404." />
      <Toggle bind:checked={dav.mail_accounts} label="Every mail account gets calendars and contacts" hint="Created on first use with the mail password or an app password." disabled={!dav.enabled} />
      <Toggle bind:checked={dav.create_defaults} label="Create a default calendar and address book" disabled={!dav.enabled} />
      <div class="grid2" style="margin-top:10px">
        <label class="field"><span>Default file quota (MB)</span><input class="input" type="number" min="0" bind:value={dav.default_quota_mb} /><span class="hint">0 means unlimited.</span></label>
        <label class="field"><span>Largest uploaded file (MB)</span><input class="input" type="number" min="1" value={mb(dav.max_resource_bytes)} onchange={(e) => (dav.max_resource_bytes = Math.max(1, Number(e.target.value)) * 1048576)} /></label>
      </div>
    </div>
    <SaveBar {s} />
  {/if}
</div></div>

<Modal title="New DAV user" bind:open={creating} width={520}>
  <form id="new-principal" onsubmit={create} style="display:grid;gap:14px">
    <div class="segmented">
      <button type="button" class:on={draft.kind === 'standalone'} onclick={() => (draft.kind = 'standalone')}>DAV only</button>
      <button type="button" class:on={draft.kind === 'linked'} onclick={() => (draft.kind = 'linked')}>For a mail account</button>
    </div>
    {#if draft.kind === 'linked'}
      <label class="field"><span>Mail account</span>
        <select class="input" bind:value={draft.account} required>{#each free as a}<option value={a.email}>{a.email}</option>{/each}</select>
        {#if !free.length}<span class="hint">Every account already has calendars and contacts.</span>{/if}
      </label>
      <Toggle bind:checked={draft.own_password} label="Give it a separate DAV password" hint="Otherwise apps sign in with the mail password or an app password." />
      {#if draft.own_password}<label class="field"><span>DAV password</span><input class="input" type="password" autocomplete="new-password" bind:value={draft.password} required /></label>{/if}
    {:else}
      <div class="grid2">
        <label class="field"><span>User name</span><input class="input mono" bind:value={draft.username} placeholder="frontdesk" required autofocus /><span class="hint">Not an email address on this server.</span></label>
        <label class="field"><span>Password</span><input class="input" type="password" autocomplete="new-password" bind:value={draft.password} required /></label>
        <label class="field"><span>Display name</span><input class="input" bind:value={draft.display_name} placeholder="Front desk" /></label>
        <label class="field"><span>Email (for invitations)</span><input class="input" type="email" bind:value={draft.email} placeholder="Optional" /></label>
      </div>
    {/if}
    <label class="field" style="max-width:220px"><span>File quota (MB)</span><input class="input" type="number" min="0" bind:value={draft.quota_mb} /></label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-principal" disabled={draft.kind === 'linked' && !free.length}>Create</button>
  {/snippet}
</Modal>

<Modal title="Edit {editing?.p.username ?? ''}" open={!!editing} width={520} onclose={() => (editing = null)}>
  {#if editing}
    <form id="edit-principal" onsubmit={saveEdit} style="display:grid;gap:14px">
      <div class="grid2">
        <label class="field"><span>Display name</span><input class="input" bind:value={editing.display_name} /></label>
        <label class="field"><span>Email</span><input class="input" type="email" bind:value={editing.email} /></label>
        <label class="field"><span>File quota (MB)</span><input class="input" type="number" min="0" bind:value={editing.quota_mb} /></label>
        <label class="field"><span>Linked mail account</span>
          <select class="input" bind:value={editing.account}>
            <option value="">None (DAV only)</option>
            {#if editing.p.linked_account}<option value={editing.p.linked_account}>{editing.p.linked_account}</option>{/if}
            {#each free as a}<option value={a.email}>{a.email}</option>{/each}
          </select>
        </label>
      </div>
      <label class="field"><span>{editing.p.has_password ? 'New DAV password' : 'DAV password'}</span><input class="input" type="password" autocomplete="new-password" bind:value={editing.password} placeholder={editing.p.has_password ? 'Unchanged' : editing.account ? 'None: uses the mail password' : 'Required'} /></label>
      {#if editing.p.has_password && editing.account && !editing.password}
        <Toggle bind:checked={editing.clear_password} label="Remove the separate DAV password" hint="Apps then sign in with the mail password or an app password." />
      {/if}
      <Toggle bind:checked={editing.active} label="Active" />
    </form>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (editing = null)}>Cancel</button>
    <button class="btn primary" type="submit" form="edit-principal">Save</button>
  {/snippet}
</Modal>

<Modal title="Delete {removing?.username ?? ''}?" open={!!removing} width={440} onclose={() => (removing = null)}>
  <p>This deletes its calendars, address books and files. It can’t be undone.{removing?.account_id ? ' The mail account is not affected.' : ''}</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (removing = null)}>Cancel</button>
    <button class="btn danger" onclick={remove}>Delete</button>
  {/snippet}
</Modal>

<style>
  .urls { display: grid; grid-template-columns: 80px minmax(0, 1fr) auto; gap: 6px 12px; align-items: center; }
  .actions { display: flex; gap: 6px; justify-content: flex-end; align-items: center; }
  tr.off td { opacity: 0.7; }
</style>
