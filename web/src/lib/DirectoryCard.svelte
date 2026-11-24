<script>
  // An account's groups (synced and set by hand) and contact details, for the contact directory.
  import { onMount } from 'svelte';
  import { get, put } from './api.js';
  import { toast } from './toast.svelte.js';
  import { link } from './router.svelte.js';

  let { id } = $props();
  let groups = $state([]);
  let profile = $state({});
  let manual = $state('');
  let saving = $state(false);
  const SOURCE = { oidc: 'single sign-on', ldap: 'LDAP', manual: 'set here' };
  const LABEL = { phone: 'Phone', given_name: 'Given name', family_name: 'Family name', nickname: 'Nickname', photo: 'Photo', address: 'Address', website: 'Website', birthday: 'Birthday', organization: 'Organization', title: 'Title', department: 'Department' };

  function show(g) {
    groups = g.groups;
    manual = g.groups.filter((x) => x.source === 'manual').map((x) => x.name).join(', ');
  }
  onMount(() => {
    get(`/admin/accounts/${id}/groups`).then(show).catch(() => {});
    get(`/admin/accounts/${id}/profile`).then((p) => (profile = p.profile ?? {})).catch(() => {});
  });

  async function save(e) {
    e?.preventDefault();
    saving = true;
    try {
      show(await put(`/admin/accounts/${id}/groups`, { groups: manual.split(',').map((x) => x.trim()).filter(Boolean) }));
      toast.ok('Groups saved.');
    } catch (err) {
      toast.error(err);
    } finally {
      saving = false;
    }
  }
  const synced = $derived(groups.filter((g) => g.source !== 'manual'));
</script>

<div class="card">
  <div class="row"><h3>Groups &amp; contact details</h3><span class="spacer"></span><a href="/dav" use:link class="small">Directory rules</a></div>
  <p class="sub">Used by the contact directory. Synced values update at each sign-in.</p>
  {#if synced.length}
    <div class="chips">{#each synced as g}<span class="chip" title="From {SOURCE[g.source] ?? g.source}">{g.name}<span class="muted"> · {SOURCE[g.source] ?? g.source}</span></span>{/each}</div>
  {:else}<p class="muted small">No groups from single sign-on or LDAP yet.</p>{/if}
  <form class="row" style="gap:8px;margin-top:10px" onsubmit={save}>
    <input class="input" bind:value={manual} placeholder="Extra groups, comma-separated" aria-label="Groups set here" />
    <button class="btn" type="submit" disabled={saving}>Save groups</button>
  </form>
  {#if Object.keys(profile).length}
    <dl class="details">
      {#each Object.entries(profile) as [k, v]}<dt>{LABEL[k] ?? k}</dt><dd>{v.join(', ')}</dd>{/each}
    </dl>
  {:else}<p class="muted small" style="margin-top:10px">No contact details synced yet.</p>{/if}
</div>

<style>
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
  .details { display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 4px 12px; margin: 12px 0 0; font-size: 13px; }
  .details dt { color: var(--muted); }
  .details dd { margin: 0; word-break: break-word; }
</style>
