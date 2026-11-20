<script>
  import { onMount } from 'svelte';
  import { get, post, patch, del } from '../lib/api.js';
  import { router } from '../lib/router.svelte.js';
  import { onCreate } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { date } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Avatar from '../lib/Avatar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Toggle from '../lib/Toggle.svelte';

  let { onChanged } = $props();
  let aliases = $state([]);
  let domains = $state([]);
  let query = $state('');
  let form = $state({ destination: '', active: true });
  let creating = $state(false);
  let draft = $state({});

  const selectedId = $derived(Number(router.parts[1]) || null);
  const detail = $derived(aliases.find((a) => a.id === selectedId) ?? null);
  const filtered = $derived(aliases.filter((a) => (a.source + a.destination).toLowerCase().includes(query.toLowerCase())));
  const localDomains = $derived(domains.filter((d) => d.mode === 'local'));

  async function load() {
    [aliases, domains] = await Promise.all([get('/admin/aliases'), get('/admin/domains')]);
  }
  onMount(load);

  $effect(() => {
    if (detail) form = { destination: detail.destination, active: detail.active };
  });

  onCreate('alias', () => {
    draft = { local: '', domain: localDomains[0]?.name ?? '', catchAll: false, destination: '' };
    creating = true;
  });

  async function create(e) {
    e?.preventDefault();
    const source = draft.catchAll ? `@${draft.domain}` : `${draft.local.trim()}@${draft.domain}`;
    try {
      const { id } = await post('/admin/aliases', { source, destination: draft.destination });
      creating = false;
      toast.ok(`${source} created.`);
      await load();
      onChanged?.();
      router.go(`/aliases/${id}`);
    } catch (err) {
      toast.error(err);
    }
  }

  async function save() {
    try {
      await patch(`/admin/aliases/${detail.id}`, form);
      toast.ok('Alias saved.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }

  async function remove() {
    if (!confirm(`Delete ${detail.source}? Mail to it will be rejected.`)) return;
    try {
      await del(`/admin/aliases/${detail.id}`);
      toast.ok('Alias deleted.');
      await load();
      router.go('/aliases');
    } catch (e) {
      toast.error(e);
    }
  }

  const dests = (s) => s.split(/[,\s]+/).filter(Boolean);
</script>

<div class="panes" class:has-detail={!!selectedId}>
  <section class="list-pane">
    <div class="list-head">
      <h1>Aliases</h1><span class="count">{aliases.length}</span><span class="spacer"></span>
      <button class="icon-btn" onclick={load} title="Refresh" aria-label="Refresh"><Icon name="refresh" /></button>
    </div>
    <div class="list-search"><input class="input" placeholder="Search aliases" bind:value={query} /></div>
    <div class="list">
      {#each filtered as a (a.id)}
        <button class="list-item" class:active={a.id === selectedId} onclick={() => router.go(`/aliases/${a.id}`)}>
          {#if !a.active}<span class="dot bad"></span>{/if}
          <Avatar text={a.source.startsWith('@') ? '*' : a.source} />
          <div class="main">
            <div class="top"><span class="name">{a.source.startsWith('@') ? `Catch-all ${a.source}` : a.source}</span><span class="meta">{date(a.created_at)}</span></div>
            <div class="line3"><Icon name="forward" size={13} /> {dests(a.destination).join(', ')}</div>
          </div>
        </button>
      {:else}
        <div class="empty"><Icon name="at" size={30} /><h3>No aliases</h3><p>Aliases deliver one address to one or more mailboxes, local or external.</p></div>
      {/each}
    </div>
  </section>

  <section class="detail-pane">
    {#if detail}
      <div class="toolbar">
        <button class="btn ghost only-narrow" onclick={() => router.go('/aliases')}><Icon name="back" /> Aliases</button>
        <span class="spacer"></span>
        <button class="icon-btn" onclick={remove} title="Delete alias" aria-label="Delete alias"><Icon name="trash" /></button>
      </div>
      <div class="detail fade-in"><div class="detail-inner">
        <h1>{detail.source}</h1>
        <div class="lead"><Avatar text={detail.source} size={48} /><div class="muted">{detail.source.startsWith('@') ? 'Catch-all: receives mail for any address on the domain that doesn’t exist.' : 'Mail to this address is delivered to the destinations below.'}</div></div>
        <div class="card">
          <h3>Destinations</h3>
          <p class="sub">One address per line or comma-separated. External addresses are forwarded with SRS so SPF still passes.</p>
          <textarea class="input mono" rows="4" bind:value={form.destination}></textarea>
          <Toggle bind:checked={form.active} label="Active" />
          <div class="row" style="margin-top:10px"><button class="btn primary" onclick={save}>Save</button></div>
        </div>
      </div></div>
    {:else if !selectedId}
      <div class="empty"><Icon name="at" size={34} /><h3>Select an alias</h3></div>
    {/if}
  </section>
</div>

<Modal title="New alias" bind:open={creating}>
  <form id="new-alias" onsubmit={create} style="display:grid;gap:14px">
    <Toggle bind:checked={draft.catchAll} label="Catch-all for a domain" hint="Receives mail for every address on the domain that doesn’t exist." />
    <label class="field"><span>Alias address</span>
      <div class="addr">
        {#if !draft.catchAll}<input class="input" bind:value={draft.local} placeholder="sales" required autofocus />{/if}
        <span class="muted">@</span>
        <select class="input" bind:value={draft.domain}>{#each localDomains as d}<option>{d.name}</option>{/each}</select>
      </div>
    </label>
    <label class="field"><span>Deliver to</span><textarea class="input mono" rows="3" bind:value={draft.destination} placeholder="alex@example.com" required></textarea></label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-alias">Create alias</button>
  {/snippet}
</Modal>

<style>
  .addr { display: flex; align-items: center; gap: 8px; }
  .addr .input { flex: 1; }
  .line3 :global(svg) { vertical-align: -2px; }
</style>
