<script>
  import { onMount } from 'svelte';
  import { get, post, patch, del } from '../lib/api.js';
  import { router } from '../lib/router.svelte.js';
  import { ui, onCreate } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { date } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Avatar from '../lib/Avatar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import Copy from '../lib/Copy.svelte';

  let { onChanged } = $props();
  let domains = $state([]);
  let transports = $state([]);
  let query = $state('');
  let detail = $state(null);
  let check = $state(null);
  let checking = $state(false);
  let form = $state({ mode: 'local', transport: '', catch_all: '' });
  let saving = $state(false);
  let creating = $state(false);
  let draft = $state({ name: '', mode: 'local', transport: '', dkim: true });
  let confirmDelete = $state(false);

  const selectedId = $derived(Number(router.parts[1]) || null);
  const filtered = $derived(domains.filter((d) => d.name.includes(query.toLowerCase())));

  async function load() {
    domains = await get('/admin/domains');
    const s = await get('/admin/settings').catch(() => null);
    transports = s?.settings.delivery.transports.filter((t) => t.kind !== 'direct') ?? [];
  }
  onMount(load);

  $effect(() => {
    const id = selectedId;
    detail = null;
    check = null;
    if (id) {
      get(`/admin/domains/${id}`).then((d) => {
        detail = d;
        form = { mode: d.mode, transport: d.transport, catch_all: d.catch_all };
        runCheck(id);
      }).catch((e) => toast.error(e));
    }
  });

  onCreate('domain', () => {
    draft = { name: '', mode: 'local', transport: transports[0]?.id ?? '', dkim: true };
    creating = true;
  });

  async function runCheck(id) {
    checking = true;
    try {
      check = await get(`/admin/domains/${id}/dns`);
    } catch {
      check = null;
    } finally {
      checking = false;
    }
  }

  function status(rec) {
    if (!check?.available) return null;
    const t = rec.type;
    if (t === 'MX') return check.mx;
    if (rec.name.includes('._domainkey.')) return check.dkim;
    if (rec.name.startsWith('_dmarc.')) return check.dmarc;
    if (t === 'TXT') return check.spf;
    return null;
  }

  async function save() {
    saving = true;
    try {
      detail = { ...detail, ...(await patch(`/admin/domains/${detail.id}`, form)) };
      toast.ok('Domain saved.');
      load();
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }

  async function setActive(v) {
    try {
      await patch(`/admin/domains/${detail.id}`, { active: v });
      toast.ok(v ? 'Domain enabled.' : 'Domain disabled; mail to it is refused.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }

  async function rotate() {
    if (!confirm('Generate a new DKIM key? Publish the new DNS record before relying on it; mail is signed with the new key right away.')) return;
    try {
      detail = await post(`/admin/domains/${detail.id}/dkim`);
      toast.ok('New DKIM key generated. Update your DNS.');
      runCheck(detail.id);
    } catch (e) {
      toast.error(e);
    }
  }

  async function create(e) {
    e?.preventDefault();
    try {
      const d = await post('/admin/domains', draft);
      creating = false;
      toast.ok(`${d.name} added.`);
      await load();
      onChanged?.();
      router.go(`/domains/${d.id}`);
    } catch (err) {
      toast.error(err);
    }
  }

  async function remove() {
    try {
      await del(`/admin/domains/${detail.id}`);
      confirmDelete = false;
      toast.ok('Domain deleted.');
      await load();
      router.go('/domains');
    } catch (e) {
      toast.error(e);
    }
  }

  const MODES = [
    ['local', 'Local mailboxes', 'Store mail in accounts on this server.'],
    ['relay', 'Forward to a server', 'Accept mail and pass it to another SMTP server (backup MX, gateway).'],
    ['webhook', 'Send to a webhook', 'POST each message to your application.'],
  ];
</script>

<div class="panes" class:has-detail={!!selectedId}>
  <section class="list-pane">
    <div class="list-head">
      <h1>Domains</h1><span class="count">{domains.length}</span><span class="spacer"></span>
      <button class="icon-btn" onclick={load} title="Refresh" aria-label="Refresh"><Icon name="refresh" /></button>
    </div>
    {#if domains.length > 6}
      <div class="list-search"><input class="input" placeholder="Search domains" bind:value={query} /></div>
    {/if}
    <div class="list">
      {#each filtered as d (d.id)}
        <button class="list-item" class:active={d.id === selectedId} onclick={() => router.go(`/domains/${d.id}`)}>
          {#if !d.active}<span class="dot bad"></span>{/if}
          <Avatar text={d.name.replace(/\..*/, '')} />
          <div class="main">
            <div class="top"><span class="name">{d.name}</span><span class="meta">{date(d.created_at)}</span></div>
            <div class="line2">{d.mode === 'local' ? `${d.accounts} account${d.accounts === 1 ? '' : 's'}` : d.mode === 'relay' ? 'Forwarded to a server' : 'Delivered to a webhook'}</div>
            <div class="line3">{d.has_dkim ? `DKIM · ${d.dkim_selector}` : 'No DKIM key'}{d.catch_all ? ' · catch-all' : ''}</div>
          </div>
        </button>
      {:else}
        <div class="empty"><Icon name="globe" size={30} /><h3>No domains yet</h3><button class="btn primary" onclick={() => ui.requestCreate('domain')}>Add a domain</button></div>
      {/each}
    </div>
  </section>

  <section class="detail-pane">
    {#if detail}
      <div class="toolbar">
        <button class="btn ghost only-narrow" onclick={() => router.go('/domains')}><Icon name="back" /> Domains</button>
        <button class="btn ghost" onclick={() => runCheck(detail.id)} disabled={checking}><Icon name="refresh" /><span class="label-text">{checking ? 'Checking…' : 'Check DNS'}</span></button>
        <button class="btn ghost" onclick={rotate}><Icon name="key" /><span class="label-text">New DKIM key</span></button>
        <span class="spacer"></span>
        <button class="icon-btn" onclick={() => (confirmDelete = true)} title="Delete domain" aria-label="Delete domain"><Icon name="trash" /></button>
      </div>
      <div class="detail fade-in"><div class="detail-inner">
        <h1>{detail.name}</h1>
        <div class="lead">
          <Avatar text={detail.name.replace(/\..*/, '')} size={48} />
          <div class="grow">
            <div class="row"><span class="chip accent">{MODES.find((m) => m[0] === detail.mode)?.[1]}</span>{#if !detail.active}<span class="chip danger">Disabled</span>{/if}</div>
            <div class="muted small">Added {date(detail.created_at)}</div>
          </div>
          <Toggle checked={detail.active} label="" onchange={setActive} />
        </div>

        <div class="card">
          <h3>Handling</h3>
          <p class="sub">What happens to mail sent to addresses at {detail.name}.</p>
          <div class="modes">
            {#each MODES as [id, title, sub]}
              <button class="mode" class:on={form.mode === id} onclick={() => (form.mode = id)}><strong>{title}</strong><span>{sub}</span></button>
            {/each}
          </div>
          {#if form.mode !== 'local'}
            <label class="field" style="margin-top:14px">
              <span>Transport</span>
              <select class="input" bind:value={form.transport}>
                <option value="">Choose…</option>
                {#each transports.filter((t) => (form.mode === 'webhook' ? t.kind === 'webhook' : t.kind === 'smtp')) as t}<option value={t.id}>{t.name || t.id}</option>{/each}
              </select>
              <span class="hint">Transports are set up under Delivery.</span>
            </label>
          {:else}
            <label class="field" style="margin-top:14px">
              <span>Catch-all</span>
              <input class="input" bind:value={form.catch_all} placeholder="Deliver unknown addresses to… (optional)" />
              <span class="hint">Mail to addresses that don’t exist goes here instead of being rejected. Leave empty to reject.</span>
            </label>
          {/if}
          <div class="row" style="margin-top:14px"><button class="btn primary" onclick={save} disabled={saving}>Save</button></div>
        </div>

        <div class="card">
          <div class="row"><h3>DNS records</h3><span class="spacer"></span>{#if check?.available === false}<span class="chip">DNS checks unavailable</span>{/if}</div>
          <p class="sub">Publish these at your DNS provider. Checks run against public DNS.</p>
          <div class="records">
            {#each detail.dns as r}
              {@const st = status(r)}
              <div class="rec">
                <div class="rec-head">
                  <span class="chip">{r.type}</span>
                  <span class="mono small name">{r.name}</span>
                  <span class="spacer"></span>
                  {#if st}
                    {#if st.ok}<span class="chip accent"><Icon name="check" size={12} stroke={2.6} /> Found</span>
                    {:else if st.found && (Array.isArray(st.found) ? st.found.length : true)}<span class="chip warning">Different</span>
                    {:else}<span class="chip danger">Missing</span>{/if}
                  {/if}
                </div>
                <div class="rec-val"><code>{r.value}</code><Copy value={r.zone_value ?? r.value} /></div>
                <div class="hint">{r.purpose}</div>
              </div>
            {/each}
          </div>
        </div>
      </div></div>
    {:else if !selectedId}
      <div class="empty"><Icon name="globe" size={34} /><h3>Select a domain</h3><p>See how its mail is handled and which DNS records to publish.</p></div>
    {/if}
  </section>
</div>

<Modal title="Add a domain" bind:open={creating}>
  <form id="new-domain" onsubmit={create} style="display:grid;gap:14px">
    <label class="field"><span>Domain name</span><input class="input" bind:value={draft.name} placeholder="example.org" autofocus required /></label>
    <label class="field"><span>Handling</span>
      <select class="input" bind:value={draft.mode}>{#each MODES as [id, t]}<option value={id}>{t}</option>{/each}</select>
    </label>
    {#if draft.mode !== 'local'}
      <label class="field"><span>Transport</span>
        <select class="input" bind:value={draft.transport}>{#each transports as t}<option value={t.id}>{t.name || t.id}</option>{/each}</select>
        {#if !transports.length}<span class="error-text">Create an SMTP or webhook transport under Delivery first.</span>{/if}
      </label>
    {/if}
    <Toggle bind:checked={draft.dkim} label="Generate a DKIM key" hint="Signs outgoing mail so receivers can verify it." />
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-domain">Add domain</button>
  {/snippet}
</Modal>

<Modal title="Delete domain?" bind:open={confirmDelete} width={420}>
  <p>Mail to <strong>{detail?.name}</strong> will be rejected. Accounts on the domain must be deleted first.</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (confirmDelete = false)}>Cancel</button>
    <button class="btn danger" onclick={remove}>Delete domain</button>
  {/snippet}
</Modal>

<style>
  .grow { flex: 1; display: grid; gap: 4px; }
  .modes { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
  .mode { display: grid; gap: 4px; text-align: left; padding: 12px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface); cursor: pointer; color: var(--muted); font-size: 13px; }
  .mode strong { color: var(--text); font-size: 14.5px; }
  .mode.on { border-color: var(--accent); background: var(--soft); }
  .records { display: grid; gap: 10px; }
  .rec { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--surface); display: grid; gap: 6px; }
  .rec-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .rec-head .name { word-break: break-all; }
  .rec-val { display: flex; align-items: flex-start; gap: 6px; }
  .rec-val code { flex: 1; word-break: break-all; background: var(--paper); border: 1px solid var(--border); border-radius: 7px; padding: 6px 8px; font-size: 12.5px; }
</style>
