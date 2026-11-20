<script>
  import { onMount } from 'svelte';
  import { get, post, patch, del } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { ago } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import Modal from '../lib/Modal.svelte';
  import Copy from '../lib/Copy.svelte';

  const s = liveSettings();
  const relay = $derived(s.data?.relay);
  let peers = $state([]);
  let loaded = $state(false);
  let creating = $state(false);
  let draft = $state({ name: '', domains: '' });
  let issued = $state(null);
  let editing = $state(null);
  let removing = $state(null);

  async function load() {
    try {
      peers = await get('/admin/relay/peers');
    } catch (e) {
      toast.error(e);
    } finally {
      loaded = true;
    }
  }
  onMount(load);

  const split = (v) => v.split(/[\n,\s]+/).map((x) => x.trim()).filter(Boolean);

  async function create(e) {
    e?.preventDefault();
    try {
      const r = await post('/admin/relay/peers', { name: draft.name.trim(), domains: split(draft.domains) });
      creating = false;
      issued = r;
      load();
      // The server switches accept_downstream on; mirror it without losing unsaved edits.
      if (!s.dirty) s.load();
      else relay.accept_downstream = true;
    } catch (err) {
      toast.error(err);
    }
  }
  async function setActive(p, active) {
    try {
      await patch(`/admin/relay/peers/${encodeURIComponent(p.name)}`, { active });
      toast.ok(active ? `${p.name} can connect.` : `${p.name} is paused; its mail is held.`);
      load();
    } catch (e) {
      toast.error(e);
    }
  }
  async function saveDomains(e) {
    e?.preventDefault();
    try {
      await patch(`/admin/relay/peers/${encodeURIComponent(editing.name)}`, { domains: split(editing.domains) });
      toast.ok('Domains updated.');
      editing = null;
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  async function remove() {
    try {
      const r = await del(`/admin/relay/peers/${encodeURIComponent(removing.name)}`);
      toast.ok(r.note || 'Peer removed.');
      removing = null;
      load();
    } catch (e) {
      toast.error(e);
    }
  }
  function toggleUpstream(on) {
    if (!relay.upstream) relay.upstream = { enabled: true, url: '', token: null, outbound: true, inbound: true, insecure: false };
    else relay.upstream.enabled = on;
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Relay link</h1><p class="muted" style="margin:6px 0 0">Connect Picacho servers over HTTPS, so a server that can't use port 25 sends and receives through one that can.</p></div></div>

  {#if relay}
    <div class="card">
      <h3>Use an upstream server</h3>
      <p class="sub">This server is the downstream: it sends mail through the upstream and collects mail the upstream received for its domains.</p>
      <Toggle checked={!!relay.upstream?.enabled} label="Relay through another Picacho server" onchange={toggleUpstream} />
      {#if relay.upstream?.enabled}
        <div class="grid2" style="margin-top:10px">
          <label class="field"><span>Upstream URL</span><input class="input mono" bind:value={relay.upstream.url} placeholder="https://mx.example.net:8080" /></label>
          <label class="field"><span>Relay token</span><input class="input mono" type="password" autocomplete="new-password" value={relay.upstream.token ?? ''} oninput={(e) => (relay.upstream.token = e.target.value || null)} placeholder="pmrl_…" /><span class="hint">Issued on the upstream's Relay link page.</span></label>
        </div>
        <Toggle bind:checked={relay.upstream.outbound} label="Send outgoing mail through the upstream" />
        <Toggle bind:checked={relay.upstream.inbound} label="Collect incoming mail from the upstream" />
        <Toggle bind:checked={relay.upstream.insecure} label="Accept an invalid upstream certificate" hint="For testing only." />
      {/if}
    </div>
    <SaveBar {s} />
  {/if}

  <div class="card">
    <div class="row"><h3>Downstream servers</h3><span class="spacer"></span>
      <button class="btn small" onclick={() => { draft = { name: '', domains: '' }; creating = true; }}><Icon name="plus" size={15} /> Add server</button>
    </div>
    <p class="sub">This server is the upstream: it accepts mail from these servers and holds mail for their domains until they collect it.</p>
    {#if relay}<Toggle bind:checked={relay.accept_downstream} label="Accept downstream servers" hint="Turned on automatically when you add one." />{/if}
    {#if peers.length}
      <table class="table" style="margin-top:10px">
        <thead><tr><th>Server</th><th>Domains</th><th>Held</th><th>Last seen</th><th>Active</th><th></th></tr></thead>
        <tbody>
          {#each peers as p (p.id)}
            <tr>
              <td><strong>{p.name}</strong><div class="muted small mono">{p.prefix}…</div></td>
              <td>{#each p.domains as d}<span class="chip mono">{d}</span> {:else}<span class="muted">—</span>{/each}</td>
              <td>{p.held ?? 0}</td>
              <td class="muted">{ago(p.last_seen)}</td>
              <td><Toggle checked={p.active} onchange={(v) => setActive(p, v)} /></td>
              <td class="actions">
                <button class="btn small" onclick={() => (editing = { name: p.name, domains: p.domains.join('\n') })}>Domains</button>
                <button class="icon-btn" onclick={() => (removing = p)} aria-label="Remove {p.name}" title="Remove"><Icon name="trash" size={16} /></button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else if loaded}
      <p class="muted small" style="margin-top:10px">No downstream servers.</p>
    {/if}
  </div>
</div></div>

<Modal title="Add downstream server" bind:open={creating} width={480}>
  <form id="new-peer" onsubmit={create} style="display:grid;gap:14px">
    <label class="field"><span>Name</span><input class="input" bind:value={draft.name} placeholder="office" pattern="[A-Za-z0-9_-]+" required autofocus /><span class="hint">Letters, digits, - and _.</span></label>
    <label class="field"><span>Its domains</span><textarea class="input mono" rows="3" bind:value={draft.domains} placeholder="office.example.com"></textarea><span class="hint">This server receives mail for them and holds it for pickup. Point their MX records here.</span></label>
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-peer">Add and issue token</button>
  {/snippet}
</Modal>

<Modal title="Relay token" open={!!issued} width={520} onclose={() => (issued = null)}>
  {#if issued}
    <div class="notice warning"><Icon name="alert" size={18} /><span>Copy this token now. It is shown only once.</span></div>
    <div class="secret"><code>{issued.token}</code><Copy value={issued.token} /></div>
    <p class="small muted">On <strong>{issued.peer.name}</strong>, open Relay link, turn on <em>Relay through another Picacho server</em>, and enter <span class="mono">{location.origin}</span> with this token.</p>
  {/if}
  {#snippet footer()}<button class="btn primary" onclick={() => (issued = null)}>Done</button>{/snippet}
</Modal>

<Modal title="Domains for {editing?.name ?? ''}" open={!!editing} width={460} onclose={() => (editing = null)}>
  {#if editing}
    <form id="peer-domains" onsubmit={saveDomains}>
      <label class="field"><span>Domains (one per line)</span><textarea class="input mono" rows="4" bind:value={editing.domains}></textarea></label>
    </form>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (editing = null)}>Cancel</button>
    <button class="btn primary" type="submit" form="peer-domains">Save</button>
  {/snippet}
</Modal>

<Modal title="Remove {removing?.name ?? ''}?" open={!!removing} width={440} onclose={() => (removing = null)}>
  <p>Its token stops working{removing?.held ? ` and ${removing.held} held message${removing.held === 1 ? '' : 's'} won't be collected` : ''}. Domains that pointed at it stay; change or delete them under Domains.</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (removing = null)}>Cancel</button>
    <button class="btn danger" onclick={remove}>Remove server</button>
  {/snippet}
</Modal>

<style>
  .actions { display: flex; gap: 6px; justify-content: flex-end; align-items: center; }
  .secret { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 9px; background: var(--surface); border: 1px solid var(--border); }
  .secret code { flex: 1; word-break: break-all; }
</style>
