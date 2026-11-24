<script>
  import { liveSettings } from '../lib/settings.svelte.js';
  import { post } from '../lib/api.js';
  import { toast } from '../lib/toast.svelte.js';
  import { RELAY_PRESETS } from '../lib/presets.js';
  import Icon from '../lib/Icon.svelte';
  import Modal from '../lib/Modal.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';

  const s = liveSettings();
  let editing = $state(false);
  let editIndex = $state(-1);
  let t = $state({});
  let testResult = $state(null);
  let testing = $state(false);
  let testTo = $state('');
  let sending = $state(false);

  const d = $derived(s.data?.delivery);
  const KIND = { direct: 'Direct MX', smtp: 'SMTP relay', webhook: 'Webhook', cloudflare: 'Cloudflare Email Service' };

  function blank(kind = 'smtp') {
    if (kind === 'cloudflare') return { id: 'cloudflare', name: 'Cloudflare Email Service', kind, host: 'smtp.mx.cloudflare.net', port: 465, tls: 'tls', username: 'api_token', password: '', url: '', secret: '', format: 'json' };
    return { id: '', name: '', kind, host: '', port: kind === 'smtp' ? 587 : 0, tls: 'starttls', username: '', password: '', url: '', secret: '', format: 'json' };
  }
  function openNew(kind) {
    t = blank(kind);
    editIndex = -1;
    testResult = null;
    editing = true;
  }
  function openEdit(i) {
    t = { ...blank(), ...d.transports[i] };
    editIndex = i;
    testResult = null;
    editing = true;
  }
  function applyPreset(p) {
    t = { ...t, kind: p.kind ?? t.kind, host: p.host, port: p.port, tls: p.tls, username: p.username ?? t.username, name: t.name || p.name, id: t.id || p.id };
  }
  function slug(v) {
    return v.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
  }
  async function commit(e) {
    e?.preventDefault();
    const clean = { ...t, id: t.id || slug(t.name) || `t${Date.now()}`, port: Number(t.port) || 0 };
    for (const k of ['username', 'password', 'url', 'secret']) if (clean[k] === '') clean[k] = null;
    if (editIndex >= 0) d.transports[editIndex] = clean;
    else d.transports.push(clean);
    if (await s.save('Transport saved.')) editing = false;
    else if (editIndex < 0) d.transports.pop();
  }
  async function removeTransport(i) {
    const id = d.transports[i].id;
    if (d.routes.some((r) => r.transport === id)) return toast.error('Remove the routing rules that use this transport first.');
    d.transports.splice(i, 1);
    await s.save('Transport removed.');
  }
  async function test() {
    testing = true;
    testResult = null;
    try {
      testResult = await post('/admin/transports/test', { transport: { ...t, port: Number(t.port) || 0 } });
    } catch (e) {
      testResult = { ok: false, message: e.message };
    } finally {
      testing = false;
    }
  }
  function addRoute() {
    d.routes.push({ pattern: '*', transport: d.transports.find((x) => x.kind !== 'webhook')?.id ?? '' });
  }
  function move(i, dir) {
    const r = d.routes;
    const j = i + dir;
    if (j < 0 || j >= r.length) return;
    [r[i], r[j]] = [r[j], r[i]];
  }
  async function sendTest(e) {
    e.preventDefault();
    sending = true;
    try {
      await post('/admin/test-message', { to: testTo });
      toast.ok(`Test message sent to ${testTo}. Watch the queue for its status.`);
    } catch (err) {
      toast.error(err);
    } finally {
      sending = false;
    }
  }
  let retryText = $state('');
  $effect(() => {
    if (d) retryText = d.retry_minutes.join(', ');
  });
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Routing &amp; relays</h1><p class="muted" style="margin:6px 0 0">How outgoing mail leaves this server: direct delivery, SMTP relays, webhooks and per-domain routes.</p></div></div>
  {#if d}
    <div class="card">
      <div class="row">
        <div><h3>Transports</h3><p class="sub">Ways mail can leave this server. Without a matching route, mail is delivered directly to the recipient’s MX.</p></div>
        <span class="spacer"></span>
        <button class="btn small" onclick={() => openNew('smtp')}><Icon name="plus" size={16} /> SMTP relay</button>
        <button class="btn small" onclick={() => openNew('webhook')}><Icon name="link" size={16} /> Webhook</button>
        <button class="btn small" onclick={() => openNew('cloudflare')}><Icon name="plus" size={16} /> Cloudflare</button>
      </div>
      <div class="transports">
        <div class="tr builtin"><Icon name="send" /><div class="grow"><strong>Direct MX</strong><span class="muted small">Built in · looks up each domain’s mail servers</span></div><button class="btn small" onclick={() => { t = blank('direct'); t.id = 'direct'; test(); editIndex = -2; editing = true; }}>Test</button></div>
        {#each d.transports as tr, i}
          <div class="tr">
            <Icon name={tr.kind === 'webhook' ? 'link' : 'route'} />
            <div class="grow"><strong>{tr.name || tr.id}</strong><span class="muted small">{KIND[tr.kind]} · {tr.kind === 'webhook' ? tr.url : `${tr.host}:${tr.port}`} · id <code>{tr.id}</code></span></div>
            <button class="btn small" onclick={() => openEdit(i)}>Edit</button>
            <button class="icon-btn" onclick={() => removeTransport(i)} aria-label="Remove"><Icon name="trash" size={16} /></button>
          </div>
        {/each}
      </div>
    </div>

    <div class="card">
      <div class="row"><div><h3>Routing</h3><p class="sub">Rules are checked top to bottom by recipient domain. <code>*</code> matches everything, <code>*.example.com</code> matches subdomains.</p></div><span class="spacer"></span><button class="btn small" onclick={addRoute} disabled={!d.transports.length}><Icon name="plus" size={16} /> Add rule</button></div>
      {#if d.routes.length}
        <table class="table">
          <thead><tr><th>Recipient domain</th><th>Send via</th><th></th></tr></thead>
          <tbody>
            {#each d.routes as r, i}
              <tr>
                <td><input class="input mono" bind:value={r.pattern} /></td>
                <td><select class="input" bind:value={r.transport}>{#each d.transports as tr}<option value={tr.id}>{tr.name || tr.id}</option>{/each}</select></td>
                <td class="nowrap">
                  <button class="icon-btn" onclick={() => move(i, -1)} aria-label="Move up"><Icon name="up" size={16} /></button>
                  <button class="icon-btn" onclick={() => move(i, 1)} aria-label="Move down"><Icon name="down" size={16} /></button>
                  <button class="icon-btn" onclick={() => d.routes.splice(i, 1)} aria-label="Remove"><Icon name="trash" size={16} /></button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted small">No rules: all outgoing mail uses direct MX delivery.</p>
      {/if}
    </div>

    <div class="card">
      <h3>Retries and bounces</h3>
      <div class="grid2" style="margin-top:12px">
        <label class="field"><span>Retry schedule (minutes)</span>
          <input class="input mono" bind:value={retryText} onchange={() => (d.retry_minutes = retryText.split(/[,\s]+/).map(Number).filter((n) => n > 0))} />
          <span class="hint">Wait between attempts; the last value repeats.</span>
        </label>
        <label class="field"><span>Give up after (hours)</span><input class="input" type="number" min="1" bind:value={d.max_queue_hours} /></label>
        <label class="field"><span>Parallel deliveries</span><input class="input" type="number" min="1" max="256" bind:value={d.concurrency} /><span class="hint">Applies after a restart.</span></label>
      </div>
      <Toggle bind:checked={d.send_bounces} label="Send bounce messages" hint="Tell senders when their mail can’t be delivered." />
      <Toggle bind:checked={d.dkim_sign} label="DKIM-sign outgoing mail" hint="Uses each domain’s key (see Domains)." />
      <Toggle bind:checked={d.require_tls} label="Require TLS for direct delivery" hint="Refuse to send to servers without valid STARTTLS. Stricter, but some servers will be unreachable." />
    </div>

    <form class="card" onsubmit={sendTest}>
      <h3>Send a test message</h3>
      <p class="sub">Delivers a short message through your routing rules, signed with DKIM.</p>
      <div class="row"><input class="input" type="email" bind:value={testTo} placeholder="you@gmail.com" required style="max-width:320px" /><button class="btn" disabled={sending}><Icon name="send" size={16} /> Send</button></div>
    </form>
    <SaveBar {s} />
  {/if}
</div></div>

<Modal title={editIndex === -2 ? 'Direct delivery' : editIndex >= 0 ? 'Edit transport' : t.kind === 'webhook' ? 'New webhook' : t.kind === 'cloudflare' ? 'Cloudflare Email Service' : 'New SMTP relay'} bind:open={editing} width={560}>
  {#if editIndex === -2}
    <p class="muted">Checks DNS and whether this machine can open outbound connections on port 25.</p>
  {:else}
    <form id="transport" onsubmit={commit} style="display:grid;gap:14px">
      <div class="grid2">
        <label class="field"><span>Name</span><input class="input" bind:value={t.name} placeholder="Amazon SES" required /></label>
        <label class="field"><span>ID</span><input class="input mono" bind:value={t.id} placeholder={slug(t.name || '') || 'relay'} disabled={editIndex >= 0} /><span class="hint">Used in routes and domain settings.</span></label>
      </div>
      {#if t.kind === 'smtp'}
        <div class="presets">{#each RELAY_PRESETS.filter((p) => p.id !== 'custom') as p}<button type="button" class="chip" onclick={() => applyPreset(p)}>{p.name}</button>{/each}</div>
        <div class="grid2">
          <label class="field"><span>Host</span><input class="input" bind:value={t.host} required /></label>
          <label class="field"><span>Port</span><input class="input" type="number" bind:value={t.port} /></label>
          <label class="field"><span>Security</span>
            <select class="input" bind:value={t.tls}><option value="starttls">STARTTLS required</option><option value="tls">TLS (implicit)</option><option value="opportunistic">STARTTLS if offered</option><option value="none">None</option></select>
          </label>
          <label class="field"><span>Username</span><input class="input" bind:value={t.username} autocomplete="off" /></label>
          <label class="field"><span>Password / API key</span><input class="input" type="password" bind:value={t.password} autocomplete="off" /></label>
        </div>
      {:else if t.kind === 'cloudflare'}
        <label class="field"><span>API token</span><input class="input" type="password" bind:value={t.password} autocomplete="off" required /><span class="hint">A Cloudflare API token with <strong>Email Sending: Edit</strong>. Your sending domains must be onboarded for Email Sending in that account.</span></label>
        <p class="small muted" style="margin:0">Sent over SMTP to smtp.mx.cloudflare.net:465. Cloudflare signs with its own DKIM key and sets Message-ID and Date; headers it doesn't take are left out (User-Agent and the like are kept as X-Original-…). At most 50 recipients and 25 MiB per message. Cloudflare's Email Service is for transactional mail.</p>
      {:else if t.kind === 'webhook'}
        <label class="field"><span>URL</span><input class="input mono" type="url" bind:value={t.url} placeholder="https://app.example.com/inbound-mail" required /></label>
        <div class="grid2">
          <label class="field"><span>Signing secret</span><input class="input" type="password" bind:value={t.secret} autocomplete="off" /><span class="hint">Sent as an HMAC-SHA256 in X-Picacho-Signature.</span></label>
          <label class="field"><span>Body</span><select class="input" bind:value={t.format}><option value="json">JSON (base64 message)</option><option value="raw">Raw message/rfc822</option></select></label>
        </div>
      {/if}
    </form>
  {/if}
  {#if testResult}
    <div class="notice {testResult.ok ? '' : 'danger'}"><Icon name={testResult.ok ? 'check' : 'alert'} size={18} /><span>{testResult.message}</span></div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={test} disabled={testing}><Icon name="zap" size={16} /> {testing ? 'Testing…' : 'Test connection'}</button>
    <span class="spacer"></span>
    <button class="btn" onclick={() => (editing = false)}>{editIndex === -2 ? 'Close' : 'Cancel'}</button>
    {#if editIndex !== -2}<button class="btn primary" type="submit" form="transport" disabled={s.saving}>Save</button>{/if}
  {/snippet}
</Modal>

<style>
  .transports { display: grid; gap: 8px; margin-top: 6px; }
  .tr { display: flex; align-items: center; gap: 14px; padding: 12px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface); }
  .tr :global(svg) { color: var(--muted); flex: none; }
  .grow { flex: 1; display: grid; min-width: 0; }
  .grow span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .presets { display: flex; flex-wrap: wrap; gap: 6px; }
  .presets .chip { cursor: pointer; height: 26px; }
  .nowrap { white-space: nowrap; }
  .table td { vertical-align: middle; }
</style>
