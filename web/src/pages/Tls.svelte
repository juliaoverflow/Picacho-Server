<script>
  import { onMount } from 'svelte';
  import { get, post } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { duration } from '../lib/format.js';
  import { link } from '../lib/router.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import ListField from '../lib/ListField.svelte';

  const s = liveSettings();
  let tls = $state(null);
  let renewing = $state(false);
  const d = $derived(s.data?.delivery);
  const srv = $derived(s.data?.server);

  async function load() {
    tls = await get('/admin/tls').catch((e) => (toast.error(e), null));
  }
  onMount(load);

  async function renew() {
    renewing = true;
    try {
      const r = await post('/admin/tls/renew');
      toast.ok(r.message || 'Certificate issued.');
      load();
    } catch (e) {
      toast.error(e);
    } finally {
      renewing = false;
    }
  }

  const SOURCES = { acme: 'Let’s Encrypt (ACME)', files: 'Certificate files from config.toml', 'self-signed': 'Self-signed' };
  const missing = $derived(tls ? (tls.wanted_names ?? []).filter((n) => !tls.names.some((c) => c === n || (c.startsWith('*.') && n.endsWith(c.slice(1))))) : []);
  const expiry = $derived(tls?.expires_in_secs);
  const MODES = [
    ['testing', 'Testing', 'Senders report failures but still deliver.'],
    ['enforce', 'Enforce', 'Senders refuse to deliver without valid TLS to your MX.'],
    ['none', 'None', 'Publish a policy that tells senders to stop using MTA-STS.'],
    ['off', 'Off', 'Don’t serve a policy at mta-sts.<domain>.'],
  ];
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>TLS &amp; MTA-STS</h1><p class="muted" style="margin:6px 0 0">The server certificate and how strictly mail is encrypted in transit.</p></div></div>

  {#if tls}
    <div class="card">
      <div class="row">
        <h3>Certificate</h3><span class="spacer"></span>
        {#if expiry == null}<span class="chip danger">None loaded</span>
        {:else if expiry < 0}<span class="chip danger">Expired</span>
        {:else if expiry < 14 * 86400}<span class="chip warning">Expires in {duration(expiry)}</span>
        {:else if expiry > 3650 * 86400}<span class="chip accent">Doesn’t expire</span>{:else}<span class="chip accent">Valid for {Math.floor(expiry / 86400)} days</span>{/if}
      </div>
      <dl class="kv">
        <dt>Source</dt><dd>{SOURCES[tls.source] ?? tls.source}</dd>
        <dt>Names</dt><dd>{#each tls.names as n}<span class="chip mono">{n}</span> {:else}<span class="muted">—</span>{/each}</dd>
        {#if tls.acme}<dt>Wanted</dt><dd>{#each tls.wanted_names ?? [] as n}<span class="chip mono" class:warning={missing.includes(n)}>{n}</span> {/each}</dd>{/if}
      </dl>
      {#if tls.acme}
        {#if missing.length}<div class="notice warning" style="margin-top:12px"><Icon name="alert" size={18} /><span>The certificate doesn’t cover {missing.join(', ')}. Renew to add {missing.length === 1 ? 'it' : 'them'}.</span></div>{/if}
        <div class="row" style="margin-top:14px">
          <button class="btn" onclick={renew} disabled={renewing}><Icon name="refresh" size={16} /> {renewing ? 'Requesting…' : 'Renew now'}</button>
          <span class="muted small">Certificates renew automatically 30 days before they expire.</span>
        </div>
      {:else}
        <p class="sub" style="margin:12px 0 0">Automatic certificates are off. Add a <code>[tls.acme]</code> section under <a href="/configuration" use:link>Configuration</a> to get one from Let’s Encrypt.</p>
      {/if}
    </div>
  {/if}

  {#if d && srv}
    <div class="card">
      <h3>Sending</h3>
      <p class="sub">How this server protects mail it delivers to other domains.</p>
      <Toggle bind:checked={d.mta_sts} label="Follow recipients' MTA-STS policies" hint="Refuses to deliver over unverified TLS to domains that require it (RFC 8461)." />
      <Toggle bind:checked={d.dane} label="Verify MX certificates with DANE" hint="Uses DNSSEC-signed TLSA records when the recipient publishes them (RFC 7672)." />
      <Toggle bind:checked={d.arc_seal} label="ARC-seal forwarded mail" hint="Lets the next server trust our SPF/DKIM results after forwarding (RFC 8617)." />
      <Toggle bind:checked={d.require_tls} label="Require TLS for direct delivery" hint="Also on Routing &amp; relays. Mail to servers without valid STARTTLS stays queued and eventually bounces." />
    </div>

    <div class="card">
      <h3>Receiving: MTA-STS policy</h3>
      <p class="sub">Published at <span class="mono">https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</span> for each domain. Add the matching <span class="mono">_mta-sts</span> TXT record shown under Domains.</p>
      <div class="modes">
        {#each MODES as [v, label, hint]}
          {@const on = (srv.mta_sts_mode ?? 'testing') === v}
          <label class="mode" class:on>
            <input type="radio" name="mta-sts" checked={on} onchange={() => (srv.mta_sts_mode = v === 'testing' ? null : v)} />
            <strong>{label}</strong><span class="muted small">{hint}</span>
          </label>
        {/each}
      </div>
      <div style="margin-top:14px"><ListField bind:value={srv.mta_sts_mx} label="Extra MX names in the policy" placeholder="backup-mx.example.net" hint="This server's host name is always included. Add backup MX hosts or a relay upstream." /></div>
    </div>
    <SaveBar {s} />
  {/if}

  <div class="card row">
    <div style="flex:1"><h3>TLS reports</h3><p class="sub" style="margin:0">Reports from other servers about failed TLS connections to you, and sending your own, are under Reports.</p></div>
    <a class="btn" href="/reports" use:link>Open Reports</a>
  </div>
</div></div>

<style>
  .kv { display: grid; grid-template-columns: 90px 1fr; gap: 8px 14px; margin: 12px 0 0; }
  .kv dt { color: var(--muted); font-size: 13.5px; padding-top: 2px; }
  .kv dd { margin: 0; display: flex; flex-wrap: wrap; gap: 6px; }
  .modes { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
  .mode { display: grid; gap: 4px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 10px; cursor: pointer; position: relative; }
  .mode.on { border-color: var(--accent); background: var(--soft); }
  .mode input { position: absolute; opacity: 0; }
  .mode:has(input:focus-visible) { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>
