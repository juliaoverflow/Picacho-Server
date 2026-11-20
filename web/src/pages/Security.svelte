<script>
  import { onMount } from 'svelte';
  import { get, post, del } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { duration } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';

  const s = liveSettings();
  let info = $state(null);
  let banIp = $state('');
  let banMinutes = $state(1440);
  const sec = $derived(s.data?.security);

  async function load() {
    info = await get('/admin/security');
  }
  onMount(load);

  async function ban(e) {
    e.preventDefault();
    try {
      await post('/admin/security/bans', { ip: banIp, minutes: Number(banMinutes) });
      banIp = '';
      toast.ok('Address banned.');
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  async function unban(ip) {
    try {
      await del(`/admin/security/bans/${encodeURIComponent(ip)}`);
      toast.ok(`${ip} can connect again.`);
      load();
    } catch (err) {
      toast.error(err);
    }
  }
  let listText = $state({ dnsbl: '', allowlist: '' });
  $effect(() => {
    if (sec) listText = { dnsbl: sec.dnsbl.join('\n'), allowlist: sec.allowlist.join('\n') };
  });
  const lines = (v) => v.split(/[\n,\s]+/).map((x) => x.trim()).filter(Boolean);
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><h1>Security</h1></div>
  {#if info}
    <div class="status">
      <div class="card"><Icon name="lock" /><div><strong>{info.tls.self_signed ? 'Self-signed certificate' : 'Certificate installed'}</strong><span class="muted small">TLS {info.tls.min_version}+ · <span class="mono">{info.tls.certificate}</span></span></div>{#if info.tls.self_signed}<span class="chip warning">Action needed</span>{:else}<span class="chip accent">OK</span>{/if}</div>
      <div class="card"><Icon name="database" /><div><strong>{info.encrypted_storage ? 'Mail encrypted at rest' : 'Mail stored unencrypted'}</strong><span class="muted small">{info.encrypted_storage ? 'AES-256-GCM' : 'Set storage.encrypt = true in config.toml'}</span></div>{#if info.encrypted_storage}<span class="chip accent">On</span>{:else}<span class="chip">Off</span>{/if}</div>
      <div class="card"><Icon name="globe" /><div><strong>Console over {info.web_tls ? 'HTTPS' : 'HTTP'}</strong><span class="muted small">{info.web_tls ? 'Served with the server certificate' : 'Use web.tls = true or a TLS reverse proxy'}</span></div>{#if info.web_tls}<span class="chip accent">OK</span>{:else}<span class="chip warning">Plain HTTP</span>{/if}</div>
    </div>
  {/if}
  {#if sec}
    <div class="card">
      <h3>Sign-in protection</h3>
      <p class="sub">Applies to IMAP, SMTP and this console. Repeated failures ban the address on every protocol.</p>
      <Toggle bind:checked={sec.require_tls_for_auth} label="Require TLS for passwords" hint="Refuse sign-in over unencrypted connections." />
      <Toggle bind:checked={sec.allow_plaintext_localhost} label="Allow plaintext from this machine" hint="For local tools and tests on 127.0.0.1." />
      <div class="grid2" style="margin-top:10px">
        <label class="field"><span>Failures before ban</span><input class="input" type="number" min="1" bind:value={sec.max_auth_failures} /></label>
        <label class="field"><span>Counting window (seconds)</span><input class="input" type="number" min="10" bind:value={sec.auth_failure_window_secs} /></label>
        <label class="field"><span>Ban length (seconds)</span><input class="input" type="number" min="10" bind:value={sec.ban_secs} /></label>
        <label class="field"><span>Minimum password length</span><input class="input" type="number" min="8" bind:value={sec.password_min_length} /></label>
      </div>
      <label class="field" style="margin-top:12px"><span>Never ban (IP or CIDR, one per line)</span><textarea class="input mono" rows="2" bind:value={listText.allowlist} onchange={() => (sec.allowlist = lines(listText.allowlist))}></textarea></label>
    </div>
    <div class="card">
      <h3>Sending</h3>
      <Toggle bind:checked={sec.enforce_sender_ownership} label="Users may only send as their own addresses" hint="Envelope sender must be the account or one of its aliases. Admins are exempt." />
    </div>
    <div class="card">
      <h3>Incoming mail checks</h3>
      <Toggle bind:checked={sec.verify_inbound} label="Verify SPF, DKIM and DMARC" hint="Results are added as an Authentication-Results header." />
      <Toggle bind:checked={sec.honor_dmarc_reject} label="Reject mail that fails DMARC with p=reject" disabled={!sec.verify_inbound} />
      <Toggle bind:checked={sec.quarantine_to_junk} label="File DMARC failures in Junk" disabled={!sec.verify_inbound} />
      <Toggle bind:checked={sec.require_rdns} label="Require reverse DNS on connecting servers" />
      <label class="field" style="margin-top:10px"><span>DNS block lists (one per line)</span><textarea class="input mono" rows="2" placeholder="zen.spamhaus.org" bind:value={listText.dnsbl} onchange={() => (sec.dnsbl = lines(listText.dnsbl))}></textarea></label>
    </div>
    <SaveBar {s} />
  {/if}
  <div class="card">
    <h3>Banned addresses</h3>
    <form class="row" onsubmit={ban} style="margin:10px 0">
      <input class="input" bind:value={banIp} placeholder="203.0.113.7" required style="max-width:220px" />
      <select class="input" bind:value={banMinutes} style="max-width:160px"><option value={60}>1 hour</option><option value={1440}>1 day</option><option value={10080}>1 week</option><option value={525600}>1 year</option></select>
      <button class="btn"><Icon name="ban" size={16} /> Ban</button>
    </form>
    {#if info?.bans.length}
      <table class="table">
        <thead><tr><th>Address</th><th>Reason</th><th>Remaining</th><th></th></tr></thead>
        <tbody>{#each info.bans as b}<tr><td class="mono">{b.ip}</td><td>{b.reason}</td><td>{duration(b.remaining_secs)}</td><td><button class="btn small" onclick={() => unban(b.ip)}>Lift</button></td></tr>{/each}</tbody>
      </table>
    {:else}<p class="muted small">No addresses are banned.</p>{/if}
  </div>
</div></div>

<style>
  .status { display: grid; gap: 10px; margin-bottom: 14px; }
  .status .card { display: flex; align-items: center; gap: 14px; margin: 0; padding: 14px 18px; }
  .status .card :global(svg) { color: var(--muted); flex: none; }
  .status .card > div { flex: 1; display: grid; min-width: 0; }
  .status .card span.small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
