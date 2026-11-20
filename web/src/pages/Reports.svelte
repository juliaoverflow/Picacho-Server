<script>
  import { onMount } from 'svelte';
  import { get, post } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { date, ago } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import ListField from '../lib/ListField.svelte';

  const s = liveSettings();
  const rep = $derived(s.data?.reports);
  let kind = $state('');
  let reports = $state([]);
  let loaded = $state(false);
  let open = $state(null);
  let sending = $state(false);

  async function load() {
    try {
      reports = await get(`/admin/reports?limit=500${kind ? `&kind=${kind}` : ''}`);
    } catch (e) {
      toast.error(e);
    } finally {
      loaded = true;
    }
  }
  onMount(load);

  async function sendNow() {
    sending = true;
    try {
      await post('/admin/maintenance/reports');
      toast.ok('Outgoing reports sent for the last period.');
    } catch (e) {
      toast.error(e);
    } finally {
      sending = false;
    }
  }

  function result(r) {
    const sm = r.summary ?? {};
    if (r.kind === 'dmarc') return { ok: sm.passed ?? 0, bad: sm.failed ?? 0, total: sm.messages ?? 0 };
    return { ok: sm.successful ?? 0, bad: sm.failed ?? 0, total: (sm.successful ?? 0) + (sm.failed ?? 0) };
  }
  const totals = $derived(reports.reduce((a, r) => {
    const x = result(r);
    a[r.kind] = a[r.kind] ?? { ok: 0, bad: 0 };
    a[r.kind].ok += x.ok;
    a[r.kind].bad += x.bad;
    return a;
  }, {}));
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Reports</h1><p class="muted" style="margin:6px 0 0">DMARC aggregate and SMTP TLS reports that other mail providers send about your domains.</p></div></div>

  <div class="summary">
    {#each [['dmarc', 'DMARC', 'messages passed'], ['tls', 'TLS', 'sessions succeeded']] as [k, label, what]}
      {@const t = totals[k]}
      <div class="card tile">
        <span class="label">{label}</span>
        {#if t && t.ok + t.bad}
          <strong>{Math.round((t.ok / (t.ok + t.bad)) * 100)}%</strong>
          <span class="muted small">{t.ok.toLocaleString()} of {(t.ok + t.bad).toLocaleString()} {what}</span>
        {:else}<strong>—</strong><span class="muted small">No {label} reports{kind && kind !== k ? ' in this view' : ''}</span>{/if}
      </div>
    {/each}
  </div>

  <div class="card">
    <div class="row">
      <h3>Received</h3><span class="spacer"></span>
      <div class="segmented">
        {#each [['', 'All'], ['dmarc', 'DMARC'], ['tls', 'TLS']] as [v, l]}<button class:on={kind === v} onclick={() => { kind = v; load(); }}>{l}</button>{/each}
      </div>
      <button class="icon-btn" onclick={load} aria-label="Refresh" title="Refresh"><Icon name="refresh" /></button>
    </div>
    {#if reports.length}
      <table class="table" style="margin-top:10px">
        <thead><tr><th>From</th><th>Type</th><th>Domain</th><th>Period</th><th>Result</th><th>Received</th></tr></thead>
        <tbody>
          {#each reports as r (r.id)}
            {@const x = result(r)}
            <tr class="clickable" onclick={() => (open = open === r.id ? null : r.id)}>
              <td><strong>{r.org || '—'}</strong></td>
              <td><span class="chip">{r.kind.toUpperCase()}</span></td>
              <td class="mono">{r.domain}</td>
              <td class="muted">{date(r.begin)}{r.end && date(r.end) !== date(r.begin) ? ` – ${date(r.end)}` : ''}</td>
              <td>{#if x.bad}<span class="chip warning">{x.bad.toLocaleString()} failed</span>{:else}<span class="chip accent">All passed</span>{/if} <span class="muted small">of {x.total.toLocaleString()}</span></td>
              <td class="muted">{ago(r.received_at)}</td>
            </tr>
            {#if open === r.id && r.kind === 'dmarc' && r.summary?.records?.length}
              <tr class="records"><td colspan="6">
                <table class="table inner">
                  <thead><tr><th>Source IP</th><th>From domain</th><th>Messages</th><th>SPF</th><th>DKIM</th><th>Disposition</th></tr></thead>
                  <tbody>{#each r.summary.records as rec}<tr>
                    <td class="mono">{rec.source_ip}</td><td>{rec.header_from}</td><td>{rec.count}</td>
                    <td><span class="chip" class:accent={rec.spf === 'pass'} class:danger={rec.spf !== 'pass'}>{rec.spf || '—'}</span></td>
                    <td><span class="chip" class:accent={rec.dkim === 'pass'} class:danger={rec.dkim !== 'pass'}>{rec.dkim || '—'}</span></td>
                    <td>{rec.disposition}</td>
                  </tr>{/each}</tbody>
                </table>
              </td></tr>
            {/if}
          {/each}
        </tbody>
      </table>
      <p class="muted small" style="margin:10px 0 0">Select a DMARC report to see which servers sent mail as your domain.</p>
    {:else if loaded}
      <div class="empty" style="padding:30px"><Icon name="chart" size={28} /><h3>No reports yet</h3><p>Add an address below and publish it in your domains' <span class="mono">_dmarc</span> rua= and <span class="mono">_smtp._tls</span> records.</p></div>
    {/if}
  </div>

  {#if rep}
    <div class="card">
      <h3>Collecting reports</h3>
      <p class="sub">Reports arriving at these addresses are parsed and kept here. They are still delivered to the mailbox.</p>
      <ListField bind:value={rep.ingest_addresses} label="Report addresses" placeholder="dmarc-reports@example.com&#10;tls-reports@example.com" rows={2} />
    </div>
    <div class="card">
      <h3>Sending reports</h3>
      <p class="sub">Tell other domains how their mail fared when it reached you. Sent once a day to domains that ask for it.</p>
      <Toggle bind:checked={rep.send_dmarc} label="Send DMARC aggregate reports" />
      <Toggle bind:checked={rep.send_tls} label="Send SMTP TLS reports" />
      <div class="grid2" style="margin-top:10px">
        <label class="field"><span>Organization name</span><input class="input" value={rep.org_name ?? ''} oninput={(e) => (rep.org_name = e.target.value || null)} placeholder={s.data.server.hostname || 'Host name'} /></label>
        <label class="field"><span>Contact address</span><input class="input" type="email" value={rep.contact ?? ''} oninput={(e) => (rep.contact = e.target.value || null)} placeholder="postmaster@{s.data.server.primary_domain || 'your domain'}" /></label>
      </div>
      <div class="row" style="margin-top:14px"><button class="btn" onclick={sendNow} disabled={sending || (!rep.send_dmarc && !rep.send_tls)}><Icon name="send" size={16} /> {sending ? 'Sending…' : 'Send reports now'}</button></div>
    </div>
    <SaveBar {s} />
  {/if}
</div></div>

<style>
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-bottom: 14px; }
  .tile { display: grid; gap: 2px; margin: 0 !important; }
  .tile .label { font-size: 12.5px; font-weight: 600; color: var(--muted); }
  .tile strong { font-size: 26px; font-weight: 600; }
  .clickable { cursor: pointer; }
  .clickable:hover td { background: var(--surface); }
  .records > td { background: var(--surface); padding: 6px 10px 12px; }
  .inner { font-size: 13px; }
</style>
