<script>
  import { onMount } from 'svelte';
  import { get } from '../lib/api.js';
  import { link } from '../lib/router.svelte.js';
  import { bytes, duration, ago } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';

  let data = $state(null);
  let error = $state('');

  async function load() {
    try {
      data = await get('/admin/overview');
      error = '';
    } catch (e) {
      error = e.message;
    }
  }
  onMount(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const checks = $derived(data ? [
    data.tls.self_signed && { level: 'warning', icon: 'lock', text: 'The server uses a self-signed TLS certificate, so mail apps will warn users. Add your certificate under Configuration → TLS.', href: '/configuration' },
    !data.storage.encrypted && { level: '', icon: 'database', text: 'Stored mail is not encrypted at rest. Turn on AES-256-GCM under Configuration → Storage.', href: '/configuration' },
    data.queue.failed > 0 && { level: 'danger', icon: 'alert', text: `${data.queue.failed} message(s) failed to deliver.`, href: '/queue' },
    data.queue.deferred > 0 && { level: 'warning', icon: 'clock', text: `${data.queue.deferred} message(s) are waiting to retry.`, href: '/queue' },
  ].filter(Boolean) : []);

  const dedup = $derived(data && data.stats.logical_bytes > 0 ? Math.max(0, 1 - data.stats.stored_bytes / data.stats.logical_bytes) : 0);
</script>

<div class="page">
  <div class="page-inner">
    <div class="page-head">
      <h1>Overview</h1>
      {#if data}<span class="chip accent"><span class="pulse"></span>Running · {duration(data.uptime_secs)}</span>{/if}
      <span class="spacer"></span>
      <button class="icon-btn" onclick={load} title="Refresh" aria-label="Refresh"><Icon name="refresh" /></button>
    </div>
    {#if error}<div class="notice danger">{error}</div>{/if}
    {#if data}
      {#if checks.length}
        <div class="checks">
          {#each checks as c}
            <a class="notice {c.level}" href={c.href} use:link><Icon name={c.icon} size={18} /><span>{c.text}</span><span class="spacer"></span><Icon name="chevron" size={16} /></a>
          {/each}
        </div>
      {/if}

      <div class="stats">
        <a class="stat card" href="/accounts" use:link><span class="label">Accounts</span><strong>{data.stats.accounts}</strong><span class="muted small">{data.stats.aliases} aliases</span></a>
        <a class="stat card" href="/domains" use:link><span class="label">Domains</span><strong>{data.stats.domains}</strong><span class="muted small">{data.primary_domain ?? ''}</span></a>
        <div class="stat card"><span class="label">Messages</span><strong>{data.stats.messages.toLocaleString()}</strong><span class="muted small">in {data.stats.mailboxes} mailboxes</span></div>
        <a class="stat card" href="/storage" use:link><span class="label">Stored</span><strong>{bytes(data.stats.stored_bytes)}</strong><span class="muted small">{dedup > 0.01 ? `${Math.round(dedup * 100)}% saved by deduplication` : `${data.stats.blobs} objects`}</span></a>
      </div>

      <div class="cols">
        <div class="card">
          <h3>Delivery queue</h3>
          <p class="sub">Outgoing mail waiting to be handed to other servers.</p>
          <div class="queue">
            <a href="/queue" use:link><strong>{data.queue.queued}</strong><span>Queued</span></a>
            <a href="/queue" use:link class:warn={data.queue.deferred}><strong>{data.queue.deferred}</strong><span>Retrying</span></a>
            <a href="/queue" use:link class:bad={data.queue.failed}><strong>{data.queue.failed}</strong><span>Failed</span></a>
          </div>
        </div>
        <div class="card">
          <h3>Connections</h3>
          <p class="sub">Clients connected right now.</p>
          <div class="queue">
            <div><strong>{data.connections.imap}</strong><span>IMAP</span></div>
            <div><strong>{data.connections.smtp}</strong><span>SMTP</span></div>
            <div class:warn={data.bans}><strong>{data.bans}</strong><span>Banned IPs</span></div>
          </div>
        </div>
      </div>

      <div class="cols">
        <div class="card">
          <h3>Services</h3>
          <table class="table">
            <tbody>
              {#each data.listeners as l}
                <tr><td><span class="ok-dot"></span>{l.protocol}</td><td class="mono muted">{l.address}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="card">
          <h3>Storage</h3>
          <table class="table">
            <tbody>
              <tr><td>Database</td><td class="muted">{data.storage.database}</td></tr>
              <tr><td>Messages</td><td class="muted truncate">{data.storage.messages}</td></tr>
              <tr><td>Attachments</td><td class="muted">{data.storage.attachments?.backend ?? 'with messages'}</td></tr>
              <tr><td>Live settings</td><td class="muted">{data.storage.settings}</td></tr>
              <tr><td>Encryption</td><td>{#if data.storage.encrypted}<span class="chip accent">AES-256-GCM</span>{:else}<span class="chip">Off</span>{/if}</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="row"><h3>Recent activity</h3><span class="spacer"></span><a href="/activity" use:link class="small">View all</a></div>
        <ul class="events">
          {#each data.events as e}
            <li><span class="lvl {e.level}"></span><span class="kind">{e.kind}</span><span class="msg">{e.message}</span><span class="muted small when">{ago(e.ts)}</span></li>
          {:else}
            <li class="muted">Nothing yet.</li>
          {/each}
        </ul>
      </div>
    {/if}
  </div>
</div>

<style>
  .checks { display: grid; gap: 8px; margin-bottom: 18px; }
  .checks a { color: var(--text); text-decoration: none; align-items: center; }
  .checks a:hover { filter: brightness(0.98); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 14px; }
  .stat { display: grid; gap: 2px; color: var(--text); text-decoration: none !important; margin: 0 !important; }
  .stat .label { color: var(--muted); font-size: 13px; font-weight: 600; }
  .stat strong { font-size: 30px; font-weight: 600; letter-spacing: -0.02em; }
  a.stat:hover { border-color: var(--accent); }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; margin-bottom: 14px; }
  .cols .card { margin: 0; }
  .queue { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .queue > * { display: grid; padding: 12px 14px; border-radius: 10px; background: var(--surface); color: var(--text); text-decoration: none !important; }
  .queue strong { font-size: 24px; font-weight: 600; }
  .queue span { color: var(--muted); font-size: 13px; }
  .queue .warn strong { color: var(--warning); }
  .queue .bad strong { color: var(--danger); }
  .ok-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); margin-right: 10px; }
  .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }
  .events { list-style: none; padding: 0; margin: 8px 0 0; display: grid; }
  .events li { display: flex; align-items: baseline; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
  .events li:last-child { border-bottom: 0; }
  .events .msg { flex: 1; min-width: 0; word-break: break-word; }
  .events .kind { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; width: 74px; flex: none; }
  .events .when { white-space: nowrap; }
  .lvl { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); flex: none; align-self: center; }
  .lvl.warn { background: var(--warning); }
  .lvl.error { background: var(--danger); }
</style>
