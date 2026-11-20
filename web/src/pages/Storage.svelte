<script>
  import { onMount } from 'svelte';
  import { get } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { bytes } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import { link } from '../lib/router.svelte.js';

  const s = liveSettings();
  let info = $state(null);
  onMount(async () => (info = await get('/admin/storage')));
  const lim = $derived(s.data?.limits);
  const mb = (b) => Math.round(b / 1048576);
  const saved = $derived(info && info.stats.logical_bytes > info.stats.stored_bytes ? info.stats.logical_bytes - info.stats.stored_bytes : 0);
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Storage &amp; limits</h1><p class="muted" style="margin:6px 0 0">Where data lives, how much is used, and limits that apply immediately. Locations are changed under Configuration.</p></div></div>
  {#if info}
    <div class="grid">
      {#each [
        ['database', 'Metadata database', info.storage.database, 'Accounts, folders, flags, queue'],
        ['inbox', 'Messages', info.storage.messages, 'Raw messages, deduplicated by content'],
        ['folder', 'Attachments', info.storage.attachments ? `${info.storage.attachments.backend}` : 'Stored with messages', info.storage.attachments ? `Parts over ${bytes(info.storage.attachments.threshold_bytes)} are split out and shared` : 'Configure [storage.attachments] to split large files out'],
        ['settings', 'Live settings', info.storage.settings, 'What you change in this console'],
        ['lock', 'Encryption', info.storage.encrypted ? 'AES-256-GCM' : 'Off', info.storage.encrypted ? 'Messages and attachments are encrypted before storage' : 'Enable with storage.encrypt = true'],
      ] as [icon, title, value, sub]}
        <div class="card tile"><Icon name={icon} /><div><span class="label">{title}</span><strong class="truncate">{value}</strong><span class="muted small">{sub}</span></div></div>
      {/each}
    </div>
    <div class="card">
      <h3>Usage</h3>
      <div class="usage">
        <div><strong>{bytes(info.stats.logical_bytes)}</strong><span>Mailbox contents</span></div>
        <div><strong>{bytes(info.stats.stored_bytes)}</strong><span>Actually stored</span></div>
        <div><strong>{bytes(saved)}</strong><span>Saved by deduplication</span></div>
        <div><strong>{info.stats.blobs.toLocaleString()}</strong><span>Stored objects</span></div>
      </div>
    </div>
  {/if}
  {#if lim}
    <div class="card">
      <h3>Limits</h3>
      <p class="sub">Apply immediately to new connections and messages.</p>
      <div class="grid2">
        <label class="field"><span>Largest message (MB)</span><input class="input" type="number" min="1" value={mb(lim.max_message_bytes)} onchange={(e) => (lim.max_message_bytes = Math.max(1, Number(e.target.value)) * 1048576)} /></label>
        <label class="field"><span>Default quota for new accounts (MB)</span><input class="input" type="number" min="0" bind:value={lim.default_quota_mb} /><span class="hint">0 means unlimited.</span></label>
        <label class="field"><span>Recipients per message</span><input class="input" type="number" min="1" bind:value={lim.max_recipients} /></label>
        <label class="field"><span>Messages each user may send per hour</span><input class="input" type="number" min="0" bind:value={lim.send_rate_per_hour} /><span class="hint">0 means unlimited.</span></label>
        <label class="field"><span>IMAP sessions per user</span><input class="input" type="number" min="1" bind:value={lim.max_imap_sessions_per_user} /></label>
      </div>
    </div>
    <SaveBar {s} />
  {/if}
  <div class="card row">
    <div style="flex:1"><h3>Changing where data lives</h3><p class="sub" style="margin:0">Database, message and attachment stores, encryption and the live-settings location are set under Configuration and apply after a restart.</p></div>
    <a class="btn" href="/configuration" use:link>Open Configuration</a>
  </div>
</div></div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-bottom: 14px; }
  .tile { display: flex; gap: 14px; margin: 0 !important; align-items: flex-start; }
  .tile :global(svg) { color: var(--accent); flex: none; margin-top: 2px; }
  .tile > div { display: grid; gap: 2px; min-width: 0; }
  .tile .label { font-size: 12.5px; font-weight: 600; color: var(--muted); }
  .usage { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 10px; }
  .usage > div { display: grid; padding: 12px 14px; border-radius: 10px; background: var(--surface); }
  .usage strong { font-size: 22px; font-weight: 600; }
  .usage span { color: var(--muted); font-size: 13px; }
</style>
