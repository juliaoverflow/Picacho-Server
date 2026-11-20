<script>
  import { onMount } from 'svelte';
  import { get } from '../lib/api.js';
  import { dateTime } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';

  let events = $state([]);
  let kind = $state('');
  let query = $state('');
  const KINDS = [['', 'All'], ['smtp', 'Mail in'], ['delivery', 'Delivery'], ['auth', 'Sign-ins'], ['security', 'Security'], ['admin', 'Changes'], ['setup', 'Setup']];
  const shown = $derived(events.filter((e) => e.message.toLowerCase().includes(query.toLowerCase())));

  async function load() {
    events = await get(`/admin/events?limit=500${kind ? `&kind=${kind}` : ''}`);
  }
  onMount(() => {
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  });
  $effect(() => {
    kind;
    load();
  });
</script>

<div class="page"><div class="page-inner">
  <div class="page-head">
    <h1>Activity</h1><span class="spacer"></span>
    <input class="input" placeholder="Filter" bind:value={query} style="max-width:240px" />
    <button class="icon-btn" onclick={load} aria-label="Refresh"><Icon name="refresh" /></button>
  </div>
  <div class="segmented" style="margin-bottom:14px;flex-wrap:wrap">
    {#each KINDS as [k, l]}<button class:on={kind === k} onclick={() => (kind = k)}>{l}</button>{/each}
  </div>
  <div class="card log">
    {#each shown as e (e.id)}
      <div class="ev"><span class="lvl {e.level}"></span><span class="when muted">{dateTime(e.ts)}</span><span class="kind">{e.kind}</span><span class="msg">{e.message}</span></div>
    {:else}
      <div class="empty"><Icon name="activity" size={30} /><h3>No events</h3></div>
    {/each}
  </div>
  <p class="hint">Events are kept for 30 days. Full logs go to the server’s standard output.</p>
</div></div>

<style>
  .log { padding: 4px 0; }
  .ev { display: flex; align-items: baseline; gap: 12px; padding: 9px 18px; border-bottom: 1px solid var(--border); font-size: 14px; }
  .ev:last-child { border-bottom: 0; }
  .when { font-size: 13px; width: 120px; flex: none; }
  .kind { font-size: 11.5px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; width: 72px; flex: none; }
  .msg { flex: 1; min-width: 0; word-break: break-word; }
  .lvl { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); flex: none; align-self: center; }
  .lvl.warn { background: var(--warning); }
  .lvl.error { background: var(--danger); }
  @media (max-width: 700px) { .ev { flex-wrap: wrap; } .when { width: auto; } }
</style>
