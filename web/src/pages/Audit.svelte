<script>
  import { onMount } from 'svelte';
  import { get } from '../lib/api.js';
  import { toast } from '../lib/toast.svelte.js';
  import { dateTime } from '../lib/format.js';
  import { link } from '../lib/router.svelte.js';
  import Icon from '../lib/Icon.svelte';

  const PAGE = 200;
  let rows = $state([]);
  let actor = $state('');
  let query = $state('');
  let more = $state(false);
  let loading = $state(false);

  async function load(append = false) {
    loading = true;
    try {
      const params = new URLSearchParams({ limit: String(PAGE) });
      if (append && rows.length) params.set('before', String(rows[rows.length - 1].id));
      if (actor) params.set('actor', actor);
      const r = await get(`/admin/audit?${params}`);
      rows = append ? [...rows, ...r] : r;
      more = r.length === PAGE;
    } catch (e) {
      toast.error(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => load());

  const actors = $derived([...new Set(rows.map((r) => r.actor))].sort());
  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => `${r.action} ${r.target} ${r.ip} ${r.actor}`.toLowerCase().includes(q));
  });
  const METHOD = { POST: 'accent', PUT: 'accent', PATCH: 'accent', DELETE: 'danger' };
  function split(a) {
    const i = a.indexOf(' ');
    return i < 0 ? ['', a] : [a.slice(0, i), a.slice(i + 1)];
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Audit log</h1><p class="muted" style="margin:6px 0 0">Every change made through this console or the API, by whom and from where. Kept for the period set under <a href="/maintenance" use:link>Retention</a>.</p></div></div>
  <div class="card">
    <div class="row">
      <input class="input" style="max-width:280px" placeholder="Filter by action, path or IP" bind:value={query} />
      <select class="input" style="max-width:240px" bind:value={actor} onchange={() => load()} aria-label="Who">
        <option value="">Everyone</option>
        {#if actor && !actors.includes(actor)}<option value={actor}>{actor}</option>{/if}
        {#each actors as a}<option value={a}>{a}</option>{/each}
      </select>
      <span class="spacer"></span>
      <button class="icon-btn" onclick={() => load()} aria-label="Refresh" title="Refresh"><Icon name="refresh" /></button>
    </div>
    {#if shown.length}
      <table class="table" style="margin-top:10px">
        <thead><tr><th>When</th><th>Who</th><th>Change</th><th>From</th></tr></thead>
        <tbody>
          {#each shown as r (r.id)}
            {@const [m, path] = split(r.action)}
            <tr>
              <td class="muted nowrap">{dateTime(r.ts)}</td>
              <td class="truncate who">{r.actor}</td>
              <td><span class="chip {METHOD[m] ?? ''}">{m || '—'}</span> <span class="mono small">{path}</span>
                {#if r.detail && typeof r.detail === 'object'}<div class="muted small mono">{JSON.stringify(r.detail)}</div>{:else if r.detail}<div class="muted small">{r.detail}</div>{/if}
              </td>
              <td class="mono small muted">{r.ip}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if more && !query}<div class="row" style="margin-top:12px;justify-content:center"><button class="btn" onclick={() => load(true)} disabled={loading}>{loading ? 'Loading…' : 'Load older'}</button></div>{/if}
    {:else if !loading}
      <div class="empty" style="padding:30px"><Icon name="history" size={28} /><h3>{query || actor ? 'No matching entries' : 'Nothing recorded yet'}</h3></div>
    {/if}
  </div>
</div></div>

<style>
  .nowrap { white-space: nowrap; }
  .who { max-width: 220px; }
</style>
