<script>
  import { onMount } from 'svelte';
  import { get, post, del } from '../lib/api.js';
  import { router } from '../lib/router.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { bytes, ago, dateTime } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Avatar from '../lib/Avatar.svelte';

  let { onChanged } = $props();
  let items = $state([]);
  let filter = $state('all');
  const selectedId = $derived(Number(router.parts[1]) || null);
  const detail = $derived(items.find((q) => q.id === selectedId) ?? null);
  const shown = $derived(filter === 'all' ? items : items.filter((q) => q.status === filter));

  async function load() {
    items = await get('/admin/queue');
    onChanged?.();
  }
  onMount(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  });

  async function retry(q) {
    try {
      await post(`/admin/queue/${q.id}/retry`);
      toast.ok('Retrying now.');
      setTimeout(load, 1500);
    } catch (e) {
      toast.error(e);
    }
  }
  async function remove(q) {
    if (!confirm('Remove this message from the queue? It won’t be delivered and no bounce is sent.')) return;
    try {
      await del(`/admin/queue/${q.id}`);
      toast.ok('Removed from the queue.');
      await load();
      router.go('/queue');
    } catch (e) {
      toast.error(e);
    }
  }
  const STATUS = { queued: ['Queued', 'accent'], deferred: ['Retrying', 'warning'], failed: ['Failed', 'danger'] };
  const route = (r) => (r?.startsWith('transport:') ? `via ${r.slice(10)}` : 'routing rules');
</script>

<div class="panes" class:has-detail={!!selectedId}>
  <section class="list-pane">
    <div class="list-head">
      <h1>Queue</h1><span class="count">{items.length}</span><span class="spacer"></span>
      <button class="icon-btn" onclick={load} title="Refresh" aria-label="Refresh"><Icon name="refresh" /></button>
    </div>
    <div class="list-search">
      <div class="segmented">
        {#each [['all', 'All'], ['queued', 'Queued'], ['deferred', 'Retrying'], ['failed', 'Failed']] as [k, l]}
          <button class:on={filter === k} onclick={() => (filter = k)}>{l}</button>
        {/each}
      </div>
    </div>
    <div class="list">
      {#each shown as q (q.id)}
        <button class="list-item" class:active={q.id === selectedId} onclick={() => router.go(`/queue/${q.id}`)}>
          <span class="dot {q.status === 'failed' ? 'bad' : q.status === 'deferred' ? 'warn' : ''}"></span>
          <Avatar text={q.recipients[0] ?? '?'} />
          <div class="main">
            <div class="top"><span class="name">{q.recipients[0]}{q.recipients.length > 1 ? ` +${q.recipients.length - 1}` : ''}</span><span class="meta">{ago(q.created_at)}</span></div>
            <div class="line2">From {q.sender || '<> (bounce)'}</div>
            <div class="line3">{STATUS[q.status]?.[0] ?? q.status} · {q.attempts} attempt{q.attempts === 1 ? '' : 's'}{q.last_error ? ` · ${q.last_error}` : ''}</div>
          </div>
        </button>
      {:else}
        <div class="empty"><Icon name="check" size={30} /><h3>Queue is empty</h3><p>Everything has been delivered.</p></div>
      {/each}
    </div>
  </section>

  <section class="detail-pane">
    {#if detail}
      <div class="toolbar">
        <button class="btn ghost only-narrow" onclick={() => router.go('/queue')}><Icon name="back" /> Queue</button>
        <button class="btn ghost" onclick={() => retry(detail)}><Icon name="refresh" /><span class="label-text">Retry now</span></button>
        <span class="spacer"></span>
        <button class="icon-btn" onclick={() => remove(detail)} title="Remove from queue" aria-label="Remove"><Icon name="trash" /></button>
      </div>
      <div class="detail fade-in"><div class="detail-inner">
        <h1>Message #{detail.id}</h1>
        <div class="lead"><span class="chip {STATUS[detail.status]?.[1]}">{STATUS[detail.status]?.[0] ?? detail.status}</span><span class="muted">{bytes(detail.size)} · queued {dateTime(detail.created_at)} · {route(detail.route)}</span></div>
        {#if detail.last_error}<div class="notice {detail.status === 'failed' ? 'danger' : 'warning'}"><Icon name="alert" size={18} /><span class="mono small">{detail.last_error}</span></div>{/if}
        <div class="card" style="margin-top:14px">
          <table class="table">
            <tbody>
              <tr><td class="muted">From</td><td class="mono">{detail.sender || '<> (null sender)'}</td></tr>
              <tr><td class="muted">To</td><td class="mono">{#each detail.recipients as r}<div>{r}</div>{/each}</td></tr>
              <tr><td class="muted">Attempts</td><td>{detail.attempts}</td></tr>
              <tr><td class="muted">Next attempt</td><td>{detail.status === 'failed' ? '—' : dateTime(detail.next_attempt)}</td></tr>
            </tbody>
          </table>
        </div>
      </div></div>
    {:else if !selectedId}
      <div class="empty"><Icon name="queue" size={34} /><h3>Outgoing queue</h3><p>Messages waiting for delivery appear here with their last error.</p></div>
    {/if}
  </section>
</div>
