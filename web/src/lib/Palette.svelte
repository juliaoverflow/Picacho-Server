<script>
  // Command palette (⌘K / Ctrl+K): jump to any page, account, domain or alias.
  import { get } from './api.js';
  import { router } from './router.svelte.js';
  import { ui } from './ui.svelte.js';
  import Icon from './Icon.svelte';

  let { pages } = $props();
  let query = $state('');
  let items = $state([]);
  let index = $state(0);
  let input = $state();

  $effect(() => {
    if (ui.paletteOpen) {
      query = '';
      index = 0;
      load();
      queueMicrotask(() => input?.focus());
    }
  });

  async function load() {
    const [accounts, domains, aliases, principals] = await Promise.all([
      get('/admin/accounts').catch(() => []),
      get('/admin/domains').catch(() => []),
      get('/admin/aliases').catch(() => []),
      get('/admin/dav/principals').catch(() => []),
    ]);
    items = [
      ...pages.map((p) => ({ icon: p.icon, label: p.label, hint: p.group ?? 'Page', path: p.path, keywords: p.keywords ?? '' })),
      { icon: 'plus', label: 'New account', hint: 'Action', run: () => { router.go('/accounts'); queueMicrotask(() => ui.requestCreate('account')); } },
      { icon: 'plus', label: 'New domain', hint: 'Action', run: () => { router.go('/domains'); queueMicrotask(() => ui.requestCreate('domain')); } },
      { icon: 'plus', label: 'New alias', hint: 'Action', run: () => { router.go('/aliases'); queueMicrotask(() => ui.requestCreate('alias')); } },
      { icon: 'plus', label: 'New DAV user', hint: 'Action', keywords: 'calendar contacts caldav carddav', run: () => { router.go('/dav'); queueMicrotask(() => ui.requestCreate('dav')); } },
      { icon: 'key', label: 'Create API token', hint: 'Action', path: '/api' },
      { icon: 'link', label: 'Add downstream relay server', hint: 'Action', keywords: 'peer relay token', path: '/relay' },
      { icon: 'refresh', label: 'Renew TLS certificate', hint: 'Action', keywords: 'acme lets encrypt', path: '/tls' },
      { icon: 'wrench', label: 'Run retention or storage sweep', hint: 'Action', keywords: 'maintenance cleanup orphan', path: '/maintenance' },
      { icon: 'download', label: 'Export or migrate a mailbox', hint: 'Action', keywords: 'backup import imap copy', path: '/accounts' },
      ...accounts.map((a) => ({ icon: 'user', label: a.display_name || a.email, hint: a.email, path: `/accounts/${a.id}` })),
      ...domains.map((d) => ({ icon: 'globe', label: d.name, hint: 'Domain', path: `/domains/${d.id}` })),
      ...aliases.map((a) => ({ icon: 'at', label: a.source, hint: `→ ${a.destination}`, path: `/aliases/${a.id}` })),
      ...principals.filter((p) => !p.account_id).map((p) => ({ icon: 'calendar', label: p.username, hint: 'DAV user', keywords: p.display_name, path: '/dav' })),
    ];
  }

  const results = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items.slice(0, 12);
    return items
      .map((it) => {
        const hay = `${it.label} ${it.hint} ${it.keywords ?? ''}`.toLowerCase();
        const at = hay.indexOf(q);
        return { it, score: at < 0 ? -1 : at === 0 ? 2 : 1 };
      })
      .filter((x) => x.score >= 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 30)
      .map((x) => x.it);
  });

  function choose(it) {
    ui.paletteOpen = false;
    if (it.run) it.run();
    else router.go(it.path);
  }

  function onkey(e) {
    if (e.key === 'ArrowDown') { index = Math.min(results.length - 1, index + 1); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { index = Math.max(0, index - 1); e.preventDefault(); }
    else if (e.key === 'Enter' && results[index]) { choose(results[index]); e.preventDefault(); }
    else if (e.key === 'Escape') ui.paletteOpen = false;
  }
</script>

<svelte:window onkeydown={(e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ui.paletteOpen = !ui.paletteOpen; }
}} />

{#if ui.paletteOpen}
  <div class="scrim" role="presentation" onclick={() => (ui.paletteOpen = false)}></div>
  <div class="palette fade-in" role="dialog" aria-label="Go to">
    <div class="search">
      <Icon name="search" />
      <input bind:this={input} bind:value={query} onkeydown={onkey} oninput={() => (index = 0)} placeholder="Go to a page, account, domain, alias or DAV user…" />
      <kbd>esc</kbd>
    </div>
    <ul>
      {#each results as it, i}
        <li><button class:active={i === index} onmouseenter={() => (index = i)} onclick={() => choose(it)}>
          <Icon name={it.icon} size={17} /><span class="label truncate">{it.label}</span><span class="hint truncate">{it.hint}</span>
        </button></li>
      {:else}
        <li class="none">No matches</li>
      {/each}
    </ul>
  </div>
{/if}

<style>
  .scrim { position: fixed; inset: 0; background: var(--overlay); z-index: 60; }
  .palette { position: fixed; top: 12vh; left: 50%; transform: translateX(-50%); width: min(620px, calc(100vw - 32px)); z-index: 61; background: var(--raised); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow); overflow: hidden; }
  .search { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); color: var(--muted); }
  input { flex: 1; border: 0; outline: none; background: transparent; font-size: 16px; color: var(--text); }
  kbd { font-family: var(--mono); font-size: 11px; padding: 2px 6px; border: 1px solid var(--border); border-radius: 5px; color: var(--muted); }
  ul { list-style: none; margin: 0; padding: 6px; max-height: 50vh; overflow: auto; }
  li button { width: 100%; display: flex; align-items: center; gap: 12px; padding: 9px 12px; border: 0; background: none; border-radius: 9px; cursor: pointer; color: var(--text); text-align: left; }
  li button :global(svg) { color: var(--muted); flex: none; }
  li button.active { background: var(--soft); }
  li button.active :global(svg) { color: var(--accent); }
  .label { font-weight: 500; }
  .hint { margin-left: auto; color: var(--muted); font-size: 13px; max-width: 45%; }
  .none { padding: 18px; text-align: center; color: var(--muted); }
</style>
