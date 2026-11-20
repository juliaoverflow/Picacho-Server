<script>
  // Apps connected through OAuth (one row per authorization).
  import { onMount } from 'svelte';
  import { get, del } from './api.js';
  import { toast } from './toast.svelte.js';
  import { ago, date } from './format.js';

  let { all = false } = $props();
  let grants = $state([]);
  const LABEL = { imap: 'IMAP', 'imap:read': 'IMAP (read)', smtp: 'Send', jmap: 'JMAP', 'jmap:read': 'JMAP (read)' };

  async function load() {
    grants = await get(`/oauth/grants${all ? '?all=1' : ''}`);
  }
  onMount(() => load().catch((e) => toast.error(e)));

  async function revoke(g) {
    if (!confirm(`Disconnect ${g.client ?? g.client_id}? It will have to ask for access again.`)) return;
    try {
      await del(`/oauth/grants/${g.family}`);
      toast.ok('Access revoked.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

{#if grants.length}
  <table class="table">
    <thead><tr><th>App</th>{#if all}<th>Account</th>{/if}<th>Access</th><th>Connected</th><th>Last used</th><th></th></tr></thead>
    <tbody>
      {#each grants as g}
        <tr>
          <td><strong>{g.client ?? g.client_id}</strong></td>
          {#if all}<td class="small">{g.account}</td>{/if}
          <td>{#each g.scopes.split(' ') as s}<span class="chip" style="margin:0 4px 4px 0">{LABEL[s] ?? s}</span>{/each}</td>
          <td class="small muted">{date(g.created_at)}</td>
          <td class="small muted">{ago(g.last_used)}</td>
          <td><button class="btn small danger" onclick={() => revoke(g)}>Disconnect</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
{:else}
  <p class="muted small">No apps are connected.</p>
{/if}
