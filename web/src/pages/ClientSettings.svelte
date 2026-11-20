<script>
  import Copy from '../lib/Copy.svelte';
  let { client } = $props();
  const rows = $derived(client ? [
    ['Incoming (IMAP)', client.imap], ['Incoming, STARTTLS', client.imap_starttls],
    ['Outgoing (SMTP)', client.smtp], ['Outgoing, STARTTLS', client.smtp_starttls],
  ] : []);
</script>

{#if client}
  <table class="table">
    <thead><tr><th>Service</th><th>Server</th><th>Port</th><th>Security</th></tr></thead>
    <tbody>
      {#each rows as [label, r]}
        <tr><td>{label}</td><td class="mono">{r.host} <Copy value={r.host} /></td><td>{r.port}</td><td>{r.security}</td></tr>
      {/each}
    </tbody>
  </table>
  <p class="hint">User name: <span class="mono">{client.username}</span> · Password: the account password.</p>
{/if}
