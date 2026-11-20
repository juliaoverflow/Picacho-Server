<script>
  import Tokens from '../lib/Tokens.svelte';
  import Copy from '../lib/Copy.svelte';

  const base = location.origin;
  const examples = [
    ['List accounts', `curl -H "Authorization: Bearer $TOKEN" ${base}/api/v1/accounts`],
    ['Create an account', `curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\\n  -d '{"email":"sam@example.com","password":"A-long-passphrase","quota_mb":2048}' \\\n  ${base}/api/v1/accounts`],
    ['Disable an account', `curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\\n  -d '{"active":false}' ${base}/api/v1/accounts/sam@example.com`],
    ['Reset a password', `curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\\n  -d '{"password":"New-long-passphrase"}' ${base}/api/v1/accounts/sam@example.com/password`],
  ];
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>API & tokens</h1><p class="muted lead-text">Automate account management, connect JMAP clients, and give mail apps their own revocable passwords.</p></div></div>

  <div class="card">
    <h3>Tokens</h3>
    <p class="sub">Tokens are shown once and stored hashed. A token's scopes decide where it works.</p>
    <Tokens admin />
  </div>

  <div class="card">
    <h3>Admin REST API</h3>
    <p class="sub">Base URL <code>{base}/api/v1</code> · send <code>Authorization: Bearer pmk_…</code> with a token that has the <strong>admin</strong> scope. Accounts can be addressed by id or email, domains by id or name.</p>
    <div class="endpoints">
      {#each [['GET / POST', '/accounts'], ['GET / PATCH / DELETE', '/accounts/{id|email}'], ['POST', '/accounts/{id|email}/password'], ['GET / POST', '/domains'], ['GET / PATCH / DELETE', '/domains/{id|name}'], ['POST', '/domains/{id|name}/dkim'], ['GET', '/domains/{id|name}/dns'], ['GET / POST', '/aliases'], ['PATCH / DELETE', '/aliases/{id}'], ['GET', '/queue'], ['POST', '/queue/{id}/retry'], ['DELETE', '/queue/{id}'], ['GET / PUT', '/settings'], ['GET', '/overview'], ['GET', '/events']] as [m, p]}
        <div class="ep"><span class="method">{m}</span><code>{p}</code></div>
      {/each}
    </div>
    <p class="small"><a href="/api/v1/openapi.json" target="_blank" rel="noopener">OpenAPI 3.1 specification</a></p>
    {#each examples as [title, cmd]}
      <div class="example"><div class="row"><strong class="small">{title}</strong><span class="spacer"></span><Copy value={cmd} /></div><pre>{cmd}</pre></div>
    {/each}
  </div>

  <div class="card">
    <h3>JMAP</h3>
    <p class="sub">RFC 8620/8621 mail, submission and quota. Clients discover everything from the session URL.</p>
    <table class="table">
      <tbody>
        <tr><td class="muted">Session</td><td class="mono">{base}/.well-known/jmap <Copy value={`${base}/.well-known/jmap`} /></td></tr>
        <tr><td class="muted">API</td><td class="mono">{base}/jmap/api</td></tr>
        <tr><td class="muted">Authentication</td><td>HTTP Basic with the account password or an app password, or a Bearer token with the <strong>jmap</strong> scope</td></tr>
        <tr><td class="muted">Push</td><td>EventSource at <code>/jmap/eventsource</code></td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>App passwords</h3>
    <p class="sub">A token with the <strong>mail</strong> scope works as the password in IMAP and SMTP apps. Each device can have its own and be revoked without changing the account password. Users create their own from their account page.</p>
  </div>
</div></div>

<style>
  .lead-text { margin: 6px 0 0; max-width: 720px; }
  .endpoints { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 6px 18px; margin: 4px 0 12px; }
  .ep { display: flex; gap: 10px; align-items: baseline; font-size: 13.5px; }
  .method { font-size: 11px; font-weight: 700; color: var(--accent); min-width: 130px; letter-spacing: 0.03em; }
  .example { margin-top: 10px; }
  pre { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 12px; font-family: var(--mono); font-size: 12.5px; overflow: auto; margin: 4px 0 0; white-space: pre; }
</style>
