<script>
  import { onMount } from 'svelte';
  import { get, post, del } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { ui } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { date } from '../lib/format.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import Copy from '../lib/Copy.svelte';
  import Modal from '../lib/Modal.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import Grants from '../lib/Grants.svelte';

  const s = liveSettings();
  const auth = $derived(s.data?.auth);
  const oauth = $derived(s.data?.oauth);
  const redirectUri = ui.status?.auth?.redirect_uri ?? `${location.origin}/api/auth/oidc/callback`;
  let lists = $state({ admin_groups: '', allowed_domains: '' });
  let testResult = $state(null);
  let testing = $state(false);
  let clients = $state([]);
  let creating = $state(false);
  let draft = $state({});
  let created = $state(null);

  $effect(() => {
    if (auth) lists = { admin_groups: auth.oidc.admin_groups.join(', '), allowed_domains: auth.oidc.allowed_domains.join(', ') };
  });
  const split = (v) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  async function loadClients() {
    clients = await get('/admin/oauth/clients');
  }
  onMount(() => loadClients().catch((e) => toast.error(e)));

  async function test() {
    testing = true;
    testResult = null;
    try {
      testResult = await post('/oidc/test', { issuer: auth.oidc.issuer });
    } catch (e) {
      testResult = { ok: false, error: e.message };
    } finally {
      testing = false;
    }
  }

  function newClient() {
    draft = { name: '', redirect_uris: '', confidential: false, imap: true, smtp: true, jmap: true };
    creating = true;
  }
  async function createClient(e) {
    e?.preventDefault();
    try {
      const scopes = ['imap', 'smtp', 'jmap'].filter((k) => draft[k]);
      created = await post('/admin/oauth/clients', { name: draft.name, redirect_uris: split(draft.redirect_uris.replace(/,/g, ' ')), confidential: draft.confidential, scopes });
      creating = false;
      loadClients();
    } catch (err) {
      toast.error(err);
    }
  }
  async function removeClient(c) {
    if (!confirm(`Remove ${c.name}? Everyone signed in through it is signed out.`)) return;
    try {
      await del(`/admin/oauth/clients/${encodeURIComponent(c.client_id)}`);
      toast.ok('App removed.');
      loadClients();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Sign-in & access</h1><p class="muted lead">How people sign in to this console and how mail apps get access to mailboxes.</p></div></div>
  {#if auth && oauth}
    <div class="card">
      <h3>Single sign-on (OpenID Connect)</h3>
      <p class="sub">Lets administrators and mailbox users sign in to the web console with your identity provider (Okta, Entra ID, Google, Keycloak, Authentik, Zitadel…).</p>
      <Toggle bind:checked={auth.oidc.enabled} label="Enable single sign-on" />
      {#if auth.oidc.enabled}
        <div class="redirect"><span class="small muted">Redirect URI to register at your provider</span><div class="row"><code>{redirectUri}</code><Copy value={redirectUri} /></div></div>
        <div class="grid2">
          <label class="field"><span>Button label</span><input class="input" bind:value={auth.oidc.display_name} placeholder="Okta" /><span class="hint">Shown as “Sign in with …”.</span></label>
          <label class="field"><span>Issuer URL</span><input class="input mono" bind:value={auth.oidc.issuer} placeholder="https://login.example.com" /></label>
          <label class="field"><span>Client ID</span><input class="input mono" bind:value={auth.oidc.client_id} /></label>
          <label class="field"><span>Client secret</span><input class="input mono" type="password" bind:value={auth.oidc.client_secret} autocomplete="off" /><span class="hint">Leave empty for public clients (PKCE only).</span></label>
          <label class="field"><span>Scopes</span><input class="input mono" bind:value={auth.oidc.scopes} /></label>
          <label class="field"><span>Email claim</span><input class="input mono" bind:value={auth.oidc.email_claim} /></label>
          <label class="field"><span>Groups claim</span><input class="input mono" bind:value={auth.oidc.groups_claim} /></label>
          <label class="field"><span>Administrator groups</span><input class="input" bind:value={lists.admin_groups} onchange={() => (auth.oidc.admin_groups = split(lists.admin_groups))} placeholder="mail-admins" /><span class="hint">Members become admins, others users. Empty: roles are managed here.</span></label>
          <label class="field"><span>Allowed email domains</span><input class="input" bind:value={lists.allowed_domains} onchange={() => (auth.oidc.allowed_domains = split(lists.allowed_domains))} placeholder="Any" /></label>
        </div>
        <Toggle bind:checked={auth.oidc.auto_create_accounts} label="Create mailboxes on first sign-in" hint="For people whose email is on one of your local domains. Otherwise an admin creates the account first." />
        <Toggle bind:checked={auth.oidc.require_verified_email} label="Require a verified email" />
        <div class="row" style="margin-top:8px"><button class="btn small" onclick={test} disabled={testing || !auth.oidc.issuer}><Icon name="zap" size={15} /> {testing ? 'Checking…' : 'Check provider'}</button></div>
        {#if testResult}
          {#if testResult.ok}
            <div class="notice"><Icon name="check" size={18} /><span>Found <span class="mono">{testResult.issuer}</span>. Authorization and token endpoints are reachable.</span></div>
          {:else}
            <div class="notice danger"><Icon name="alert" size={18} /><span>{testResult.error}</span></div>
          {/if}
        {/if}
      {/if}
    </div>

    <div class="card">
      <h3>Passwords</h3>
      <Toggle bind:checked={auth.web_password_login} label="Allow email and password sign-in to the console" hint="Turn off to require single sign-on for everyone." disabled={!auth.oidc.enabled && auth.web_password_login} />
      {#if !auth.web_password_login && !ui.me?.sso_linked}
        <div class="notice warning"><Icon name="alert" size={18} /><span>You haven't signed in with single sign-on yet. Do that in another window before saving, or you may lock yourself out.</span></div>
      {/if}
      <Toggle bind:checked={auth.mail_password_login} label="Allow account passwords in mail apps" hint="When off, IMAP, SMTP and JMAP accept only app passwords and OAuth tokens. Required for SSO-only users anyway." />
      <p class="hint">Locked out? Start the server with <code>PICACHO_ALLOW_PASSWORD_LOGIN=1</code> to re-enable password sign-in temporarily.</p>
    </div>

    <div class="card">
      <h3>OAuth for mail apps</h3>
      <p class="sub">Apps send people to a consent screen where they choose read-only or read & write access for IMAP and JMAP, and whether the app may send mail.</p>
      <Toggle bind:checked={oauth.enabled} label="Allow apps to request access with OAuth" />
      <Toggle bind:checked={oauth.dynamic_registration} label="Let apps register themselves" hint="RFC 7591. Off: only apps you register below can ask for access." />
      <div class="grid2" style="margin-top:8px">
        <label class="field"><span>Access token lifetime (minutes)</span><input class="input" type="number" min="1" bind:value={oauth.access_token_minutes} /></label>
        <label class="field"><span>Stay connected for (days)</span><input class="input" type="number" min="1" bind:value={oauth.refresh_token_days} /><span class="hint">Refresh tokens rotate on every use.</span></label>
      </div>
      <div class="redirect"><span class="small muted">Server metadata</span><div class="row"><code>{location.origin}/.well-known/oauth-authorization-server</code><Copy value={`${location.origin}/.well-known/oauth-authorization-server`} /></div></div>
    </div>
    <SaveBar {s} />

    <div class="card">
      <div class="row"><div><h3>Registered apps</h3><p class="sub">Mail clients and integrations allowed to ask for access.</p></div><span class="spacer"></span><button class="btn small primary" onclick={newClient}><Icon name="plus" size={16} /> Register app</button></div>
      {#if clients.length}
        <table class="table">
          <thead><tr><th>App</th><th>Client ID</th><th>Type</th><th>May request</th><th>Added</th><th></th></tr></thead>
          <tbody>
            {#each clients as c}
              <tr>
                <td><strong>{c.name}</strong>{#if c.dynamic}<span class="chip" style="margin-left:6px">self-registered</span>{/if}<div class="small muted mono">{c.redirect_uris.join(' ')}</div></td>
                <td class="mono small">{c.client_id} <Copy value={c.client_id} /></td>
                <td class="small">{c.confidential ? 'Confidential' : 'Public (PKCE)'}</td>
                <td class="small">{c.scopes}</td>
                <td class="small muted">{date(c.created_at)}</td>
                <td><button class="btn small danger" onclick={() => removeClient(c)}>Remove</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}<p class="muted small">No apps registered.</p>{/if}
    </div>

    <div class="card"><h3>Connected apps</h3><p class="sub">Everyone's active OAuth authorizations.</p><Grants all /></div>
  {/if}
</div></div>

<Modal title="Register an app" bind:open={creating} width={520}>
  <form id="new-client" onsubmit={createClient} style="display:grid;gap:14px">
    <label class="field"><span>Name</span><input class="input" bind:value={draft.name} placeholder="Thunderbird" required autofocus /></label>
    <label class="field"><span>Redirect URIs</span><textarea class="input mono" rows="3" bind:value={draft.redirect_uris} placeholder="http://127.0.0.1/callback&#10;com.example.mail:/oauth2redirect" required></textarea><span class="hint">One per line. https, loopback http (any port) or an app scheme.</span></label>
    <div class="field"><span>May request</span>
      <div class="row">{#each [['imap', 'IMAP'], ['smtp', 'SMTP'], ['jmap', 'JMAP']] as [k, l]}<label class="row small"><input type="checkbox" bind:checked={draft[k]} /> {l}</label>{/each}</div>
    </div>
    <Toggle bind:checked={draft.confidential} label="Confidential client" hint="Server-side apps that can keep a secret. Desktop and mobile apps are public and use PKCE." />
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (creating = false)}>Cancel</button>
    <button class="btn primary" type="submit" form="new-client">Register</button>
  {/snippet}
</Modal>

<Modal title="App registered" open={!!created} width={520}>
  {#if created}
    <table class="table"><tbody>
      <tr><td class="muted">Client ID</td><td class="mono">{created.client.client_id} <Copy value={created.client.client_id} /></td></tr>
      {#if created.client_secret}<tr><td class="muted">Client secret</td><td class="mono" style="word-break:break-all">{created.client_secret} <Copy value={created.client_secret} /></td></tr>{/if}
      <tr><td class="muted">Authorize</td><td class="mono small">{location.origin}/oauth/authorize</td></tr>
      <tr><td class="muted">Token</td><td class="mono small">{location.origin}/oauth/token</td></tr>
    </tbody></table>
    {#if created.client_secret}<p class="small muted">The secret is shown only once.</p>{/if}
  {/if}
  {#snippet footer()}<button class="btn primary" onclick={() => (created = null)}>Done</button>{/snippet}
</Modal>

<style>
  .lead { margin: 6px 0 0; max-width: 720px; }
  .redirect { display: grid; gap: 4px; margin: 10px 0 14px; padding: 10px 12px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); }
  .redirect code { word-break: break-all; font-size: 13px; }
</style>
