<script>
  import { post } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { ui } from '../lib/ui.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import Copy from '../lib/Copy.svelte';
  import SaveBar from '../lib/SaveBar.svelte';

  const s = liveSettings();
  const auth = $derived(s.data?.auth);
  const redirectUri = ui.status?.auth?.redirect_uri ?? `${location.origin}/api/auth/oidc/callback`;
  const metadataUrl = `${location.origin}/.well-known/oauth-protected-resource`;
  let lists = $state({ admin_groups: '', allowed_domains: '' });
  let testResult = $state(null);
  let testing = $state(false);

  $effect(() => {
    if (auth) lists = { admin_groups: auth.oidc.admin_groups.join(', '), allowed_domains: auth.oidc.allowed_domains.join(', ') };
  });
  const split = (v) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

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

  // Pinal Accounts: register this server as an ordinary app in the Pinal
  // Developers portal, then paste its client ID and secret.
  function usePinal() {
    Object.assign(auth.oidc, {
      enabled: true,
      display_name: 'Pinal',
      issuer: 'https://accounts.pinal.tech',
      scopes: 'openid email profile',
      email_claim: 'email',
      require_verified_email: true,
      access_tokens: true,
      resource: auth.oidc.resource || location.origin
    });
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Sign-in & access</h1><p class="muted lead">How people sign in to this console and how mail apps get access to mailboxes.</p></div></div>
  {#if auth}
    <div class="card">
      <h3>Single sign-on (OpenID Connect)</h3>
      <div class="row">
        <p class="sub" style="flex:1">Lets administrators and mailbox users sign in to the web console with your identity provider (Pinal Accounts, Okta, Entra ID, Google, Keycloak, Authentik, Zitadel…).</p>
        <button class="btn small" onclick={usePinal}><Icon name="zap" size={15} /> Use Pinal Accounts</button>
      </div>
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
      <Toggle bind:checked={auth.mail_password_login} label="Allow account passwords in mail apps" hint="When off, IMAP, SMTP and JMAP accept only app passwords and access tokens. Required for SSO-only users anyway." />
      <p class="hint">Locked out? Start the server with <code>PICACHO_ALLOW_PASSWORD_LOGIN=1</code> to re-enable password sign-in temporarily.</p>
    </div>

    <div class="card">
      <h3>Access for apps</h3>
      <p class="sub">This server doesn't issue tokens. Apps get them from your identity provider, which shows the consent screen and lists connected apps; IMAP, SMTP, JMAP, CalDAV, CardDAV and the REST API (<code>/v1/mail</code>) accept them.</p>
      <Toggle bind:checked={auth.oidc.access_tokens} label="Accept access tokens from the identity provider" hint="Tokens must be JWTs signed by the issuer above and addressed to this server's resource identifier." />
      {#if auth.oidc.access_tokens}
        <div class="grid2">
          <label class="field"><span>Resource identifier</span><input class="input mono" bind:value={auth.oidc.resource} placeholder={location.origin} /><span class="hint">Register the same URL as a resource at the provider. Tokens carry it in <code>aud</code>.</span></label>
          <div class="field"><span>What each scope allows</span>
            <ul class="scopes small">
              <li><code>mail.read</code> read-only IMAP and JMAP; with <code>mail.labels</code> and <code>mail.compose</code>, full access</li>
              <li><code>mail.send</code> SMTP submission</li>
              <li><code>mail.settings</code> filters, forwarding and vacation</li>
              <li><code>calendar.*</code> CalDAV, <code>contacts.*</code> CardDAV</li>
            </ul>
          </div>
        </div>
        <div class="redirect"><span class="small muted">Protected resource metadata (RFC 9728)</span><div class="row"><code>{metadataUrl}</code><Copy value={metadataUrl} /></div></div>
      {/if}
    </div>
    <SaveBar {s} />
  {/if}
</div></div>

<style>
  .lead { margin: 6px 0 0; max-width: 720px; }
  .redirect { display: grid; gap: 4px; margin: 10px 0 14px; padding: 10px 12px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); }
  .redirect code { word-break: break-all; font-size: 13px; }
  .scopes { margin: 2px 0 0; padding-left: 18px; display: grid; gap: 4px; color: var(--muted); }
</style>
