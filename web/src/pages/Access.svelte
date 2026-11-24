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
  let lists = $state({ admin_groups: '', allowed_domains: '', ldap_admin_groups: '', ldap_required_groups: '' });
  let testResult = $state(null);
  let testing = $state(false);
  let ldapMode = $state('search');
  let ldapTest = $state({ user: '', password: '', busy: false, result: null });

  $effect(() => {
    if (auth) {
      lists = {
        admin_groups: auth.oidc.admin_groups.join(', '),
        allowed_domains: auth.oidc.allowed_domains.join(', '),
        ldap_admin_groups: auth.ldap.admin_groups.join(', '),
        ldap_required_groups: auth.ldap.required_groups.join(', ')
      };
      ldapMode = auth.ldap.user_dn_template ? 'direct' : 'search';
    }
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

  // Directory presets: attribute names and filters only; the URL, base DN
  // and service account are yours to fill in.
  const ldapPresets = {
    openldap: { user_filter: '(&(objectClass=inetOrgPerson)(|(uid={user})(mail={user})))', email_attr: 'mail', name_attr: 'displayName', group_attr: 'memberOf', group_filter: '(|(member={dn})(uniqueMember={dn}))', group_name_attr: 'cn' },
    ad: { user_filter: '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName={local})(userPrincipalName={user})(mail={user})))', email_attr: 'mail', name_attr: 'displayName', group_attr: 'memberOf', group_filter: '(member={dn})', group_name_attr: 'cn' },
    freeipa: { user_filter: '(&(objectClass=person)(|(uid={user})(mail={user})))', email_attr: 'mail', name_attr: 'displayName', group_attr: 'memberOf', group_filter: '(member={dn})', group_name_attr: 'cn' },
    lldap: { user_filter: '(&(objectClass=person)(|(uid={user})(mail={user})))', email_attr: 'mail', name_attr: 'cn', group_attr: 'memberOf', group_filter: '(member={dn})', group_name_attr: 'cn' }
  };
  function ldapPreset(e) {
    const p = ldapPresets[e.target.value];
    if (p) Object.assign(auth.ldap, p);
    e.target.value = '';
  }
  function setLdapMode(m) {
    ldapMode = m;
    if (m === 'search') auth.ldap.user_dn_template = '';
  }
  async function testLdap() {
    ldapTest.busy = true;
    ldapTest.result = null;
    try {
      ldapTest.result = await post('/admin/ldap/test', { ldap: auth.ldap, user: ldapTest.user || null, password: ldapTest.password || null });
    } catch (e) {
      ldapTest.result = { ok: false, error: e.message };
    } finally {
      ldapTest.busy = false;
      ldapTest.password = '';
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
      <h3>Directory (LDAP)</h3>
      <div class="row">
        <p class="sub" style="flex:1">Check passwords against OpenLDAP, Active Directory, FreeIPA, LLDAP or another LDAP directory, in the console and in mail, calendar and contacts apps. Works alongside single sign-on and access tokens: someone can use SSO in the console and their directory password in their mail app.</p>
        <select class="input" style="width:auto" onchange={ldapPreset} aria-label="Preset">
          <option value="">Preset…</option>
          <option value="openldap">OpenLDAP</option>
          <option value="ad">Active Directory</option>
          <option value="freeipa">FreeIPA</option>
          <option value="lldap">LLDAP</option>
        </select>
      </div>
      <Toggle bind:checked={auth.ldap.enabled} label="Enable directory sign-in" />
      {#if auth.ldap.enabled}
        <div class="grid2">
          <label class="field"><span>Directory URL</span><input class="input mono" bind:value={auth.ldap.url} placeholder="ldaps://ldap.example.com" /><span class="hint">ldaps:// (636), ldap:// (389) or ldapi://</span></label>
          <label class="field"><span>Name on the sign-in page</span><input class="input" bind:value={auth.ldap.display_name} placeholder="Directory" /></label>
        </div>
        {#if auth.ldap.url.startsWith('ldap://')}
          <Toggle bind:checked={auth.ldap.starttls} label="Use StartTLS" />
          {#if !auth.ldap.starttls}
            <Toggle bind:checked={auth.ldap.allow_plaintext} label="Allow unencrypted LDAP" hint="Passwords travel in clear. Only on a private network you trust." />
          {/if}
        {/if}
        {#if auth.ldap.url.startsWith('ldaps://') || auth.ldap.starttls}
          <details class="more"><summary class="small">Certificates</summary>
            <label class="field"><span>Extra trusted CA (PEM)</span><textarea class="input mono" rows="4" bind:value={auth.ldap.ca_cert} placeholder="-----BEGIN CERTIFICATE-----"></textarea><span class="hint">For a directory with a private CA. Public CAs are trusted already.</span></label>
            <Toggle bind:checked={auth.ldap.tls_skip_verify} label="Don't verify the certificate" hint="Testing only: anyone on the network could read passwords." />
          </details>
        {/if}

        <div class="seg" role="tablist">
          <button class="btn small" class:primary={ldapMode === 'search'} onclick={() => setLdapMode('search')}>Search, then bind</button>
          <button class="btn small" class:primary={ldapMode === 'direct'} onclick={() => setLdapMode('direct')}>Bind as the user</button>
        </div>
        <div class="grid2">
          {#if ldapMode === 'search'}
            <label class="field"><span>Service account DN</span><input class="input mono" bind:value={auth.ldap.bind_dn} placeholder="cn=picacho,ou=services,dc=example,dc=com" /><span class="hint">Empty: search anonymously.</span></label>
            <label class="field"><span>Service account password</span><input class="input mono" type="password" bind:value={auth.ldap.bind_password} autocomplete="off" /></label>
          {:else}
            <label class="field"><span>User DN template</span><input class="input mono" bind:value={auth.ldap.user_dn_template} placeholder="uid={'{user}'},ou=people,dc=example,dc=com" /><span class="hint">Or <code>{'{user}'}@corp.example.com</code> for Active Directory. No service account needed.</span></label>
          {/if}
          <label class="field"><span>Users base DN</span><input class="input mono" bind:value={auth.ldap.base_dn} placeholder="ou=people,dc=example,dc=com" /></label>
          <label class="field wide"><span>User filter</span><input class="input mono" bind:value={auth.ldap.user_filter} /><span class="hint"><code>{'{user}'}</code> is what the person typed; <code>{'{local}'}</code> and <code>{'{domain}'}</code> are the parts of an address. Values are escaped.</span></label>
          <label class="field"><span>Email attribute</span><input class="input mono" bind:value={auth.ldap.email_attr} /><span class="hint">Picks the mailbox.</span></label>
          <label class="field"><span>Name attribute</span><input class="input mono" bind:value={auth.ldap.name_attr} /></label>
          <label class="field"><span>Group attribute on users</span><input class="input mono" bind:value={auth.ldap.group_attr} placeholder="memberOf" /></label>
          <label class="field"><span>Groups base DN</span><input class="input mono" bind:value={auth.ldap.group_base_dn} placeholder="Optional: ou=groups,dc=example,dc=com" /><span class="hint">Searches groups too, for directories without memberOf.</span></label>
          {#if auth.ldap.group_base_dn}
            <label class="field"><span>Group filter</span><input class="input mono" bind:value={auth.ldap.group_filter} /><span class="hint"><code>{'{dn}'}</code> is the user's DN.</span></label>
            <label class="field"><span>Group name attribute</span><input class="input mono" bind:value={auth.ldap.group_name_attr} /></label>
          {/if}
          <label class="field"><span>Administrator groups</span><input class="input" bind:value={lists.ldap_admin_groups} onchange={() => (auth.ldap.admin_groups = split(lists.ldap_admin_groups))} placeholder="mail-admins" /><span class="hint">Group names or DNs. Members become admins, others users. Empty: roles are managed here.</span></label>
          <label class="field"><span>Required groups</span><input class="input" bind:value={lists.ldap_required_groups} onchange={() => (auth.ldap.required_groups = split(lists.ldap_required_groups))} placeholder="Anyone in the directory" /></label>
        </div>
        <Toggle bind:checked={auth.ldap.auto_create_accounts} label="Create mailboxes on first sign-in" hint="When the directory address is on one of your local domains. Otherwise an admin creates the account first." />
        <Toggle bind:checked={auth.ldap.web_login} label="Use for the web console" />
        <Toggle bind:checked={auth.ldap.mail_login} label="Use for mail, calendar and contacts apps" hint="IMAP, SMTP, JMAP, CalDAV, CardDAV and ManageSieve." />
        <p class="hint">People found in the directory sign in with their directory password only. Accounts the directory doesn't know (a break-glass admin, for example) keep their local password while password sign-in is on below. Successful logins are cached for five minutes.</p>

        <div class="test">
          <span class="small muted">Test the settings below before saving (optional: a user to look up, and their password)</span>
          <div class="row">
            <input class="input" bind:value={ldapTest.user} placeholder="User name or address" autocomplete="off" />
            <input class="input" type="password" bind:value={ldapTest.password} placeholder="Password" autocomplete="new-password" />
            <button class="btn small" onclick={testLdap} disabled={ldapTest.busy || !auth.ldap.url}><Icon name="zap" size={15} /> {ldapTest.busy ? 'Testing…' : 'Test'}</button>
          </div>
        </div>
        {#if ldapTest.result}
          {@const r = ldapTest.result}
          {#if !r.ok}
            <div class="notice danger"><Icon name="alert" size={18} /><span>{r.error}</span></div>
          {:else if r.found === undefined}
            <div class="notice"><Icon name="check" size={18} /><span>Connected{auth.ldap.bind_dn && ldapMode === 'search' ? ' and signed in as the service account' : ''}.</span></div>
          {:else if !r.found}
            <div class="notice warning"><Icon name="alert" size={18} /><span>No user matches the filter.</span></div>
          {:else if r.password_ok === false}
            <div class="notice warning"><Icon name="alert" size={18} /><span>User found, but the password is wrong.</span></div>
          {:else}
            <div class="notice"><Icon name="check" size={18} /><span>
              {r.password_ok ? 'Password accepted. ' : ''}<span class="mono">{r.user.dn}</span><br />
              Mailbox: {r.user.emails.length ? r.user.emails.join(', ') : 'none (no email attribute)'}{r.user.name ? ` · ${r.user.name}` : ''}<br />
              Groups: {r.user.groups.length ? r.user.groups.join(', ') : 'none'}{auth.ldap.admin_groups.length ? ` · ${r.admin ? 'administrator' : 'user'}` : ''}{r.allowed ? '' : ' · not in a required group'}
            </span></div>
          {/if}
        {/if}
      {/if}
    </div>

    <div class="card">
      <h3>Passwords</h3>
      <Toggle bind:checked={auth.web_password_login} label="Allow local passwords in the console" hint="Turn off to require single sign-on or directory sign-in for everyone." disabled={!auth.oidc.enabled && !(auth.ldap.enabled && auth.ldap.web_login) && auth.web_password_login} />
      {#if !auth.web_password_login && !ui.me?.sso_linked && !(auth.ldap.enabled && auth.ldap.web_login)}
        <div class="notice warning"><Icon name="alert" size={18} /><span>You haven't signed in with single sign-on yet. Do that in another window before saving, or you may lock yourself out.</span></div>
      {/if}
      <Toggle bind:checked={auth.mail_password_login} label="Allow local passwords in mail apps" hint="When off, IMAP, SMTP and JMAP accept only app passwords, access tokens and (if enabled above) directory passwords." />
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
  .seg { display: flex; gap: 6px; margin: 12px 0 4px; }
  .wide { grid-column: 1 / -1; }
  .more { margin: 6px 0; }
  .more summary { cursor: pointer; color: var(--muted); }
  .test { display: grid; gap: 6px; margin: 12px 0 8px; padding: 10px 12px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); }
  .test .input { flex: 1; min-width: 0; }
  .scopes { margin: 2px 0 0; padding-left: 18px; display: grid; gap: 4px; color: var(--muted); }
</style>
