<script>
  import { post } from '../lib/api.js';
  import Logo from '../lib/Logo.svelte';
  import Icon from '../lib/Icon.svelte';
  import { theme } from '../lib/theme.svelte.js';
  import { ui } from '../lib/ui.svelte.js';
  import { brand } from '../lib/brand.svelte.js';

  let { onDone, next = '/' } = $props();
  let email = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state(new URLSearchParams(location.search).get('error') ?? '');
  const auth = $derived(ui.status?.auth ?? { password: true, oidc: null, ldap: null });
  let showPassword = $state(false);

  async function submit(e) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const me = await post('/auth/login', { email, password });
      password = '';
      onDone(me);
    } catch (err) {
      error = err.message;
    } finally {
      busy = false;
    }
  }
  function sso() {
    location.href = `/api/auth/oidc/start?next=${encodeURIComponent(next)}`;
  }
</script>

<div class="login">
  <button class="icon-btn theme" onclick={() => theme.toggle()} aria-label="Toggle dark mode"><Icon name={theme.dark ? 'sun' : 'moon'} /></button>
  <div class="card fade-in panel">
    <div class="brand"><Logo size={40} /><h1>{brand.name}</h1><p class="muted">{ui.status?.hostname}</p></div>
    {#if brand.login_message}<p class="message">{brand.login_message}</p>{/if}
    {#if error}<div class="notice danger"><Icon name="alert" size={18} /><span>{error}</span></div>{/if}
    {#if auth.oidc}
      <button class="btn primary big" onclick={sso}><Icon name="key" /> Sign in with {auth.oidc.name}</button>
    {/if}
    {#if auth.password}
      {#if auth.oidc && !showPassword}
        <button class="link" onclick={() => (showPassword = true)}>{auth.ldap ? `Sign in with your ${auth.ldap.name} account` : 'Sign in with email and password'}</button>
      {:else}
        {#if auth.oidc}<div class="or"><span>or</span></div>{/if}
        <form onsubmit={submit}>
          {#if auth.ldap}
            <label class="field"><span>Email or {auth.ldap.name} user name</span><input class="input" type="text" bind:value={email} autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus /></label>
          {:else}
            <label class="field"><span>Email</span><input class="input" type="email" bind:value={email} autocomplete="username" required autofocus /></label>
          {/if}
          <label class="field"><span>Password</span><input class="input" type="password" bind:value={password} autocomplete="current-password" required /></label>
          <button class="btn big" class:primary={!auth.oidc} disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
      {/if}
    {:else if !auth.oidc}
      <div class="notice warning"><span>No sign-in method is available. Ask your administrator.</span></div>
    {/if}
    {#if brand.support_url || brand.support_email}
      <p class="support small muted">Need help?
        {#if brand.support_url}<a href={brand.support_url} target="_blank" rel="noopener noreferrer">Support</a>{/if}
        {#if brand.support_email}{brand.support_url ? ' · ' : ''}<a href="mailto:{brand.support_email}">{brand.support_email}</a>{/if}
      </p>
    {/if}
  </div>
  {#if !brand.hide_powered_by && brand.name !== 'Picacho Server'}<p class="powered small muted">Powered by Picacho Server</p>{/if}
</div>

<style>
  .login { min-height: 100%; display: grid; place-items: center; align-content: center; gap: 14px; padding: 24px 16px; position: relative; }
  .theme { position: absolute; top: 12px; right: 14px; }
  .panel { width: min(400px, 100%); display: grid; gap: 14px; padding: 30px 28px; border-radius: 16px; box-shadow: var(--shadow); }
  form { display: grid; gap: 14px; }
  .brand { display: grid; justify-items: center; gap: 6px; margin-bottom: 6px; text-align: center; }
  h1 { font-size: 22px; }
  p { margin: 0; }
  .message { text-align: center; color: var(--muted); white-space: pre-line; }
  .btn.big { justify-content: center; }
  .link { border: 0; background: none; color: var(--accent); cursor: pointer; font-size: 14px; }
  .or { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 13px; }
  .or::before, .or::after { content: ''; flex: 1; height: 1px; background: var(--border); }
  .support { text-align: center; }
</style>
