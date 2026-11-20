<script>
  import { onMount } from 'svelte';
  import { get, setUnauthorizedHandler } from './lib/api.js';
  import { router } from './lib/router.svelte.js';
  import { ui } from './lib/ui.svelte.js';
  import './lib/theme.svelte.js';
  import Toasts from './lib/Toasts.svelte';
  import Setup from './pages/Setup.svelte';
  import Login from './pages/Login.svelte';
  import Shell from './pages/Shell.svelte';
  import Me from './pages/Me.svelte';
  import Consent from './pages/Consent.svelte';
  import { applyBranding } from './lib/brand.svelte.js';

  let phase = $state('loading');
  let error = $state('');

  async function boot() {
    try {
      ui.status = await get('/status');
      applyBranding(ui.status.branding ?? {});
    } catch (e) {
      error = e.message;
      phase = 'error';
      return;
    }
    if (ui.status.setup_required) {
      phase = 'setup';
      if (router.path !== '/setup') router.go('/setup', { replace: true });
      return;
    }
    try {
      ui.me = await get('/auth/me');
      phase = 'app';
      if (router.path === '/setup' || router.path === '/login') router.go('/', { replace: true });
    } catch {
      phase = 'login';
    }
  }

  setUnauthorizedHandler(() => {
    ui.me = null;
    phase = 'login';
  });

  onMount(boot);

  // OAuth consent pages keep their query string through sign-in.
  const consent = location.pathname === '/oauth/authorize';
  const next = location.pathname + location.search;

  function signedIn(me) {
    ui.me = me;
    phase = 'app';
    if (router.path === '/login' || router.path === '/setup') router.go('/', { replace: true });
  }
</script>

{#if phase === 'loading'}
  <div class="center muted">Loading…</div>
{:else if phase === 'error'}
  <div class="center"><div class="notice danger">{error}</div><button class="btn" onclick={boot}>Retry</button></div>
{:else if phase === 'setup'}
  <Setup onDone={signedIn} />
{:else if phase === 'login'}
  <Login onDone={signedIn} next={consent ? next : router.path} />
{:else if consent}
  <Consent />
{:else if ui.me?.role === 'admin'}
  <Shell />
{:else}
  <Me />
{/if}
<Toasts />

<style>
  .center { height: 100%; display: grid; place-content: center; gap: 12px; justify-items: center; }
</style>
