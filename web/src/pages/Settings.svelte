<script>
  import { post } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { theme, ACCENTS } from '../lib/theme.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import SaveBar from '../lib/SaveBar.svelte';
  import { ui } from '../lib/ui.svelte.js';

  const s = liveSettings();
  const srv = $derived(s.data?.server);
  let current = $state('');
  let next = $state('');

  async function changePassword(e) {
    e.preventDefault();
    try {
      await post('/me/password', { current, new: next });
      current = next = '';
      toast.ok('Password changed. Other console sessions were signed out.');
    } catch (err) {
      toast.error(err);
    }
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><h1>Settings</h1></div>
  {#if srv}
    <div class="card">
      <h3>Server</h3>
      <p class="sub">Shown to other mail servers and in greetings.</p>
      <div class="grid2">
        <label class="field"><span>Host name</span><input class="input" bind:value={srv.hostname} /><span class="hint">Restart to regenerate a self-signed certificate for a new name.</span></label>
        <label class="field"><span>Primary domain</span><input class="input" bind:value={srv.primary_domain} /><span class="hint">Used for bounces and forwarding (SRS).</span></label>
        <label class="field"><span>Greeting</span><input class="input" bind:value={srv.greeting} placeholder="ESMTP Picacho Server" /></label>
      </div>
    </div>
    <SaveBar {s} />
  {/if}
  <div class="card">
    <h3>Appearance</h3>
    <p class="sub">Saved in this browser.</p>
    <div class="row">
      <div class="segmented">
        {#each [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']] as [k, l]}
          <button class:on={theme.appearance === k} onclick={() => theme.setAppearance(k)}>{l}</button>
        {/each}
      </div>
      <div class="swatches">
        {#each ACCENTS as [name, light, dark]}
          <button class="swatch" class:on={theme.accent === name} style="--c:{theme.dark ? dark : light}" onclick={() => theme.setAccent(name)} title={name} aria-label={`${name} accent`}></button>
        {/each}
      </div>
    </div>
  </div>
  {#if ui.me?.has_password !== false}
  <form class="card" onsubmit={changePassword}>
    <h3>Your password</h3>
    <div class="grid2" style="margin-top:10px">
      <label class="field"><span>Current password</span><input class="input" type="password" bind:value={current} autocomplete="current-password" required /></label>
      <label class="field"><span>New password</span><input class="input" type="password" bind:value={next} autocomplete="new-password" required /></label>
    </div>
    <div class="row" style="margin-top:14px"><button class="btn primary">Change password</button></div>
  </form>
  {/if}
</div></div>

<style>
  .swatches { display: flex; gap: 8px; }
  .swatch { width: 26px; height: 26px; border-radius: 50%; border: 2px solid transparent; background: var(--c); cursor: pointer; box-shadow: inset 0 0 0 2px var(--paper); }
  .swatch.on { border-color: var(--c); }
</style>
