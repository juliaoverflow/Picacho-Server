<script>
  import { onDestroy } from 'svelte';
  import { get } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { applyBranding, brand } from '../lib/brand.svelte.js';
  import { ACCENTS, theme } from '../lib/theme.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import Logo from '../lib/Logo.svelte';

  const s = liveSettings();
  const b = $derived(s.data?.branding);

  // Live preview while editing; restore the saved look when leaving.
  $effect(() => {
    if (b) applyBranding(JSON.parse(JSON.stringify(b)));
  });
  onDestroy(async () => applyBranding(await get('/branding').catch(() => ({}))));

  function pick(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 256 * 1024) return toast.error('Choose an image of 256 KB or less.');
    if (!/^image\/(png|jpeg|webp|gif|svg\+xml)$/.test(f.type)) return toast.error('Use a PNG, JPEG, WebP, GIF or SVG image.');
    const r = new FileReader();
    r.onload = () => (b.logo = r.result);
    r.readAsDataURL(f);
  }
  const text = (k) => (v) => (b[k] = v.trim() ? v : null);
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Branding</h1><p class="muted lead">Make the console, sign-in and app consent pages look like your organization. Changes preview live.</p></div></div>
  {#if b}
    <div class="layout">
      <div>
        <div class="card">
          <h3>Identity</h3>
          <label class="field"><span>Name</span><input class="input" value={b.name ?? ''} oninput={(e) => text('name')(e.target.value)} placeholder="Picacho Server" maxlength="60" /></label>
          <div class="field" style="margin-top:14px"><span>Logo</span>
            <div class="row">
              <div class="logo-box">{#if b.logo}<img src={b.logo} alt="Logo preview" />{:else}<span class="muted small">Default</span>{/if}</div>
              <label class="btn small">Upload…<input type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/svg+xml" onchange={pick} hidden /></label>
              {#if b.logo}<button class="btn small" onclick={() => (b.logo = null)}>Remove</button>{/if}
            </div>
            <span class="hint">PNG, JPEG, WebP, GIF or SVG, up to 256 KB. Also used as the browser icon.</span>
          </div>
        </div>
        <div class="card">
          <h3>Accent color</h3>
          <p class="sub">Buttons, selection and highlights. Overrides each person's own accent choice.</p>
          <div class="row">
            <input type="color" value={b.accent ?? '#246846'} oninput={(e) => (b.accent = e.target.value)} />
            <input class="input mono" style="max-width:120px" value={b.accent ?? ''} oninput={(e) => (b.accent = /^#[0-9a-f]{6}$/i.test(e.target.value) ? e.target.value : b.accent)} placeholder="#246846" />
            {#each ACCENTS as [name, light]}<button class="swatch" style="--c:{light}" title={name} aria-label={name} onclick={() => (b.accent = light)}></button>{/each}
            {#if b.accent}<button class="btn small" onclick={() => (b.accent = null)}>Use default</button>{/if}
          </div>
        </div>
        <div class="card">
          <h3>Sign-in page</h3>
          <label class="field"><span>Message</span><textarea class="input" rows="3" value={b.login_message ?? ''} oninput={(e) => text('login_message')(e.target.value)} placeholder="Use your company account to sign in."></textarea></label>
          <div class="grid2" style="margin-top:12px">
            <label class="field"><span>Support link</span><input class="input" value={b.support_url ?? ''} oninput={(e) => text('support_url')(e.target.value)} placeholder="https://help.example.com" /></label>
            <label class="field"><span>Support email</span><input class="input" value={b.support_email ?? ''} oninput={(e) => text('support_email')(e.target.value)} placeholder="it@example.com" /></label>
          </div>
          <Toggle bind:checked={b.hide_powered_by} label="Hide “Powered by Picacho Server”" />
        </div>
        <SaveBar {s} />
      </div>
      <div class="preview-col">
        <div class="section-title">Preview</div>
        <div class="preview card">
          <div class="pv-brand"><Logo size={34} /><strong>{brand.name}</strong></div>
          {#if b.login_message}<p class="muted small center">{b.login_message}</p>{/if}
          <button class="btn primary">Sign in with SSO</button>
          <div class="pv-input">Email</div>
          {#if b.support_url || b.support_email}<p class="small muted center">Need help? <a href={b.support_url || `mailto:${b.support_email}`}>Support</a></p>{/if}
        </div>
        <p class="hint">Shown in {theme.dark ? 'dark' : 'light'} mode. Toggle the theme to check the other.</p>
      </div>
    </div>
  {/if}
</div></div>

<style>
  .lead { margin: 6px 0 0; max-width: 720px; }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 18px; align-items: start; }
  .preview-col { position: sticky; top: 0; }
  .preview { display: grid; gap: 12px; padding: 22px; }
  .pv-brand { display: grid; justify-items: center; gap: 6px; }
  .pv-input { height: 36px; border: 1px solid var(--border); border-radius: 9px; padding: 8px 12px; color: var(--muted); font-size: 13px; background: var(--paper); }
  .preview .btn { justify-content: center; }
  .center { text-align: center; margin: 0; white-space: pre-line; }
  .logo-box { width: 120px; height: 48px; border: 1px dashed var(--border); border-radius: 10px; display: grid; place-items: center; background: var(--surface); overflow: hidden; }
  .logo-box img { max-width: 110px; max-height: 40px; }
  input[type='color'] { width: 42px; height: 36px; border: 1px solid var(--border); border-radius: 9px; padding: 2px; background: var(--paper); cursor: pointer; }
  .swatch { width: 24px; height: 24px; border-radius: 50%; border: 0; background: var(--c); cursor: pointer; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } .preview-col { position: static; } }
</style>
